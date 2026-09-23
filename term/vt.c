#include <stdlib.h>
#include <string.h>
#include "vt.h"
#include "nsenc.h"

enum { ST_GROUND, ST_ESC, ST_ESC_INTER, ST_CSI, ST_CSI_INTER, ST_OSC, ST_OSC_ESC, ST_STRING, ST_STRING_ESC };

/* DEC special graphics, 0x5f..0x7e */
static const vt_u16 DEC_GFX[32] = {
    0x0020, 0x25c6, 0x2592, 0x2409, 0x240c, 0x240d, 0x240a, 0x00b0,
    0x00b1, 0x2424, 0x240b, 0x2518, 0x2510, 0x250c, 0x2514, 0x253c,
    0x23ba, 0x23bb, 0x2500, 0x23bc, 0x23bd, 0x251c, 0x2524, 0x2534,
    0x252c, 0x2502, 0x2264, 0x2265, 0x03c0, 0x2260, 0x00a3, 0x00b7
};

/* ------------------------------------------------------------------ */
/* cells, rows, screens                                                */
/* ------------------------------------------------------------------ */

static vt_cell blank_cell(const vt *t)
{
    vt_cell c;
    c.ch = ' ';
    c.fg = 0;
    c.bg = t->pen.bg;
    c.attr = (vt_u8)(VT_DEFFG | (t->pen.attr & VT_DEFBG));
    return c;
}

static void fill(vt_cell *p, int n, vt_cell c)
{
    int i;
    for (i = 0; i < n; i++) p[i] = c;
}

static vt_cell *alloc_row(int cols, vt_cell c)
{
    vt_cell *r = (vt_cell *)malloc((size_t)cols * sizeof(vt_cell));
    if (r) fill(r, cols, c);
    return r;
}

static void free_rows(vt_cell **rows, int n)
{
    int i;
    if (!rows) return;
    for (i = 0; i < n; i++) free(rows[i]);
    free(rows);
}

static vt_cell **alloc_screen(int rows, int cols, vt_cell c)
{
    vt_cell **s = (vt_cell **)calloc((size_t)rows, sizeof(vt_cell *));
    int i;
    if (!s) return NULL;
    for (i = 0; i < rows; i++) {
        s[i] = alloc_row(cols, c);
        if (!s[i]) { free_rows(s, rows); return NULL; }
    }
    return s;
}

static void mark(vt *t, int row)
{
    if (row >= 0 && row < t->rows) t->dirty[row] = 1;
}

static void mark_range(vt *t, int a, int b)
{
    int i;
    for (i = a; i <= b; i++) mark(t, i);
}

/* ------------------------------------------------------------------ */
/* scrollback                                                          */
/* ------------------------------------------------------------------ */

/* Take ownership of `row` into the scrollback; return a row for the caller to reuse. */
static vt_cell *sb_push(vt *t, vt_cell *row)
{
    int idx;
    vt_cell *fresh;
    if (t->sb_max <= 0) return row;
    if (t->sb_count == t->sb_max) {
        vt_cell *old = t->sb[t->sb_head];
        int oldw = t->sb_w[t->sb_head];
        t->sb[t->sb_head] = row;
        t->sb_w[t->sb_head] = t->cols;
        t->sb_head = (t->sb_head + 1) % t->sb_max;
        if (oldw == t->cols) return old;
        free(old);
        fresh = (vt_cell *)malloc((size_t)t->cols * sizeof(vt_cell));
        return fresh;
    }
    fresh = (vt_cell *)malloc((size_t)t->cols * sizeof(vt_cell));
    if (!fresh) return row;                 /* out of memory: drop the line instead */
    idx = (t->sb_head + t->sb_count) % t->sb_max;
    t->sb[idx] = row;
    t->sb_w[idx] = t->cols;
    t->sb_count++;
    return fresh;
}

int vt_scrollback_count(const vt *t) { return t->sb_count; }

const vt_cell *vt_line_at(const vt *t, int idx, int *width)
{
    if (idx >= 0) {
        if (idx >= t->rows) return NULL;
        *width = t->cols;
        return t->line[idx];
    }
    idx = -idx;                              /* 1 = newest */
    if (idx > t->sb_count) return NULL;
    idx = (t->sb_head + t->sb_count - idx) % t->sb_max;
    *width = t->sb_w[idx];
    return t->sb[idx];
}

/* ------------------------------------------------------------------ */
/* scrolling                                                           */
/* ------------------------------------------------------------------ */

static void scroll_up(vt *t, int top, int bottom, int n, int to_sb)
{
    int i, h = bottom - top + 1;
    vt_cell *row;
    if (n > h) n = h;
    if (n <= 0) return;
    for (i = 0; i < n; i++) {
        row = t->line[top];
        memmove(&t->line[top], &t->line[top + 1], (size_t)(h - 1) * sizeof(vt_cell *));
        if (to_sb && top == 0 && !t->in_alt) row = sb_push(t, row);
        if (!row) row = alloc_row(t->cols, blank_cell(t));
        else fill(row, t->cols, blank_cell(t));
        t->line[bottom] = row;
    }
    mark_range(t, top, bottom);
}

static void scroll_down(vt *t, int top, int bottom, int n)
{
    int i, h = bottom - top + 1;
    vt_cell *row;
    if (n > h) n = h;
    if (n <= 0) return;
    for (i = 0; i < n; i++) {
        row = t->line[bottom];
        memmove(&t->line[top + 1], &t->line[top], (size_t)(h - 1) * sizeof(vt_cell *));
        fill(row, t->cols, blank_cell(t));
        t->line[top] = row;
    }
    mark_range(t, top, bottom);
}

static void index_down(vt *t)
{
    if (t->cy == t->bottom) scroll_up(t, t->top, t->bottom, 1, 1);
    else if (t->cy < t->rows - 1) t->cy++;
}

static void index_up(vt *t)
{
    if (t->cy == t->top) scroll_down(t, t->top, t->bottom, 1);
    else if (t->cy > 0) t->cy--;
}

/* ------------------------------------------------------------------ */
/* cursor & output helpers                                             */
/* ------------------------------------------------------------------ */

static void cursor_to(vt *t, int row, int col)
{
    int lo = 0, hi = t->rows - 1;
    if (t->origin) { row += t->top; lo = t->top; hi = t->bottom; }
    if (row < lo) row = lo;
    if (row > hi) row = hi;
    if (col < 0) col = 0;
    if (col >= t->cols) col = t->cols - 1;
    t->cy = row;
    t->cx = col;
    t->wrap_pending = 0;
}

static void emit(vt *t, const char *s)
{
    size_t n = strlen(s);
    if ((size_t)t->out_len + n > VT_OUTBUF) return;
    memcpy(t->out + t->out_len, s, n);
    t->out_len += (int)n;
}

int vt_take_output(vt *t, unsigned char *buf, int max)
{
    int n = t->out_len < max ? t->out_len : max;
    memcpy(buf, t->out, (size_t)n);
    memmove(t->out, t->out + n, (size_t)(t->out_len - n));
    t->out_len -= n;
    return n;
}

static void emit_num(vt *t, int v)
{
    char b[16];
    int i = 0, j;
    char tmp[16];
    if (v == 0) tmp[i++] = '0';
    while (v > 0) { tmp[i++] = (char)('0' + v % 10); v /= 10; }
    for (j = 0; j < i; j++) b[j] = tmp[i - 1 - j];
    b[i] = '\0';
    emit(t, b);
}

/* ------------------------------------------------------------------ */
/* printing                                                            */
/* ------------------------------------------------------------------ */

static void put_cp(vt *t, vt_u32 cp)
{
    vt_cell *row;
    vt_cell *c;
    int cs = t->shift ? t->g1 : t->g0;

    if (cs == 1 && cp >= 0x5f && cp <= 0x7e) cp = DEC_GFX[cp - 0x5f];
    if (cp > 0xffff) cp = '?';
    if (cp >= 0x300 && cp <= 0x36f) return;                 /* combining marks: no cell for them */

    if (t->wrap_pending) {
        if (t->autowrap) { t->cx = 0; index_down(t); }
        t->wrap_pending = 0;
    }
    row = t->line[t->cy];
    if (t->insert && t->cx < t->cols - 1)
        memmove(&row[t->cx + 1], &row[t->cx], (size_t)(t->cols - t->cx - 1) * sizeof(vt_cell));
    c = &row[t->cx];
    c->ch = (vt_u16)cp;
    c->fg = t->pen.fg;
    c->bg = t->pen.bg;
    c->attr = t->pen.attr;
    mark(t, t->cy);
    if (t->cx == t->cols - 1) t->wrap_pending = t->autowrap ? 1 : 0;
    else t->cx++;
}

static void next_tab(vt *t, int n)
{
    while (n-- > 0) {
        do { t->cx++; } while (t->cx < t->cols - 1 && !t->tabs[t->cx]);
        if (t->cx >= t->cols - 1) { t->cx = t->cols - 1; break; }
    }
    t->wrap_pending = 0;
}

static void prev_tab(vt *t, int n)
{
    while (n-- > 0) {
        do { t->cx--; } while (t->cx > 0 && !t->tabs[t->cx]);
        if (t->cx <= 0) { t->cx = 0; break; }
    }
    t->wrap_pending = 0;
}

static void execute_c0(vt *t, int c)
{
    switch (c) {
    case 0x07: t->bell = 1; break;
    case 0x08: if (t->cx > 0) t->cx--; t->wrap_pending = 0; break;
    case 0x09: next_tab(t, 1); break;
    case 0x0a: case 0x0b: case 0x0c:
        index_down(t);
        t->wrap_pending = 0;
        if (t->newline_mode) t->cx = 0;
        break;
    case 0x0d: t->cx = 0; t->wrap_pending = 0; break;
    case 0x0e: t->shift = 1; break;
    case 0x0f: t->shift = 0; break;
    default: break;
    }
}

/* ------------------------------------------------------------------ */
/* erase / insert / delete                                             */
/* ------------------------------------------------------------------ */

static void erase_cells(vt *t, int row, int from, int to)   /* [from, to) */
{
    if (from < 0) from = 0;
    if (to > t->cols) to = t->cols;
    if (from >= to) return;
    fill(&t->line[row][from], to - from, blank_cell(t));
    mark(t, row);
}

static void erase_display(vt *t, int mode)
{
    int r;
    switch (mode) {
    case 0:
        erase_cells(t, t->cy, t->cx, t->cols);
        for (r = t->cy + 1; r < t->rows; r++) erase_cells(t, r, 0, t->cols);
        break;
    case 1:
        for (r = 0; r < t->cy; r++) erase_cells(t, r, 0, t->cols);
        erase_cells(t, t->cy, 0, t->cx + 1);
        break;
    case 2:
        for (r = 0; r < t->rows; r++) erase_cells(t, r, 0, t->cols);
        break;
    case 3:
        if (!t->in_alt) {
            int i;
            for (i = 0; i < t->sb_count; i++) free(t->sb[(t->sb_head + i) % t->sb_max]);
            t->sb_count = 0;
            t->sb_head = 0;
        }
        break;
    }
}

static void erase_line(vt *t, int mode)
{
    if (mode == 0) erase_cells(t, t->cy, t->cx, t->cols);
    else if (mode == 1) erase_cells(t, t->cy, 0, t->cx + 1);
    else if (mode == 2) erase_cells(t, t->cy, 0, t->cols);
}

static void insert_chars(vt *t, int n)
{
    vt_cell *row = t->line[t->cy];
    if (n > t->cols - t->cx) n = t->cols - t->cx;
    memmove(&row[t->cx + n], &row[t->cx], (size_t)(t->cols - t->cx - n) * sizeof(vt_cell));
    fill(&row[t->cx], n, blank_cell(t));
    mark(t, t->cy);
    t->wrap_pending = 0;
}

static void delete_chars(vt *t, int n)
{
    vt_cell *row = t->line[t->cy];
    if (n > t->cols - t->cx) n = t->cols - t->cx;
    memmove(&row[t->cx], &row[t->cx + n], (size_t)(t->cols - t->cx - n) * sizeof(vt_cell));
    fill(&row[t->cols - n], n, blank_cell(t));
    mark(t, t->cy);
    t->wrap_pending = 0;
}

/* ------------------------------------------------------------------ */
/* colour                                                              */
/* ------------------------------------------------------------------ */

void vt_palette_rgb(int i, vt_u8 *r, vt_u8 *g, vt_u8 *b)
{
    static const vt_u8 ansi[16][3] = {
        {0, 0, 0}, {205, 0, 0}, {0, 205, 0}, {205, 205, 0}, {0, 0, 238}, {205, 0, 205}, {0, 205, 205}, {229, 229, 229},
        {127, 127, 127}, {255, 0, 0}, {0, 255, 0}, {255, 255, 0}, {92, 92, 255}, {255, 0, 255}, {0, 255, 255}, {255, 255, 255}
    };
    static const vt_u8 lv[6] = { 0, 95, 135, 175, 215, 255 };
    if (i < 0) i = 0;
    if (i > 255) i = 255;
    if (i < 16) { *r = ansi[i][0]; *g = ansi[i][1]; *b = ansi[i][2]; }
    else if (i < 232) {
        i -= 16;
        *r = lv[i / 36]; *g = lv[(i / 6) % 6]; *b = lv[i % 6];
    } else {
        *r = *g = *b = (vt_u8)(8 + 10 * (i - 232));
    }
}

static int rgb_to_index(int r, int g, int b)
{
    static const int lv[6] = { 0, 95, 135, 175, 215, 255 };
    int best = 16, bestd = 1 << 30, i, j, k, d;
    if (r < 0) r = 0; if (r > 255) r = 255;
    if (g < 0) g = 0; if (g > 255) g = 255;
    if (b < 0) b = 0; if (b > 255) b = 255;
    for (i = 0; i < 6; i++) for (j = 0; j < 6; j++) for (k = 0; k < 6; k++) {
        d = (r - lv[i]) * (r - lv[i]) + (g - lv[j]) * (g - lv[j]) + (b - lv[k]) * (b - lv[k]);
        if (d < bestd) { bestd = d; best = 16 + 36 * i + 6 * j + k; }
    }
    for (i = 0; i < 24; i++) {
        int v = 8 + 10 * i;
        d = (r - v) * (r - v) + (g - v) * (g - v) + (b - v) * (b - v);
        if (d < bestd) { bestd = d; best = 232 + i; }
    }
    return best;
}

static void sgr(vt *t)
{
    int i, p;
    if (t->nparams == 0) { t->nparams = 1; t->params[0] = 0; }
    for (i = 0; i < t->nparams; i++) {
        p = t->params[i];
        if (p == 0) { t->pen.fg = 0; t->pen.bg = 0; t->pen.attr = VT_DEFFG | VT_DEFBG; }
        else if (p == 1) t->pen.attr |= VT_BOLD;
        else if (p == 2) t->pen.attr |= VT_DIM;
        else if (p == 3) t->pen.attr |= VT_ITALIC;
        else if (p == 4 || p == 21) t->pen.attr |= VT_UNDERLINE;
        else if (p == 5 || p == 6) t->pen.attr |= VT_BLINK;
        else if (p == 7) t->pen.attr |= VT_REVERSE;
        else if (p == 22) t->pen.attr &= (vt_u8)~(VT_BOLD | VT_DIM);
        else if (p == 23) t->pen.attr &= (vt_u8)~VT_ITALIC;
        else if (p == 24) t->pen.attr &= (vt_u8)~VT_UNDERLINE;
        else if (p == 25) t->pen.attr &= (vt_u8)~VT_BLINK;
        else if (p == 27) t->pen.attr &= (vt_u8)~VT_REVERSE;
        else if (p >= 30 && p <= 37) { t->pen.fg = (vt_u8)(p - 30); t->pen.attr &= (vt_u8)~VT_DEFFG; }
        else if (p == 39) t->pen.attr |= VT_DEFFG;
        else if (p >= 40 && p <= 47) { t->pen.bg = (vt_u8)(p - 40); t->pen.attr &= (vt_u8)~VT_DEFBG; }
        else if (p == 49) t->pen.attr |= VT_DEFBG;
        else if (p >= 90 && p <= 97) { t->pen.fg = (vt_u8)(p - 90 + 8); t->pen.attr &= (vt_u8)~VT_DEFFG; }
        else if (p >= 100 && p <= 107) { t->pen.bg = (vt_u8)(p - 100 + 8); t->pen.attr &= (vt_u8)~VT_DEFBG; }
        else if (p == 38 || p == 48) {
            int idx = -1;
            if (i + 2 < t->nparams && t->params[i + 1] == 5) {
                idx = t->params[i + 2] & 255;
                i += 2;
            } else if (i + 4 < t->nparams && t->params[i + 1] == 2) {
                idx = rgb_to_index(t->params[i + 2], t->params[i + 3], t->params[i + 4]);
                i += 4;
            } else {
                i = t->nparams;                          /* malformed: swallow the rest */
            }
            if (idx >= 0) {
                if (p == 38) { t->pen.fg = (vt_u8)idx; t->pen.attr &= (vt_u8)~VT_DEFFG; }
                else         { t->pen.bg = (vt_u8)idx; t->pen.attr &= (vt_u8)~VT_DEFBG; }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* modes                                                               */
/* ------------------------------------------------------------------ */

static void save_cursor(vt *t, int alt)
{
    vt_saved *s = alt ? &t->saved_alt : &t->saved;
    s->cx = t->cx; s->cy = t->cy; s->wrap_pending = t->wrap_pending; s->origin = t->origin;
    s->g0 = t->g0; s->g1 = t->g1; s->shift = t->shift; s->pen = t->pen;
}

static void restore_cursor(vt *t, int alt)
{
    vt_saved *s = alt ? &t->saved_alt : &t->saved;
    t->cx = s->cx; t->cy = s->cy; t->wrap_pending = s->wrap_pending; t->origin = s->origin;
    t->g0 = s->g0; t->g1 = s->g1; t->shift = s->shift; t->pen = s->pen;
    if (t->cx >= t->cols) t->cx = t->cols - 1;
    if (t->cy >= t->rows) t->cy = t->rows - 1;
}

static void switch_screen(vt *t, int alt)
{
    if ((alt != 0) == (t->in_alt != 0)) return;
    t->in_alt = alt;
    t->line = alt ? t->alt_line : t->main_line;
    if (alt) {
        int r;
        vt_cell b = blank_cell(t);
        for (r = 0; r < t->rows; r++) fill(t->line[r], t->cols, b);
    }
    t->all_dirty = 1;
    mark_range(t, 0, t->rows - 1);
}

static void set_mode(vt *t, int priv, int m, int on)
{
    if (priv == '?') {
        switch (m) {
        case 1:    t->app_cursor = on; break;
        case 5:    t->reverse_screen = on; t->all_dirty = 1; mark_range(t, 0, t->rows - 1); break;
        case 6:    t->origin = on; cursor_to(t, 0, 0); break;
        case 7:    t->autowrap = on; break;
        case 25:   t->cursor_visible = on; break;
        case 47: case 1047: switch_screen(t, on); break;
        case 1048: if (on) save_cursor(t, 1); else restore_cursor(t, 1); break;
        case 1049:
            if (on) { save_cursor(t, 1); switch_screen(t, 1); }
            else    { switch_screen(t, 0); restore_cursor(t, 1); }
            break;
        case 2004: t->bracketed_paste = on; break;
        case 9: case 1000: case 1002: case 1003:
            /* these four are mutually exclusive: setting one replaces whatever was active, but
             * disabling one that ISN'T the active mode (a stale/blanket cleanup sequence) must not
             * clobber a different mode a later "h" already switched to */
            if (on) t->mouse_mode = m;
            else if (t->mouse_mode == m) t->mouse_mode = 0;
            break;
        case 1006: t->mouse_sgr = on; break;
        case 1004: t->mouse_focus = on; break;
        default: break;
        }
    } else if (priv == 0) {
        if (m == 4) t->insert = on;
        else if (m == 20) t->newline_mode = on;
    }
}

/* ------------------------------------------------------------------ */
/* CSI                                                                 */
/* ------------------------------------------------------------------ */

static int prm(const vt *t, int i, int def)
{
    if (i >= t->nparams || t->params[i] <= 0) return def;
    return t->params[i];
}

static int raw(const vt *t, int i) { return i < t->nparams ? t->params[i] : 0; }

static void csi_dispatch(vt *t, int f)
{
    int n, i;

    if (t->inter) {                                   /* CSI ... SP/!/" final */
        if (t->inter == '!' && f == 'p') vt_reset(t);          /* DECSTR */
        return;
    }
    if (t->priv == '?') {
        if (f == 'h' || f == 'l')
            for (i = 0; i < t->nparams; i++) set_mode(t, '?', t->params[i], f == 'h');
        return;
    }
    if (t->priv == '>' || t->priv == '=' || t->priv == '<') return;      /* secondary DA etc.: stay quiet */

    switch (f) {
    case 'A': cursor_to(t, t->cy - (t->origin ? t->top : 0) - prm(t, 0, 1), t->cx); break;
    case 'B': case 'e': cursor_to(t, t->cy - (t->origin ? t->top : 0) + prm(t, 0, 1), t->cx); break;
    case 'C': case 'a': cursor_to(t, t->cy - (t->origin ? t->top : 0), t->cx + prm(t, 0, 1)); break;
    case 'D': cursor_to(t, t->cy - (t->origin ? t->top : 0), t->cx - prm(t, 0, 1)); break;
    case 'E': cursor_to(t, t->cy - (t->origin ? t->top : 0) + prm(t, 0, 1), 0); break;
    case 'F': cursor_to(t, t->cy - (t->origin ? t->top : 0) - prm(t, 0, 1), 0); break;
    case 'G': case '`': cursor_to(t, t->cy - (t->origin ? t->top : 0), prm(t, 0, 1) - 1); break;
    case 'H': case 'f': cursor_to(t, prm(t, 0, 1) - 1, prm(t, 1, 1) - 1); break;
    case 'd': cursor_to(t, prm(t, 0, 1) - 1, t->cx); break;
    case 'I': next_tab(t, prm(t, 0, 1)); break;
    case 'Z': prev_tab(t, prm(t, 0, 1)); break;
    case 'J': erase_display(t, raw(t, 0)); break;
    case 'K': erase_line(t, raw(t, 0)); break;
    case 'L':
        if (t->cy >= t->top && t->cy <= t->bottom) { scroll_down(t, t->cy, t->bottom, prm(t, 0, 1)); t->cx = 0; t->wrap_pending = 0; }
        break;
    case 'M':
        if (t->cy >= t->top && t->cy <= t->bottom) { scroll_up(t, t->cy, t->bottom, prm(t, 0, 1), 0); t->cx = 0; t->wrap_pending = 0; }
        break;
    case '@': insert_chars(t, prm(t, 0, 1)); break;
    case 'P': delete_chars(t, prm(t, 0, 1)); break;
    case 'X': n = prm(t, 0, 1); erase_cells(t, t->cy, t->cx, t->cx + n); break;
    case 'S': scroll_up(t, t->top, t->bottom, prm(t, 0, 1), 1); break;
    case 'T': scroll_down(t, t->top, t->bottom, prm(t, 0, 1)); break;
    case 'g':
        if (raw(t, 0) == 0) t->tabs[t->cx] = 0;
        else if (raw(t, 0) == 3) memset(t->tabs, 0, (size_t)t->cols);
        break;
    case 'h': case 'l':
        for (i = 0; i < t->nparams; i++) set_mode(t, 0, t->params[i], f == 'h');
        break;
    case 'm': sgr(t); break;
    case 'n':
        if (raw(t, 0) == 5) emit(t, "\033[0n");
        else if (raw(t, 0) == 6) {
            emit(t, "\033[");
            emit_num(t, t->cy + 1 - (t->origin ? t->top : 0));
            emit(t, ";");
            emit_num(t, t->cx + 1);
            emit(t, "R");
        }
        break;
    case 'c':
        if (raw(t, 0) == 0) emit(t, "\033[?1;2c");             /* VT100 with advanced video option */
        break;
    case 'r': {
        int top = prm(t, 0, 1) - 1, bot = prm(t, 1, t->rows) - 1;
        if (bot >= t->rows) bot = t->rows - 1;
        if (top < bot) { t->top = top; t->bottom = bot; }
        cursor_to(t, 0, 0);
        break;
    }
    case 's': save_cursor(t, 0); break;
    case 'u': restore_cursor(t, 0); break;
    default: break;
    }
}

/* ------------------------------------------------------------------ */
/* parser                                                              */
/* ------------------------------------------------------------------ */

static void osc_dispatch(vt *t)
{
    int n = 0, i = 0;
    t->osc[t->osc_len] = '\0';
    while (t->osc[i] >= '0' && t->osc[i] <= '9') n = n * 10 + (t->osc[i++] - '0');
    if (t->osc[i] == ';' && (n == 0 || n == 2)) {
        strncpy(t->title, t->osc + i + 1, VT_TITLEMAX - 1);
        t->title[VT_TITLEMAX - 1] = '\0';
        t->title_changed = 1;
    }
}

static void esc_dispatch(vt *t, int c)
{
    switch (c) {
    case '7': save_cursor(t, 0); break;
    case '8': restore_cursor(t, 0); break;
    case '=': t->app_keypad = 1; break;
    case '>': t->app_keypad = 0; break;
    case 'D': index_down(t); t->wrap_pending = 0; break;
    case 'E': index_down(t); t->cx = 0; t->wrap_pending = 0; break;
    case 'M': index_up(t); t->wrap_pending = 0; break;
    case 'H': t->tabs[t->cx] = 1; break;
    case 'c': vt_reset(t); break;
    case 'Z': emit(t, "\033[?1;2c"); break;
    default: break;
    }
}

static void ground_byte(vt *t, int c)
{
    if (t->utf8 && c >= 0x80) {
        if (c >= 0xc0) {                              /* start of a multi-byte sequence */
            if (t->utf8_left) put_cp(t, 0xfffd);
            if (c < 0xe0)      { t->utf8_cp = (vt_u32)(c & 0x1f); t->utf8_left = 1; }
            else if (c < 0xf0) { t->utf8_cp = (vt_u32)(c & 0x0f); t->utf8_left = 2; }
            else if (c < 0xf8) { t->utf8_cp = (vt_u32)(c & 0x07); t->utf8_left = 3; }
            else               { put_cp(t, 0xfffd); t->utf8_left = 0; }
        } else if (t->utf8_left) {                    /* continuation byte */
            t->utf8_cp = (t->utf8_cp << 6) | (vt_u32)(c & 0x3f);
            if (--t->utf8_left == 0) put_cp(t, t->utf8_cp);
        } else {
            put_cp(t, 0xfffd);                        /* stray continuation */
        }
        return;
    }
    if (t->utf8_left) { put_cp(t, 0xfffd); t->utf8_left = 0; }      /* truncated sequence */
    if (c < 0x20) { execute_c0(t, c); return; }
    if (c == 0x7f) return;
    /* 0x20..0x7e, or an 8-bit NeXTSTEP-encoded character when UTF-8 is off */
    put_cp(t, c >= 0x80 ? (vt_u32)nsenc_decode((unsigned char)c) : (vt_u32)c);
}

void vt_write(vt *t, const unsigned char *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        int c = data[i];

        /* Controls that act in every state */
        if (c == 0x18 || c == 0x1a) { t->state = ST_GROUND; continue; }        /* CAN, SUB */
        if (c == 0x1b && t->state != ST_OSC && t->state != ST_STRING) {
            t->state = ST_ESC;
            t->inter = 0;
            continue;
        }

        switch (t->state) {
        case ST_GROUND:
            ground_byte(t, c);
            break;
        case ST_ESC:
            if (c == '[') {
                t->state = ST_CSI;
                t->nparams = 0; t->priv = 0; t->inter = 0;
                memset(t->params, 0, sizeof(t->params));
            } else if (c == ']') { t->state = ST_OSC; t->osc_len = 0; }
            else if (c == 'P' || c == 'X' || c == '^' || c == '_') t->state = ST_STRING;
            else if (c >= 0x20 && c <= 0x2f) { t->inter = c; t->state = ST_ESC_INTER; }
            else if (c < 0x20) execute_c0(t, c);
            else { esc_dispatch(t, c); t->state = ST_GROUND; }
            break;
        case ST_ESC_INTER:
            if (c >= 0x20 && c <= 0x2f) break;
            if (t->inter == '(') t->g0 = (c == '0') ? 1 : 0;
            else if (t->inter == ')') t->g1 = (c == '0') ? 1 : 0;
            else if (t->inter == '#' && c == '8') {
                vt_cell e = blank_cell(t);
                int r, k;
                e.ch = 'E';
                for (r = 0; r < t->rows; r++) { for (k = 0; k < t->cols; k++) t->line[r][k] = e; mark(t, r); }
            } else if (t->inter == '%') {
                if (c == 'G') t->utf8 = 1; else if (c == '@') t->utf8 = 0;
            }
            t->state = ST_GROUND;
            break;
        case ST_CSI:
        case ST_CSI_INTER:
            if (c < 0x20) { execute_c0(t, c); break; }
            if (c >= '0' && c <= '9' && t->state == ST_CSI) {
                if (t->nparams == 0) t->nparams = 1;
                if (t->params[t->nparams - 1] < 100000)
                    t->params[t->nparams - 1] = t->params[t->nparams - 1] * 10 + (c - '0');
            } else if ((c == ';' || c == ':') && t->state == ST_CSI) {
                if (t->nparams == 0) t->nparams = 1;
                if (t->nparams < VT_MAXPARAMS) { t->nparams++; t->params[t->nparams - 1] = 0; }
            } else if (c >= 0x3c && c <= 0x3f && t->state == ST_CSI && t->nparams == 0 && !t->priv) {
                t->priv = c;
            } else if (c >= 0x20 && c <= 0x2f) {
                if (!t->inter) t->inter = c;
                t->state = ST_CSI_INTER;
            } else if (c >= 0x40 && c <= 0x7e) {
                csi_dispatch(t, c);
                t->state = ST_GROUND;
            } else {
                t->state = ST_GROUND;                 /* malformed: abandon */
            }
            break;
        case ST_OSC:
            if (c == 0x07 || c == 0x9c) { osc_dispatch(t); t->state = ST_GROUND; }
            else if (c == 0x1b) t->state = ST_OSC_ESC;
            else if (t->osc_len < VT_TITLEMAX + 4 && c >= 0x20) t->osc[t->osc_len++] = (char)c;
            break;
        case ST_OSC_ESC:
            if (c == '\\') osc_dispatch(t);
            t->state = ST_GROUND;
            break;
        case ST_STRING:
            if (c == 0x07 || c == 0x9c) t->state = ST_GROUND;
            else if (c == 0x1b) t->state = ST_STRING_ESC;
            break;
        case ST_STRING_ESC:
            t->state = ST_GROUND;
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void init_tabs(vt *t)
{
    int i;
    for (i = 0; i < t->cols; i++) t->tabs[i] = (vt_u8)((i % 8) == 0);
}

void vt_reset(vt *t)
{
    int r;
    memset(&t->saved, 0, sizeof(t->saved));
    memset(&t->saved_alt, 0, sizeof(t->saved_alt));
    t->pen.fg = 0; t->pen.bg = 0; t->pen.attr = VT_DEFFG | VT_DEFBG;
    t->saved.pen = t->saved_alt.pen = t->pen;
    if (t->in_alt) { t->in_alt = 0; t->line = t->main_line; }
    for (r = 0; r < t->rows; r++) fill(t->main_line[r], t->cols, blank_cell(t));
    t->cx = t->cy = 0;
    t->wrap_pending = 0;
    t->top = 0; t->bottom = t->rows - 1;
    t->autowrap = 1; t->origin = 0; t->insert = 0; t->newline_mode = 0;
    t->cursor_visible = 1; t->reverse_screen = 0;
    t->app_cursor = 0; t->app_keypad = 0; t->bracketed_paste = 0;
    t->mouse_mode = 0; t->mouse_sgr = 0; t->mouse_focus = 0;
    t->g0 = t->g1 = 0; t->shift = 0;
    t->state = ST_GROUND;
    t->utf8_left = 0;
    t->out_len = 0;
    init_tabs(t);
    t->all_dirty = 1;
    mark_range(t, 0, t->rows - 1);
}

vt *vt_new(int cols, int rows, int scrollback_lines)
{
    vt *t;
    vt_cell b;
    if (cols < 1) cols = 1;
    if (rows < 1) rows = 1;
    t = (vt *)calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->cols = cols; t->rows = rows;
    t->utf8 = 1;
    t->pen.attr = VT_DEFFG | VT_DEFBG;
    b = blank_cell(t);
    t->main_line = alloc_screen(rows, cols, b);
    t->alt_line = alloc_screen(rows, cols, b);
    t->dirty = (vt_u8 *)calloc((size_t)rows, 1);
    t->tabs = (vt_u8 *)calloc((size_t)cols, 1);
    if (scrollback_lines > 0) {
        t->sb = (vt_cell **)calloc((size_t)scrollback_lines, sizeof(vt_cell *));
        t->sb_w = (int *)calloc((size_t)scrollback_lines, sizeof(int));
        if (t->sb && t->sb_w) t->sb_max = scrollback_lines;
    }
    if (!t->main_line || !t->alt_line || !t->dirty || !t->tabs) { vt_free(t); return NULL; }
    t->line = t->main_line;
    vt_reset(t);
    return t;
}

void vt_free(vt *t)
{
    int i;
    if (!t) return;
    free_rows(t->main_line, t->rows);
    free_rows(t->alt_line, t->rows);
    for (i = 0; i < t->sb_count; i++) free(t->sb[(t->sb_head + i) % t->sb_max]);
    free(t->sb); free(t->sb_w); free(t->dirty); free(t->tabs);
    free(t);
}

static vt_cell **resize_screen(vt *t, vt_cell **old, int ncols, int nrows, int drop, int to_sb)
{
    vt_cell b = blank_cell(t);
    vt_cell **n = alloc_screen(nrows, ncols, b);
    int r, keep, w;
    if (!n) return NULL;
    for (r = 0; r < drop && r < t->rows; r++) {          /* lines pushed off the top */
        if (to_sb && t->sb_max > 0) {
            vt_cell *row = old[r];
            vt_cell *spare = sb_push(t, row);
            old[r] = spare ? spare : alloc_row(t->cols, b);
        }
    }
    keep = t->rows - drop;
    if (keep > nrows) keep = nrows;
    w = t->cols < ncols ? t->cols : ncols;
    for (r = 0; r < keep; r++) memcpy(n[r], old[r + drop], (size_t)w * sizeof(vt_cell));
    return n;
}

void vt_resize(vt *t, int cols, int rows)
{
    vt_cell **nm, **na;
    vt_u8 *nd, *nt;
    int drop = 0;

    if (cols < 1) cols = 1;
    if (rows < 1) rows = 1;
    if (cols == t->cols && rows == t->rows) return;
    if (rows < t->rows && t->cy >= rows) drop = t->cy - rows + 1;

    nd = (vt_u8 *)calloc((size_t)rows, 1);
    nt = (vt_u8 *)calloc((size_t)cols, 1);
    if (!nd || !nt) { free(nd); free(nt); return; }
    nm = resize_screen(t, t->main_line, cols, rows, t->in_alt ? 0 : drop, 1);
    na = resize_screen(t, t->alt_line, cols, rows, t->in_alt ? drop : 0, 0);
    if (!nm || !na) { free_rows(nm, rows); free_rows(na, rows); free(nd); free(nt); return; }

    free_rows(t->main_line, t->rows);
    free_rows(t->alt_line, t->rows);
    free(t->dirty); free(t->tabs);
    t->main_line = nm; t->alt_line = na;
    t->line = t->in_alt ? na : nm;
    t->dirty = nd; t->tabs = nt;
    t->cols = cols; t->rows = rows;
    init_tabs(t);
    t->cy -= drop;
    if (t->cy < 0) t->cy = 0;
    if (t->cy >= rows) t->cy = rows - 1;
    if (t->cx >= cols) t->cx = cols - 1;
    t->wrap_pending = 0;
    t->top = 0; t->bottom = rows - 1;
    t->saved.cx = t->saved.cy = t->saved_alt.cx = t->saved_alt.cy = 0;
    t->all_dirty = 1;
    mark_range(t, 0, rows - 1);
}

void vt_clear_dirty(vt *t)
{
    memset(t->dirty, 0, (size_t)t->rows);
    t->all_dirty = 0;
}

void vt_mark_all_dirty(vt *t)
{
    t->all_dirty = 1;
    mark_range(t, 0, t->rows - 1);
}

/* ------------------------------------------------------------------ */
/* keyboard & display helpers                                          */
/* ------------------------------------------------------------------ */

static int put_str(unsigned char *out, int n, const char *s)
{
    while (*s) out[n++] = (unsigned char)*s++;
    return n;
}

static int put_int(unsigned char *out, int n, int v)
{
    char tmp[12];
    int i = 0;
    if (v == 0) tmp[i++] = '0';
    while (v > 0) { tmp[i++] = (char)('0' + v % 10); v /= 10; }
    while (i) out[n++] = (unsigned char)tmp[--i];
    return n;
}

int vt_encode_key(const vt *t, int key, int mods, unsigned char *out)
{
    int m = 1 + ((mods & VT_MOD_SHIFT) ? 1 : 0) + ((mods & VT_MOD_ALT) ? 2 : 0) + ((mods & VT_MOD_CTRL) ? 4 : 0);
    int n = 0;
    char fin = 0;
    int num = 0;

    switch (key) {
    case VT_KEY_UP: fin = 'A'; break;
    case VT_KEY_DOWN: fin = 'B'; break;
    case VT_KEY_RIGHT: fin = 'C'; break;
    case VT_KEY_LEFT: fin = 'D'; break;
    case VT_KEY_HOME: fin = 'H'; break;
    case VT_KEY_END: fin = 'F'; break;
    case VT_KEY_INSERT: num = 2; break;
    case VT_KEY_DELETE: num = 3; break;
    case VT_KEY_PGUP: num = 5; break;
    case VT_KEY_PGDN: num = 6; break;
    case VT_KEY_BACKTAB: return put_str(out, 0, "\033[Z");
    default:
        if (key >= VT_KEY_F1 && key <= VT_KEY_F1 + 11) {
            static const int fnum[12] = { 0, 0, 0, 0, 15, 17, 18, 19, 20, 21, 23, 24 };
            int f = key - VT_KEY_F1;
            if (f < 4) { fin = (char)('P' + f); if (m == 1) { out[0] = 033; out[1] = 'O'; out[2] = (unsigned char)fin; return 3; } }
            else num = fnum[f];
            break;
        }
        return 0;
    }
    if (fin) {
        n = put_str(out, 0, "\033");
        if (m == 1) {
            n = put_str(out, n, (t->app_cursor && key <= VT_KEY_END) ? "O" : "[");
            out[n++] = (unsigned char)fin;
        } else {
            n = put_str(out, n, "[1;");
            n = put_int(out, n, m);
            out[n++] = (unsigned char)fin;
        }
        return n;
    }
    n = put_str(out, 0, "\033[");
    n = put_int(out, n, num);
    if (m != 1) { out[n++] = ';'; n = put_int(out, n, m); }
    out[n++] = '~';
    return n;
}

/* Bit layout verified against real xterm (button.c: BtnCode/EditorButton), not guessed: base 0, +4/+8/+16
 * for shift/meta(alt)/ctrl, +32 for motion, then the button number (0/1/2), +3 for "no button" (a
 * release in the default encoding, or motion with nothing held -- xterm computes this by passing
 * button = -1 into the same BtnCode() either way, in EVERY encoding), or +64/+65 for the wheel.
 * The one place encodings genuinely differ: SGR's release keeps the real button number and switches
 * the trailing letter to 'm' instead of folding release into that ambiguous +3 -- xterm's ButtonRelease
 * case only substitutes button = -1 for the default encoding, leaving it alone under SGR/pixel-position. */
int vt_encode_mouse(const vt *t, int button, int col, int row, int mods, int motion, int release,
                     unsigned char *out)
{
    int code, n;

    if (!t->mouse_mode) return 0;
    if (motion) {
        if (button < 0) { if (t->mouse_mode != 1003) return 0; }             /* no button: any-event only */
        else if (t->mouse_mode != 1002 && t->mouse_mode != 1003) return 0;   /* a button: needs 1002 or 1003 */
    } else if (release) {
        if (t->mouse_mode == 9) return 0;      /* X10 reports presses only */
        if (button >= 4) return 0;             /* wheel buttons never send a release (xterm doesn't either) */
    }
    /* a plain press is valid in every mode */

    code = 0;
    if (mods & VT_MOD_SHIFT) code += 4;
    if (mods & VT_MOD_ALT)   code += 8;         /* xterm's "meta" */
    if (mods & VT_MOD_CTRL)  code += 16;
    if (motion) code += 32;

    if (button >= 4) code += 64 + (button - 4);
    else if (motion && button < 0) code += 3;                       /* any-event: moving, nothing held */
    else if (release && !motion && !t->mouse_sgr) code += 3;        /* default encoding: ambiguous release */
    else code += (button < 0 ? 0 : button);                        /* press, drag, or an SGR release */

    if (t->mouse_sgr) {                         /* mode 1006: decimal, no 223-cell limit, own release letter */
        n = put_str(out, 0, "\033[<");
        n = put_int(out, n, code);
        out[n++] = ';';
        n = put_int(out, n, col);
        out[n++] = ';';
        n = put_int(out, n, row);
        out[n++] = (release && !motion) ? 'm' : 'M';
        return n;
    }

    /* default X10-derived encoding: three raw bytes, each value+32, so coordinates beyond 223 (255-32)
     * cannot be represented -- clamped here rather than left to overflow an unsigned char and corrupt
     * the sequence. */
    if (col > 223) col = 223;
    if (row > 223) row = 223;
    out[0] = 033; out[1] = '['; out[2] = 'M';
    out[3] = (unsigned char)(32 + code);
    out[4] = (unsigned char)(32 + col);
    out[5] = (unsigned char)(32 + row);
    return 6;
}

vt_u16 vt_fallback_char(vt_u16 cp)
{
    if (cp >= 0x2500 && cp <= 0x257f) {
        if (cp == 0x2500 || cp == 0x2501 || cp == 0x2504 || cp == 0x2505 || cp == 0x2508 || cp == 0x2509) return '-';
        if (cp == 0x2502 || cp == 0x2503 || cp == 0x2506 || cp == 0x2507 || cp == 0x250a || cp == 0x250b) return '|';
        return '+';
    }
    switch (cp) {
    case 0x25c6: case 0x25cf: case 0x2022: return '*';
    case 0x2592: case 0x2591: case 0x2593: case 0x2588: return '#';
    case 0x23ba: case 0x23bb: return '-';
    case 0x23bc: case 0x23bd: return '_';
    case 0x2264: return '<';
    case 0x2265: return '>';
    case 0x2260: return '!';
    case 0x03c0: return 'p';
    case 0x2018: case 0x2019: return '\'';
    case 0x201c: case 0x201d: return '"';
    case 0x2013: case 0x2014: return '-';
    case 0x2026: return '.';
    case 0x00a0: return ' ';
    case 0x2409: case 0x240c: case 0x240d: case 0x240a: case 0x2424: case 0x240b: return ' ';
    default: return cp < 0x100 ? cp : '?';
    }
}
