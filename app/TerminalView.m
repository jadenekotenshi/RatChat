#import "TerminalView.h"
#import "UIHelpers.h"
#include "nsenc.h"
#include <string.h>

#define MARGIN 3.0

/* floor/ceil without <math.h>: an undeclared floor() would be assumed to return int and
 * silently miscompute, so geometry uses these plain-C helpers instead. */
static int ifloor(float x) { int i = (int)x; return (x < (float)i) ? i - 1 : i; }
static int iceil(float x)  { int i = (int)x; return (x > (float)i) ? i + 1 : i; }
#define CODE_DEFFG 256
#define CODE_DEFBG 257

@interface TerminalView (Private)
- (NSColor *)colorForCode:(int)code;
- (NSRect)rectForRow:(int)r;
- (void)drawRow:(int)r cursor:(BOOL)withCursor;
- (void)pointToCell:(NSPoint)p line:(int *)line col:(int *)col;
- (BOOL)cellIsSelectedLine:(int)line col:(int)col;
- (void)syncScroller;
- (void)markDirty;
- (void)sendString:(NSString *)s;
- (void)escTimeout:(NSTimer *)timer;
- (BOOL)reportMouseLine:(int)line col:(int)col button:(int)button flags:(unsigned)flags
                  motion:(int)motion release:(int)release;
- (BOOL)beginMouseReport:(NSEvent *)theEvent button:(int)button;
@end

@implementation TerminalView

- (id)initWithFrame:(NSRect)frame
{
    NSRect bb;
    self = [super initWithFrame:frame];
    if (!self) return nil;

    font = [[NSFont userFixedPitchFontOfSize:12.0] retain];
    if (!font) font = [[NSFont fontWithName:@"Courier" size:12.0] retain];
    bb = [font boundingRectForFont];
    cellW = [font widthOfString:@"M"];
    if (cellW < 1.0) cellW = 7.0;
    cellH = (float)iceil(bb.size.height);
    if (cellH < 8.0) cellH = 14.0;
    baseline = -bb.origin.y;                      /* distance from the cell bottom to the baseline */
    if (baseline < 0.0) baseline = 0.0;

    defaultFg = [[NSColor blackColor] retain];
    defaultBg = [[NSColor whiteColor] retain];

    cols = 80; rows = 24;
    term = vt_new(cols, rows, 2000);
    deleteSendsBackspace = 0;
    altSendsEscape = 1;
    lastSb = 0;
    [self fitToFrame];
    return self;
}

- (void)dealloc
{
    int i;
    [escTimer invalidate];
    vt_free(term);
    [font release];
    [defaultFg release];
    [defaultBg release];
    for (i = 0; i < 256; i++) [palette[i] release];
    [super dealloc];
}

- (void)setDelegate:(id)anObject { delegate = anObject; }
- (void)setScroller:(NSScroller *)aScroller
{
    scroller = aScroller;
    [scroller setTarget:self];
    [scroller setAction:@selector(scrollerMoved:)];
    [self syncScroller];
}
- (vt *)terminal { return term; }
- (int)cols { return cols; }
- (int)rows { return rows; }
- (BOOL)isOpaque { return YES; }
- (BOOL)acceptsFirstResponder { return YES; }
- (BOOL)acceptsFirstMouse:(NSEvent *)theEvent { return YES; }
- (void)setUTF8:(BOOL)flag { term->utf8 = flag ? 1 : 0; }

- (NSSize)contentSizeForCols:(int)c rows:(int)r
{
    return NSMakeSize(c * cellW + 2.0 * MARGIN, r * cellH + 2.0 * MARGIN);
}

/* ---------------------------------------------------------------- */
/* geometry */

- (NSRect)rectForRow:(int)r
{
    NSRect b = [self bounds];
    return NSMakeRect(0.0, NSMaxY(b) - MARGIN - (r + 1) * cellH, b.size.width, cellH);
}

- (void)fitToFrame
{
    NSRect b;
    int nc, nr;
    if (!term) return;                            /* called from -initWithFrame: before setup */
    b = [self bounds];
    nc = ifloor((b.size.width - 2.0 * MARGIN) / cellW);
    nr = ifloor((b.size.height - 2.0 * MARGIN) / cellH);
    if (nc < 2) nc = 2;
    if (nr < 1) nr = 1;
    if (nc == cols && nr == rows) return;
    cols = nc; rows = nr;
    vt_resize(term, cols, rows);
    if (scrollBack > vt_scrollback_count(term)) scrollBack = vt_scrollback_count(term);
    selActive = 0;
    [self syncScroller];
    [self setNeedsDisplay:YES];
    if ([delegate respondsToSelector:@selector(terminalView:resizedToCols:rows:)])
        [delegate terminalView:self resizedToCols:cols rows:rows];
}

- (void)setFrameSize:(NSSize)newSize
{
    [super setFrameSize:newSize];
    [self fitToFrame];
}

- (void)pointToCell:(NSPoint)p line:(int *)line col:(int *)col
{
    NSRect b = [self bounds];
    int r = ifloor((NSMaxY(b) - MARGIN - p.y) / cellH);
    int c = ifloor((p.x - MARGIN) / cellW);
    if (r < 0) r = 0;
    if (r >= rows) r = rows - 1;
    if (c < 0) c = 0;
    if (c >= cols) c = cols - 1;
    *line = r - scrollBack;                /* absolute: <0 is scrollback */
    *col = c;
}

/* ---------------------------------------------------------------- */
/* feeding output from the connection                                      */

- (void)markDirty
{
    int r;
    if (term->all_dirty || scrollBack > 0) {
        [self setNeedsDisplay:YES];
    } else {
        for (r = 0; r < rows && r < term->rows; r++)
            if (term->dirty[r]) [self setNeedsDisplayInRect:[self rectForRow:r]];
        if (lastCy < rows) [self setNeedsDisplayInRect:[self rectForRow:lastCy]];
        if (term->cy < rows) [self setNeedsDisplayInRect:[self rectForRow:term->cy]];
    }
    lastCx = term->cx;
    lastCy = term->cy;
    vt_clear_dirty(term);
}

- (void)writeBytes:(const unsigned char *)bytes length:(int)n
{
    unsigned char reply[64];
    int got, sb0 = vt_scrollback_count(term), sb1;

    vt_write(term, bytes, (size_t)n);
    sb1 = vt_scrollback_count(term);
    if (sb1 != sb0) {
        selActive = 0;                                     /* line numbers shifted under the selection */
        if (scrollBack > 0) {                              /* keep what the user is reading in place */
            scrollBack += sb1 - sb0;
            if (scrollBack > sb1) scrollBack = sb1;
        }
    }
    while ((got = vt_take_output(term, reply, sizeof(reply))) > 0)
        [delegate terminalView:self sendBytes:reply length:got];
    if (term->bell) { term->bell = 0; NSBeep(); }
    [self syncScroller];
    [self markDirty];
}

/* ---------------------------------------------------------------- */
/* drawing                                                          */

- (NSColor *)colorForCode:(int)code
{
    vt_u8 r, g, b;
    if (code == CODE_DEFFG) return defaultFg;
    if (code == CODE_DEFBG) return defaultBg;
    if (!palette[code]) {
        vt_palette_rgb(code, &r, &g, &b);
        palette[code] = [[NSColor colorWithCalibratedRed:r / 255.0 green:g / 255.0
                                                    blue:b / 255.0 alpha:1.0] retain];
    }
    return palette[code];
}

- (BOOL)cellIsSelectedLine:(int)line col:(int)col
{
    int l0 = selAnchorLine, c0 = selAnchorCol, l1 = selEndLine, c1 = selEndCol, t;
    if (!selActive) return NO;
    if (l0 > l1 || (l0 == l1 && c0 > c1)) { t = l0; l0 = l1; l1 = t; t = c0; c0 = c1; c1 = t; }
    if (line < l0 || line > l1) return NO;
    if (line == l0 && col < c0) return NO;
    if (line == l1 && col > c1) return NO;
    return YES;
}

/* Everything that determines how a cell looks, folded into one comparable key. */
static unsigned cell_key(const vt_cell *c, int invert, int reverse_screen,
                         int *fgCode, int *bgCode)
{
    int fg = (c->attr & VT_DEFFG) ? CODE_DEFFG : c->fg;
    int bg = (c->attr & VT_DEFBG) ? CODE_DEFBG : c->bg;
    int rev = ((c->attr & VT_REVERSE) ? 1 : 0) ^ (invert ? 1 : 0) ^ (reverse_screen ? 1 : 0);
    int t;
    if ((c->attr & VT_BOLD) && fg < 8) fg += 8;              /* bold brightens the base colours */
    if (rev) { t = fg; fg = bg; bg = t; }        /* codes 256/257 name the default colours themselves,
                                                    so swapping them yields correct reverse video */
    *fgCode = fg;
    *bgCode = bg;
    return (unsigned)fg | ((unsigned)bg << 9) |
           ((unsigned)(c->attr & (VT_BOLD | VT_UNDERLINE | VT_DIM)) << 18);
}

- (void)drawRow:(int)r cursor:(BOOL)withCursor
{
    int w = 0, c, e, n, i, fgc, bgc, fgc2, bgc2, line = r - scrollBack;
    const vt_cell *cells = vt_line_at(term, line, &w);
    NSRect rr = [self rectForRow:r];
    float x, y = rr.origin.y;
    unsigned key, key2;
    vt_cell blank;
    char buf[300];
    BOOL anyText;
    NSColor *fg;

    blank.ch = ' '; blank.fg = 0; blank.bg = 0; blank.attr = VT_DEFFG | VT_DEFBG;

    for (c = 0; c < cols; ) {
        const vt_cell *cell = (cells && c < w) ? &cells[c] : &blank;
        int inv = [self cellIsSelectedLine:line col:c] ||
                  (withCursor && r == term->cy && c == term->cx);
        key = cell_key(cell, inv, term->reverse_screen, &fgc, &bgc);

        for (e = c + 1; e < cols; e++) {                     /* extend the run */
            const vt_cell *cell2 = (cells && e < w) ? &cells[e] : &blank;
            int inv2 = [self cellIsSelectedLine:line col:e] ||
                       (withCursor && r == term->cy && e == term->cx);
            key2 = cell_key(cell2, inv2, term->reverse_screen, &fgc2, &bgc2);
            if (key2 != key) break;
        }
        n = e - c;
        x = MARGIN + c * cellW;

        [[self colorForCode:bgc] set];
        NSRectFill(NSMakeRect(x, y, n * cellW + (e == cols ? MARGIN : 0.0), cellH));

        anyText = NO;
        for (i = 0; i < n && i < (int)sizeof(buf) - 1; i++) {
            const vt_cell *cl = (cells && c + i < w) ? &cells[c + i] : &blank;
            int b = nsenc_encode(cl->ch);
            if (b < 0) b = nsenc_encode(vt_fallback_char(cl->ch));
            if (b < 0) b = '?';
            if (b == 0) b = ' ';
            buf[i] = (char)b;
            if (b != ' ') anyText = YES;
        }
        buf[i] = '\0';
        while (i > 0 && buf[i - 1] == ' ') buf[--i] = '\0';      /* don't paint trailing blanks */

        fg = [self colorForCode:fgc];
        if ((key >> 18) & VT_DIM)
            fg = [fg blendedColorWithFraction:0.5 ofColor:[self colorForCode:bgc]];
        if (anyText) {
            [font set];
            [fg set];
            PSmoveto(x, y + baseline);
            PSshow(buf);
            if ((key >> 18) & VT_BOLD) {                     /* overstrike: works with any font */
                PSmoveto(x + 1.0, y + baseline);
                PSshow(buf);
            }
        }
        if ((key >> 18) & VT_UNDERLINE) {
            [fg set];
            NSRectFill(NSMakeRect(x, y + baseline - 1.5, n * cellW, 1.0));
        }
        c = e;
    }
}

- (void)drawRect:(NSRect)rect
{
    int r, first, last;
    BOOL key = [[self window] isKeyWindow];
    BOOL live = (scrollBack == 0 && term->cursor_visible);
    NSRect b = [self bounds];

    [defaultBg set];
    NSRectFill(rect);

    first = ifloor((NSMaxY(b) - MARGIN - NSMaxY(rect)) / cellH);
    last  = ifloor((NSMaxY(b) - MARGIN - NSMinY(rect)) / cellH);
    if (first < 0) first = 0;
    if (last >= rows) last = rows - 1;
    for (r = first; r <= last; r++) [self drawRow:r cursor:(live && key)];

    if (live && !key) {                                      /* hollow cursor while inactive */
        NSRect cr = NSMakeRect(MARGIN + term->cx * cellW, [self rectForRow:term->cy].origin.y, cellW, cellH);
        [defaultFg set];
        NSFrameRect(cr);
    }
}

/* ---------------------------------------------------------------- */
/* scrolling                                                        */

- (void)syncScroller
{
    int sb = vt_scrollback_count(term);
    float total = (float)(sb + rows);
    if (!scroller) return;
    if (sb == 0) {
        [scroller setFloatValue:1.0 knobProportion:1.0];
        [scroller setEnabled:NO];
    } else {
        [scroller setEnabled:YES];
        [scroller setFloatValue:(float)(sb - scrollBack) / (float)sb knobProportion:(float)rows / total];
    }
}

- (void)scrollByLines:(int)n
{
    int sb = vt_scrollback_count(term), old = scrollBack;
    scrollBack += n;
    if (scrollBack < 0) scrollBack = 0;
    if (scrollBack > sb) scrollBack = sb;
    if (scrollBack != old) { [self syncScroller]; [self setNeedsDisplay:YES]; }
}

- (void)scrollerMoved:(id)sender
{
    int sb = vt_scrollback_count(term);
    switch ([scroller hitPart]) {
    case NSScrollerDecrementPage:  [self scrollByLines:rows - 1]; break;
    case NSScrollerIncrementPage:  [self scrollByLines:-(rows - 1)]; break;
    case NSScrollerDecrementLine:  [self scrollByLines:1]; break;
    case NSScrollerIncrementLine:  [self scrollByLines:-1]; break;
    case NSScrollerKnob:
    case NSScrollerKnobSlot: {
        int want = sb - ifloor([scroller floatValue] * sb + 0.5);
        if (want < 0) want = 0;
        if (want > sb) want = sb;
        if (want != scrollBack) { scrollBack = want; [self setNeedsDisplay:YES]; }
        break;
    }
    default: break;
    }
}

/* ---------------------------------------------------------------- */
/* keyboard                                                         */

- (void)sendString:(NSString *)s
{
    NSData *d;
    if (!s || [s length] == 0) return;
    d = [s dataUsingEncoding:(term->utf8 ? NSUTF8StringEncoding : NSNEXTSTEPStringEncoding)
        allowLossyConversion:YES];
    if ([d length]) [delegate terminalView:self sendBytes:(const unsigned char *)[d bytes] length:[d length]];
}

- (void)keyDown:(NSEvent *)theEvent
{
    NSString *chars = [theEvent characters];
    unsigned flags = [theEvent modifierFlags];
    unsigned short c;
    int key = 0, mods = 0, n;
    unsigned char out[32];

    if (!chars || [chars length] == 0) return;
    c = [chars characterAtIndex:0];

    /* Unconditional (unlike the "unrecognized key" trace further down): diagnosing exactly what a
     * real keypress delivers -- e.g. whether an arrow key really does arrive as the documented
     * two-event ESC-then-bare-letter NeXT quirk this file's escPending logic assumes, or as a
     * single event whose first char doesn't match KEYCH_UP/etc after all -- needs to see every
     * keyDown, not just ones nothing else already explains. Enable with: touch ~/.RatChat.trace */
    SSTrace("keyDown: first char U+%04X (%d chars total), modifierFlags 0x%x, escPending=%d",
            (unsigned)c, (int)[chars length], flags, (int)escPending);

    /* A held-back ESC (see below) is resolved by whatever key comes next, before anything else
     * about this keyDown is interpreted. */
    if (escPending) {
        int key2 = 0;
        escPending = NO;
        [escTimer invalidate]; escTimer = nil;
        if (flags == 0 && [chars length] == 1) {
            switch (c) {
            case 'A': key2 = VT_KEY_UP; break;
            case 'B': key2 = VT_KEY_DOWN; break;
            case 'C': key2 = VT_KEY_RIGHT; break;
            case 'D': key2 = VT_KEY_LEFT; break;
            }
        }
        if (key2) {
            n = vt_encode_key(term, key2, 0, out);
            if (n) [delegate terminalView:self sendBytes:out length:n];
            return;                          /* the held ESC was the first half of this pair: not sent on its own */
        }
        out[0] = 0x1b;
        [delegate terminalView:self sendBytes:out length:1];
        /* falls through: this key is handled normally below, as if the ESC had never been held back */
    }

    if ((flags & NSShiftKeyMask) && (c == KEYCH_PGUP || c == KEYCH_PGDN)) {        /* local scrollback */
        [self scrollByLines:(c == KEYCH_PGUP ? rows - 1 : -(rows - 1))];
        return;
    }
    if (scrollBack) { scrollBack = 0; [self syncScroller]; [self setNeedsDisplay:YES]; }
    selActive = 0;

    if (flags & NSShiftKeyMask)     mods |= VT_MOD_SHIFT;
    if (flags & NSAlternateKeyMask) mods |= VT_MOD_ALT;
    if (flags & NSControlKeyMask)   mods |= VT_MOD_CTRL;

    switch (c) {
    case KEYCH_UP: key = VT_KEY_UP; break;
    case KEYCH_DOWN: key = VT_KEY_DOWN; break;
    case KEYCH_LEFT: key = VT_KEY_LEFT; break;
    case KEYCH_RIGHT: key = VT_KEY_RIGHT; break;
    case KEYCH_HOME: key = VT_KEY_HOME; break;
    case KEYCH_END: key = VT_KEY_END; break;
    case KEYCH_PGUP: key = VT_KEY_PGUP; break;
    case KEYCH_PGDN: key = VT_KEY_PGDN; break;
    case KEYCH_INSERT: key = VT_KEY_INSERT; break;
    case KEYCH_DELETE: key = VT_KEY_DELETE; break;
    case BACKTAB_CHAR: key = VT_KEY_BACKTAB; break;
    default:
        if (c >= KEYCH_F1 && c < KEYCH_F1 + 12) key = VT_KEY_F1 + (c - KEYCH_F1);
        break;
    }
    if (key) {
        n = vt_encode_key(term, key, mods, out);
        SSTrace("keyDown: key=%d mods=%d app_cursor=%d -> n=%d bytes=%02X %02X %02X %02X delegate=%p",
                key, mods, term->app_cursor, n,
                n > 0 ? out[0] : 0, n > 1 ? out[1] : 0, n > 2 ? out[2] : 0, n > 3 ? out[3] : 0,
                (void *)delegate);
        if (n) [delegate terminalView:self sendBytes:out length:n];
        return;
    }

    if (c == 0x7f || c == 0x08) {                                    /* the Delete/Backspace key */
        out[0] = deleteSendsBackspace ? 0x08 : 0x7f;
        [delegate terminalView:self sendBytes:out length:1];
        return;
    }
    if (c == 0x03 && !(flags & NSControlKeyMask)) c = 0x0d;          /* keypad Enter */
    if (c == 0x0d) { out[0] = 0x0d; [delegate terminalView:self sendBytes:out length:1]; return; }

    if ((flags & NSAlternateKeyMask) && altSendsEscape) {
        NSString *base = [theEvent charactersIgnoringModifiers];
        out[0] = 0x1b;
        [delegate terminalView:self sendBytes:out length:1];
        [self sendString:(base && [base length]) ? base : chars];
        return;
    }

    /* A lone, unmodified ESC is held rather than sent immediately, in case it is the first half of
     * an arrow key (see escPending above); resolved within escTimeout if nothing else arrives.
     * Anything else unrecognized here is only logged, never held -- never ordinary printable text,
     * which could be something typed at the input line.  Enable with: touch ~/.RatChat.trace */
    if (c == 0x1b && [chars length] == 1 && flags == 0) {
        escPending = YES;
        escTimer = [NSTimer scheduledTimerWithTimeInterval:0.05 target:self
                                                    selector:@selector(escTimeout:) userInfo:nil repeats:NO];
        return;
    }
    if (c > 0x7e || (c < 0x20 && c != 0x09 && c != 0x0d)) {
        SSTrace("keyDown: unrecognized key, first char U+%04X (%d chars total), modifierFlags 0x%x",
                (unsigned)c, (int)[chars length], flags);
    }
    [self sendString:chars];
}

- (void)escTimeout:(NSTimer *)timer
{
    unsigned char esc = 0x1b;
    escPending = NO;
    escTimer = nil;                          /* a non-repeating NSTimer invalidates itself on firing */
    [delegate terminalView:self sendBytes:&esc length:1];
}

/* ---------------------------------------------------------------- */
/* mouse reporting (xterm protocol; see term/vt.h)                  */

/* Encodes and sends one event, if the terminal's currently enabled mode reports it (vt_encode_mouse
 * says no by returning 0, e.g. motion under a mode that does not track it). line/col are in the same
 * scrollback-relative, possibly out-of-range convention pointToCell: uses for local selection; clamped
 * to the visible grid and made 1-based here, since the wire protocol has no notion of scrollback.
 * Motion reports are suppressed when the cell has not changed, matching xterm itself ("only if the
 * mouse pointer has moved to a different character cell"). Returns whether anything was sent. */
- (BOOL)reportMouseLine:(int)line col:(int)col button:(int)button flags:(unsigned)flags
                  motion:(int)motion release:(int)release
{
    unsigned char out[16];
    int mods = 0, n;
    if (flags & NSShiftKeyMask)     mods |= VT_MOD_SHIFT;
    if (flags & NSAlternateKeyMask) mods |= VT_MOD_ALT;
    if (flags & NSControlKeyMask)   mods |= VT_MOD_CTRL;
    if (line < 0) line = 0;
    if (line >= rows) line = rows - 1;
    if (col < 0) col = 0;
    if (col >= cols) col = cols - 1;
    if (motion && line == mouseLastReportLine && col == mouseLastReportCol) return NO;
    n = vt_encode_mouse(term, button, col + 1, line + 1, mods, motion, release, out);
    if (!n) return NO;
    [delegate terminalView:self sendBytes:out length:n];
    mouseLastReportLine = line; mouseLastReportCol = col;
    return YES;
}

/* Called from mouseDown:/rightMouseDown: to decide, once, whether this whole gesture (through the
 * matching mouseUp:) is a report to the host or ordinary local interaction (selection, for the left
 * button) -- holding Shift always forces local interaction, the same override xterm itself uses.
 * Returns YES (and has already sent the press) if the caller should do nothing further. */
- (BOOL)beginMouseReport:(NSEvent *)theEvent button:(int)button
{
    NSPoint p;
    int line, col;
    if (!term->mouse_mode || ([theEvent modifierFlags] & NSShiftKeyMask)) { mouseReportingActive = NO; return NO; }
    [[self window] makeFirstResponder:self];
    p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    [self pointToCell:p line:&line col:&col];
    mouseReportingActive = YES;
    mouseReportButton = button;
    mouseLastReportLine = -1; mouseLastReportCol = -1;    /* out of range: the first motion report always goes through */
    [self reportMouseLine:line col:col button:button flags:[theEvent modifierFlags] motion:0 release:0];
    return YES;
}

/* ---------------------------------------------------------------- */
/* selection, copy, paste                                           */

- (BOOL)isWordChar:(unsigned short)ch
{
    if (ch > 0x7f) return YES;
    if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) return YES;
    return ch != 0 && strchr("_-./~:@%+=#", (int)ch) != NULL;
}

- (void)mouseDown:(NSEvent *)theEvent
{
    NSPoint p;
    int line, col, w, e;
    const vt_cell *cells;

    if ([self beginMouseReport:theEvent button:0]) return;   /* an app wants clicks: hold shift for local selection */

    p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    [[self window] makeFirstResponder:self];
    [self pointToCell:p line:&line col:&col];
    selAnchorLine = selEndLine = line;
    selAnchorCol = selEndCol = col;
    selActive = 0;

    if ([theEvent clickCount] >= 3) {                                /* whole line */
        selAnchorCol = 0; selEndCol = cols - 1; selActive = 1;
    } else if ([theEvent clickCount] == 2 && (cells = vt_line_at(term, line, &w)) != NULL && col < w) {
        int s = col;
        e = col;
        if ([self isWordChar:cells[col].ch]) {
            while (s > 0 && [self isWordChar:cells[s - 1].ch]) s--;
            while (e < w - 1 && [self isWordChar:cells[e + 1].ch]) e++;
        }
        selAnchorCol = s; selEndCol = e; selActive = 1;
    }
    [self setNeedsDisplay:YES];
}

- (void)mouseDragged:(NSEvent *)theEvent
{
    NSPoint p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    int line, col;
    [self pointToCell:p line:&line col:&col];
    if (mouseReportingActive) {
        [self reportMouseLine:line col:col button:mouseReportButton flags:[theEvent modifierFlags] motion:1 release:0];
        return;
    }
    if (line != selEndLine || col != selEndCol || !selActive) {
        selEndLine = line; selEndCol = col; selActive = 1;
        [self setNeedsDisplay:YES];
    }
}

- (void)mouseUp:(NSEvent *)theEvent
{
    NSPoint p;
    int line, col;
    if (!mouseReportingActive) return;
    p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    [self pointToCell:p line:&line col:&col];
    [self reportMouseLine:line col:col button:mouseReportButton flags:[theEvent modifierFlags] motion:0 release:1];
    mouseReportingActive = NO;
}

- (void)rightMouseDown:(NSEvent *)theEvent { [self beginMouseReport:theEvent button:2]; }
- (void)rightMouseDragged:(NSEvent *)theEvent
{
    if (!mouseReportingActive) return;
    [self mouseDragged:theEvent];
}
- (void)rightMouseUp:(NSEvent *)theEvent { [self mouseUp:theEvent]; }

#ifdef OPENSTEP
/* [V] -[NSEvent deltaX]/deltaY: confirmed absent from OPENSTEP 4.2's real AppKit (not just an
 * undeclared-but-present method, like the DIR/NSDragOperation build breaks were -- GNUstep's own
 * from-scratch reimplementation of the OpenStep API gates exactly this pair of accessors behind
 * "Mac OS X only", while the NSScrollWheel event type itself is not gated). There is no confirmed
 * way to read a wheel event's amount or direction on this platform, so this does nothing rather
 * than guess at one; the local scrollbar, Shift-PageUp/PageDown, and click/drag mouse reporting all
 * still work. See README.md's Mouse reporting section. */
- (void)scrollWheel:(NSEvent *)theEvent
{
}
#else
- (void)scrollWheel:(NSEvent *)theEvent
{
    float dy = [theEvent deltaY];
    if (dy == 0.0) return;
    if (term->mouse_mode && !([theEvent modifierFlags] & NSShiftKeyMask)) {
        NSPoint p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
        int line, col;
        [self pointToCell:p line:&line col:&col];
        [self reportMouseLine:line col:col button:(dy > 0.0 ? 4 : 5) flags:[theEvent modifierFlags]
                        motion:0 release:0];
        return;
    }
    [self scrollByLines:(dy > 0.0 ? 3 : -3)];      /* a fixed step per wheel event: robust to whatever
                                                     * granularity this hardware's NSEvent deltaY uses */
}
#endif

- (NSString *)selectedText
{
    int l0 = selAnchorLine, c0 = selAnchorCol, l1 = selEndLine, c1 = selEndCol, t, line, c, w, last;
    NSMutableString *out = [NSMutableString string];
    unichar row[512];
    if (!selActive) return nil;
    if (l0 > l1 || (l0 == l1 && c0 > c1)) { t = l0; l0 = l1; l1 = t; t = c0; c0 = c1; c1 = t; }
    for (line = l0; line <= l1; line++) {
        const vt_cell *cells = vt_line_at(term, line, &w);
        int from = (line == l0) ? c0 : 0, to = (line == l1) ? c1 : w - 1, n = 0;
        if (!cells) continue;
        if (to >= w) to = w - 1;
        last = to;
        if (line != l1) while (last >= from && cells[last].ch == ' ') last--;   /* trim trailing blanks */
        for (c = from; c <= last && n < 512; c++) row[n++] = cells[c].ch;
        [out appendString:[NSString stringWithCharacters:row length:n]];
        if (line != l1) [out appendString:@"\n"];
    }
    return out;
}

- (void)copy:(id)sender
{
    NSString *s = [self selectedText];
    NSPasteboard *pb;
    if (!s || [s length] == 0) return;
    pb = [NSPasteboard generalPasteboard];
    [pb declareTypes:[NSArray arrayWithObject:NSStringPboardType] owner:nil];
    [pb setString:s forType:NSStringPboardType];
}

- (void)paste:(id)sender
{
    NSString *s = [[NSPasteboard generalPasteboard] stringForType:NSStringPboardType];
    unsigned char esc[8];
    if (!s || [s length] == 0) return;
    if (scrollBack) { scrollBack = 0; [self syncScroller]; [self setNeedsDisplay:YES]; }
    if (term->bracketed_paste) {
        memcpy(esc, "\033[200~", 6);
        [delegate terminalView:self sendBytes:esc length:6];
    }
    [self sendString:s];
    if (term->bracketed_paste) {
        memcpy(esc, "\033[201~", 6);
        [delegate terminalView:self sendBytes:esc length:6];
    }
}

- (void)selectAll:(id)sender
{
    selAnchorLine = -scrollBack; selAnchorCol = 0;
    selEndLine = rows - 1 - scrollBack; selEndCol = cols - 1;
    selActive = 1;
    [self setNeedsDisplay:YES];
}

- (void)clearScrollback:(id)sender
{
    const unsigned char seq[] = "\033[3J";
    vt_write(term, seq, 4);
    scrollBack = 0;
    selActive = 0;
    [self syncScroller];
    [self setNeedsDisplay:YES];
}

- (BOOL)becomeFirstResponder
{
    [self setNeedsDisplay:YES];
    if (term->mouse_focus) { unsigned char seq[3]; seq[0] = 033; seq[1] = '['; seq[2] = 'I';
        [delegate terminalView:self sendBytes:seq length:3]; }
    return YES;
}
- (BOOL)resignFirstResponder
{
    [self setNeedsDisplay:YES];
    if (term->mouse_focus) { unsigned char seq[3]; seq[0] = 033; seq[1] = '['; seq[2] = 'O';
        [delegate terminalView:self sendBytes:seq length:3]; }
    return YES;
}

@end
