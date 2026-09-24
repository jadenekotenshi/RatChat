#include <stdlib.h>
#include <string.h>
#include "wire.h"

void sb_init(sbuf *b) { b->p = NULL; b->len = b->cap = 0; b->oom = 0; }

void sb_free(sbuf *b)
{
    if (b->p) { ssh_wipe(b->p, b->cap); free(b->p); }
    sb_init(b);
}

void sb_clear(sbuf *b)
{
    if (b->p) ssh_wipe(b->p, b->len);
    b->len = 0;
}

int sb_reserve(sbuf *b, size_t extra)
{
    size_t need = b->len + extra, ncap;
    u8 *np;
    if (b->oom) return -1;
    if (need < b->len) { b->oom = 1; return -1; }        /* overflow */
    if (need <= b->cap) return 0;
    ncap = b->cap ? b->cap : 256;
    while (ncap < need) {
        if (ncap > ((size_t)-1) / 2) { b->oom = 1; return -1; }
        ncap *= 2;
    }
    np = (u8 *)malloc(ncap);
    if (!np) { b->oom = 1; return -1; }
    if (b->p) { memcpy(np, b->p, b->len); ssh_wipe(b->p, b->cap); free(b->p); }
    b->p = np; b->cap = ncap;
    return 0;
}

int sb_put(sbuf *b, const void *d, size_t n)
{
    if (sb_reserve(b, n) < 0) return -1;
    if (n) memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}

int sb_put_u8(sbuf *b, u8 v) { return sb_put(b, &v, 1); }

int sb_put_u32(sbuf *b, u32 v)
{
    u8 t[4];
    STORE32_BE(t, v);
    return sb_put(b, t, 4);
}

int sb_put_u64(sbuf *b, u64 v)
{
    u8 t[8];
    STORE64_BE(t, v);
    return sb_put(b, t, 8);
}

int sb_put_str(sbuf *b, const void *d, size_t n)
{
    if (sb_put_u32(b, (u32)n) < 0) return -1;
    return sb_put(b, d, n);
}

int sb_put_cstr(sbuf *b, const char *s) { return sb_put_str(b, s, strlen(s)); }

int sb_put_mpint(sbuf *b, const u8 *be, size_t n)
{
    while (n && *be == 0) { be++; n--; }                 /* strip leading zeros */
    if (n == 0) return sb_put_u32(b, 0);
    if (be[0] & 0x80) {                                  /* keep it non-negative */
        if (sb_put_u32(b, (u32)n + 1) < 0 || sb_put_u8(b, 0) < 0) return -1;
    } else {
        if (sb_put_u32(b, (u32)n) < 0) return -1;
    }
    return sb_put(b, be, n);
}

void sb_consume(sbuf *b, size_t n)
{
    if (n >= b->len) { sb_clear(b); return; }
    memmove(b->p, b->p + n, b->len - n);
    ssh_wipe(b->p + (b->len - n), n);
    b->len -= n;
}

/* ------------------------------ reader ------------------------------ */

void sr_init(sreader *r, const u8 *p, size_t len) { r->p = p; r->len = len; r->pos = 0; r->err = 0; }
size_t sr_left(const sreader *r) { return r->err ? 0 : r->len - r->pos; }

const u8 *sr_bytes(sreader *r, size_t n)
{
    const u8 *p;
    if (r->err || n > r->len - r->pos) { r->err = 1; return NULL; }
    p = r->p + r->pos;
    r->pos += n;
    return p;
}

u8 sr_u8(sreader *r)
{
    const u8 *p = sr_bytes(r, 1);
    return p ? p[0] : 0;
}

u32 sr_u32(sreader *r)
{
    const u8 *p = sr_bytes(r, 4);
    return p ? LOAD32_BE(p) : 0;
}

u64 sr_u64(sreader *r)
{
    const u8 *p = sr_bytes(r, 8);
    return p ? LOAD64_BE(p) : 0;
}

const u8 *sr_str(sreader *r, size_t *len)
{
    u32 n = sr_u32(r);
    const u8 *p;
    if (r->err) { *len = 0; return NULL; }
    p = sr_bytes(r, n);
    *len = p ? n : 0;
    return p;
}

/* ------------------------------ base64 ------------------------------ */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_encode(const u8 *in, size_t n, char *out, size_t outsz, int pad)
{
    size_t i, o = 0, need = pad ? ((n + 2) / 3) * 4 : (n * 4 + 2) / 3;
    u32 v;
    if (outsz < need + 1) return -1;
    for (i = 0; i + 2 < n; i += 3) {
        v = ((u32)in[i] << 16) | ((u32)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64[(v >> 18) & 63]; out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];  out[o++] = B64[v & 63];
    }
    if (n - i == 1) {
        v = (u32)in[i] << 16;
        out[o++] = B64[(v >> 18) & 63]; out[o++] = B64[(v >> 12) & 63];
        if (pad) { out[o++] = '='; out[o++] = '='; }
    } else if (n - i == 2) {
        v = ((u32)in[i] << 16) | ((u32)in[i + 1] << 8);
        out[o++] = B64[(v >> 18) & 63]; out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        if (pad) out[o++] = '=';
    }
    out[o] = '\0';
    return (int)o;
}

int b64_decode(const char *in, size_t n, u8 *out, size_t outsz)
{
    u32 acc = 0;
    int bits = 0, v, seen_pad = 0;
    size_t i, o = 0;
    const char *q;
    for (i = 0; i < n; i++) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '=') { seen_pad = 1; continue; }
        if (seen_pad) return -1;                         /* data after padding */
        q = strchr(B64, c);
        if (!q || c == '\0') return -1;
        v = (int)(q - B64);
        acc = (acc << 6) | (u32)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outsz) return -1;
            out[o++] = (u8)((acc >> bits) & 0xff);
        }
    }
    return (int)o;
}
