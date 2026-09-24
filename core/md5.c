#include <string.h>
#include "md5.h"
#include "md5_tab.h"

static const u8 MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static void md5_block(md5_ctx *c, const u8 *p)
{
    u32 w[16], a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], f, t;
    int i, g;
    for (i = 0; i < 16; i++) w[i] = LOAD32_LE(p + 4 * i);
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & cc) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ cc ^ d;          g = (3 * i + 5) & 15; }
        else             { f = cc ^ (b | ~d);       g = (7 * i) & 15; }
        t = d; d = cc; cc = b;
        b = (b + ROL32((a + f + MD5_K[i] + w[g]) & 0xffffffffUL, MD5_S[i])) & 0xffffffffUL;
        a = t;
    }
    c->h[0] = (c->h[0] + a) & 0xffffffffUL; c->h[1] = (c->h[1] + b) & 0xffffffffUL;
    c->h[2] = (c->h[2] + cc) & 0xffffffffUL; c->h[3] = (c->h[3] + d) & 0xffffffffUL;
}

void md5_init(md5_ctx *c)
{
    c->h[0] = 0x67452301UL; c->h[1] = 0xefcdab89UL; c->h[2] = 0x98badcfeUL; c->h[3] = 0x10325476UL;
    c->len = 0; c->n = 0;
}

void md5_update(md5_ctx *c, const void *data, size_t len)
{
    const u8 *p = (const u8 *)data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += (u32)take; p += take; len -= take;
        if (c->n == 64) { md5_block(c, c->buf); c->n = 0; }
    }
}

void md5_final(md5_ctx *c, u8 out[16])
{
    u64 bits = c->len * 8;
    u8 pad = 0x80, zero = 0, lenb[8];
    int i;
    md5_update(c, &pad, 1);
    while (c->n != 56) md5_update(c, &zero, 1);
    for (i = 0; i < 8; i++) lenb[i] = (u8)(bits >> (8 * i));         /* length is little-endian */
    md5_update(c, lenb, 8);
    for (i = 0; i < 4; i++) STORE32_LE(out + 4 * i, c->h[i]);
    ssh_wipe(c, sizeof(*c));
}
