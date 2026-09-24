#include <string.h>
#include "sha1.h"

static void sha1_block(sha1_ctx *c, const u8 *p)
{
    u32 w[80], a, b, cc, d, e, f, k, t;
    int i;

    for (i = 0; i < 16; i++) w[i] = LOAD32_BE(p + 4 * i);
    for (i = 16; i < 80; i++) w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | (~b & d);            k = 0x5a827999UL; }
        else if (i < 40) { f = b ^ cc ^ d;                     k = 0x6ed9eba1UL; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);  k = 0x8f1bbcdcUL; }
        else             { f = b ^ cc ^ d;                     k = 0xca62c1d6UL; }
        t = (ROL32(a, 5) + f + e + k + w[i]) & 0xffffffffUL;
        e = d; d = cc; cc = ROL32(b, 30); b = a; a = t;
    }
    c->h[0] = (c->h[0] + a) & 0xffffffffUL; c->h[1] = (c->h[1] + b) & 0xffffffffUL;
    c->h[2] = (c->h[2] + cc) & 0xffffffffUL; c->h[3] = (c->h[3] + d) & 0xffffffffUL;
    c->h[4] = (c->h[4] + e) & 0xffffffffUL;
}

void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301UL; c->h[1] = 0xefcdab89UL; c->h[2] = 0x98badcfeUL;
    c->h[3] = 0x10325476UL; c->h[4] = 0xc3d2e1f0UL;
    c->len = 0; c->n = 0;
}

void sha1_update(sha1_ctx *c, const void *data, size_t len)
{
    const u8 *p = (const u8 *)data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += (u32)take; p += take; len -= take;
        if (c->n == 64) { sha1_block(c, c->buf); c->n = 0; }
    }
}

void sha1_final(sha1_ctx *c, u8 out[20])
{
    u64 bits = c->len * 8;
    u8 pad = 0x80, zero = 0, lenb[8];
    int i;
    sha1_update(c, &pad, 1);
    while (c->n != 56) sha1_update(c, &zero, 1);
    STORE64_BE(lenb, bits);
    sha1_update(c, lenb, 8);
    for (i = 0; i < 5; i++) STORE32_BE(out + 4 * i, c->h[i]);
    ssh_wipe(c, sizeof(*c));
}

void hmac_sha1(const u8 *key, size_t klen, const void *data, size_t len, u8 out[20])
{
    u8 k[64], pad[64], inner[20];
    sha1_ctx c;
    size_t i;
    memset(k, 0, sizeof(k));
    if (klen > 64) { sha1_init(&c); sha1_update(&c, key, klen); sha1_final(&c, k); }
    else memcpy(k, key, klen);
    for (i = 0; i < 64; i++) pad[i] = (u8)(k[i] ^ 0x36);
    sha1_init(&c); sha1_update(&c, pad, 64); sha1_update(&c, data, len); sha1_final(&c, inner);
    for (i = 0; i < 64; i++) pad[i] = (u8)(k[i] ^ 0x5c);
    sha1_init(&c); sha1_update(&c, pad, 64); sha1_update(&c, inner, 20); sha1_final(&c, out);
    ssh_wipe(k, sizeof(k));
}
