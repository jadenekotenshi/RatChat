#include <string.h>
#include "sha1.h"

/* The four groups of 20 rounds differ only in the boolean function and the constant; each round is
 * written on renamed variables (the roles of a..e rotate every round) so nothing is shuffled. */
#define F1(b, c, d) (((b) & (c)) | (~(b) & (d)))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define SHA1_RND(f, k, a, b, c, d, e, i) do { \
    (e) += ROL32(a, 5) + f(b, c, d) + (k) + w[i]; (b) = ROL32(b, 30); } while (0)
#define SHA1_5(f, k, i) do { \
    SHA1_RND(f, k, a, b, cc, d, e, i);     SHA1_RND(f, k, e, a, b, cc, d, (i) + 1); \
    SHA1_RND(f, k, d, e, a, b, cc, (i) + 2); SHA1_RND(f, k, cc, d, e, a, b, (i) + 3); \
    SHA1_RND(f, k, b, cc, d, e, a, (i) + 4); } while (0)

static void sha1_block(sha1_ctx *c, const u8 *p)
{
    u32 w[80], a, b, cc, d, e;
    int i;

    for (i = 0; i < 16; i++) w[i] = LOAD32_BE(p + 4 * i);
    for (i = 16; i < 80; i++) w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
    for (i = 0; i < 20; i += 5) SHA1_5(F1, 0x5a827999UL, i);
    for (i = 20; i < 40; i += 5) SHA1_5(F2, 0x6ed9eba1UL, i);
    for (i = 40; i < 60; i += 5) SHA1_5(F3, 0x8f1bbcdcUL, i);
    for (i = 60; i < 80; i += 5) SHA1_5(F2, 0xca62c1d6UL, i);
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
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
    if (c->n) {                                    /* top up a partly filled buffer first */
        size_t take = 64 - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += (u32)take; p += take; len -= take;
        if (c->n < 64) return;
        sha1_block(c, c->buf);
        c->n = 0;
    }
    while (len >= 64) { sha1_block(c, p); p += 64; len -= 64; }      /* whole blocks straight from the input */
    if (len) { memcpy(c->buf, p, len); c->n = (u32)len; }
}

void sha1_final(sha1_ctx *c, u8 out[20])
{
    u64 bits = c->len * 8;
    int i;

    c->buf[c->n++] = 0x80;
    if (c->n > 56) {
        memset(c->buf + c->n, 0, 64 - c->n);
        sha1_block(c, c->buf);
        c->n = 0;
    }
    memset(c->buf + c->n, 0, 56 - c->n);
    STORE64_BE(c->buf + 56, bits);
    sha1_block(c, c->buf);
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
