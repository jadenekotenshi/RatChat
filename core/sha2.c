#include <string.h>
#include "sha2.h"
#include "sha2_tab.h"

/* Calling memset through a volatile pointer keeps the compiler from proving the store dead and
 * dropping it (the reason this exists), while still using libc's optimized fill: the byte loop this
 * replaced cost about 28x what a memmove of the same size does, and sb_consume wipes every packet
 * it frees. */
static void *(*volatile wipe_memset)(void *, int, size_t) = memset;

void ssh_wipe(void *p, size_t n)
{
    wipe_memset(p, 0, n);
}

int ssh_ct_memcmp(const void *a, const void *b, size_t n)
{
    const u8 *x = (const u8 *)a, *y = (const u8 *)b;
    u8 d = 0;
    while (n--) d |= (u8)(*x++ ^ *y++);
    return d;
}

/* ------------------------------ SHA-256 ------------------------------ */

#define S256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define S256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S256_BS0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define S256_BS1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define S256_SS0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define S256_SS1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

/* One round on renamed variables: instead of shuffling all eight working values down one place every
 * round (h = g; g = f; ...), eight rounds are written out with the roles rotating, so the shuffle
 * costs nothing.  Only d and h change: d += T1 is the new e, and T1 + T2 is the new a, stored in h. */
#define RND256(a, b, c, d, e, f, g, h, i) do { \
    u32 t1_ = (h) + S256_BS1(e) + S256_CH(e, f, g) + K256[i] + w[i]; \
    u32 t2_ = S256_BS0(a) + S256_MAJ(a, b, c); \
    (d) += t1_; (h) = t1_ + t2_; } while (0)

static void sha256_block(sha256_ctx *c, const u8 *p)
{
    u32 w[64], a, b, cc, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) w[i] = LOAD32_BE(p + 4 * i);
    for (i = 16; i < 64; i++)
        w[i] = (S256_SS1(w[i - 2]) + w[i - 7] + S256_SS0(w[i - 15]) + w[i - 16]) & 0xffffffffUL;

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i += 8) {
        RND256(a, b, cc, d, e, f, g, h, i);
        RND256(h, a, b, cc, d, e, f, g, i + 1);
        RND256(g, h, a, b, cc, d, e, f, i + 2);
        RND256(f, g, h, a, b, cc, d, e, i + 3);
        RND256(e, f, g, h, a, b, cc, d, i + 4);
        RND256(d, e, f, g, h, a, b, cc, i + 5);
        RND256(cc, d, e, f, g, h, a, b, i + 6);
        RND256(b, cc, d, e, f, g, h, a, i + 7);
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g;  c->h[7] += h;
}

void sha256_init(sha256_ctx *c)
{
    memcpy(c->h, H256_INIT, sizeof(c->h));
    c->len = 0;
    c->n = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const u8 *p = (const u8 *)data;
    c->len += len;
    if (c->n) {
        size_t take = SHA256_BLOCK - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += (u32)take; p += take; len -= take;
        if (c->n < SHA256_BLOCK) return;
        sha256_block(c, c->buf);
        c->n = 0;
    }
    while (len >= SHA256_BLOCK) { sha256_block(c, p); p += SHA256_BLOCK; len -= SHA256_BLOCK; }
    if (len) { memcpy(c->buf, p, len); c->n = (u32)len; }
}

/* Padding is the 0x80 byte, zeros up to 8 bytes short of a block boundary (a whole extra block if
 * there is no room), then the bit length: built directly in the buffer, not fed through update() one
 * byte at a time. */
void sha256_final(sha256_ctx *c, u8 out[SHA256_DIGEST])
{
    u64 bits = c->len * 8;
    int i;

    c->buf[c->n++] = 0x80;
    if (c->n > 56) {
        memset(c->buf + c->n, 0, SHA256_BLOCK - c->n);
        sha256_block(c, c->buf);
        c->n = 0;
    }
    memset(c->buf + c->n, 0, 56 - c->n);
    STORE64_BE(c->buf + 56, bits);
    sha256_block(c, c->buf);
    for (i = 0; i < 8; i++) STORE32_BE(out + 4 * i, c->h[i]);
    ssh_wipe(c, sizeof(*c));
}

void sha256(const void *data, size_t len, u8 out[SHA256_DIGEST])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ------------------------------ SHA-512 ------------------------------ */

#define S512_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define S512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S512_BS0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define S512_BS1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define S512_SS0(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define S512_SS1(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static void sha512_block(sha512_ctx *c, const u8 *p)
{
    u64 w[80], a, b, cc, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) w[i] = LOAD64_BE(p + 8 * i);
    for (i = 16; i < 80; i++)
        w[i] = S512_SS1(w[i - 2]) + w[i - 7] + S512_SS0(w[i - 15]) + w[i - 16];

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 80; i++) {
        t1 = h + S512_BS1(e) + S512_CH(e, f, g) + K512[i] + w[i];
        t2 = S512_BS0(a) + S512_MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g;  c->h[7] += h;
}

void sha512_init(sha512_ctx *c)
{
    memcpy(c->h, H512_INIT, sizeof(c->h));
    c->len = 0;
    c->n = 0;
}

void sha512_update(sha512_ctx *c, const void *data, size_t len)
{
    const u8 *p = (const u8 *)data;
    c->len += len;
    if (c->n) {
        size_t take = SHA512_BLOCK - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += (u32)take; p += take; len -= take;
        if (c->n < SHA512_BLOCK) return;
        sha512_block(c, c->buf);
        c->n = 0;
    }
    while (len >= SHA512_BLOCK) { sha512_block(c, p); p += SHA512_BLOCK; len -= SHA512_BLOCK; }
    if (len) { memcpy(c->buf, p, len); c->n = (u32)len; }
}

void sha512_final(sha512_ctx *c, u8 out[SHA512_DIGEST])
{
    u64 bits = c->len * 8;
    int i;

    c->buf[c->n++] = 0x80;
    if (c->n > 112) {
        memset(c->buf + c->n, 0, SHA512_BLOCK - c->n);
        sha512_block(c, c->buf);
        c->n = 0;
    }
    memset(c->buf + c->n, 0, 120 - c->n);          /* zeros, including the high 64 bits of the 128-bit length */
    STORE64_BE(c->buf + 120, bits);
    sha512_block(c, c->buf);
    for (i = 0; i < 8; i++) STORE64_BE(out + 8 * i, c->h[i]);
    ssh_wipe(c, sizeof(*c));
}

void sha512(const void *data, size_t len, u8 out[SHA512_DIGEST])
{
    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, data, len);
    sha512_final(&c, out);
}

/* ------------------------------ SHA-384 ------------------------------ */

void sha384_init(sha384_ctx *c)
{
    memcpy(c->h, H384_INIT, sizeof(c->h));
    c->len = 0;
    c->n = 0;
}

void sha384_update(sha384_ctx *c, const void *data, size_t len) { sha512_update(c, data, len); }

void sha384_final(sha384_ctx *c, u8 out[SHA384_DIGEST])
{
    u8 full[SHA512_DIGEST];
    sha512_final(c, full);
    memcpy(out, full, SHA384_DIGEST);
    ssh_wipe(full, sizeof(full));
}

void sha384(const void *data, size_t len, u8 out[SHA384_DIGEST])
{
    sha384_ctx c;
    sha384_init(&c);
    sha384_update(&c, data, len);
    sha384_final(&c, out);
}
