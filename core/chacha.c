#include <string.h>
#include "chacha.h"

/* ------------------------------ ChaCha20 ------------------------------ */

#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROL32(d, 16); \
    c += d; b ^= c; b = ROL32(b, 12); \
    a += b; d ^= a; d = ROL32(d, 8);  \
    c += d; b ^= c; b = ROL32(b, 7);

void chacha_keysetup(chacha_ctx *c, const u8 key[32])
{
    static const char sigma[] = "expand 32-byte k";
    int i;
    for (i = 0; i < 4; i++) c->s[i] = LOAD32_LE((const u8 *)sigma + 4 * i);
    for (i = 0; i < 8; i++) c->s[4 + i] = LOAD32_LE(key + 4 * i);
    c->s[12] = c->s[13] = c->s[14] = c->s[15] = 0;
}

void chacha_ivsetup(chacha_ctx *c, const u8 iv[8], u64 counter)
{
    c->s[12] = (u32)(counter & 0xffffffffUL);
    c->s[13] = (u32)(counter >> 32);
    c->s[14] = LOAD32_LE(iv);
    c->s[15] = LOAD32_LE(iv + 4);
}

static void chacha_block(const chacha_ctx *c, u8 out[64])
{
    u32 x[16];
    int i;
    memcpy(x, c->s, sizeof(x));
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]) QR(x[1], x[5], x[9],  x[13])
        QR(x[2], x[6], x[10], x[14]) QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15]) QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[8],  x[13]) QR(x[3], x[4], x[9],  x[14])
    }
    for (i = 0; i < 16; i++) {
        u32 v = x[i] + c->s[i];
        STORE32_LE(out + 4 * i, v);
    }
}

void chacha_xor(chacha_ctx *c, const u8 *in, u8 *out, size_t len)
{
    u8 ks[64];
    size_t i, n;
    while (len) {
        chacha_block(c, ks);
        if (++c->s[12] == 0) c->s[13]++;
        n = len < 64 ? len : 64;
        for (i = 0; i < n; i++) out[i] = (u8)(in[i] ^ ks[i]);
        in += n; out += n; len -= n;
    }
    ssh_wipe(ks, sizeof(ks));
}

/* ------------------------------ Poly1305 ------------------------------ */
/* 26-bit limb implementation (after poly1305-donna-32). */

typedef struct { u32 r[5], h[5], pad[4]; } poly_ctx;

static void poly_blocks(poly_ctx *p, const u8 *m, size_t bytes, u32 hibit)
{
    u32 r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
    u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    u32 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
    u64 d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;  /* always set before read, every pass of the
                                                    * while loop below; m68k's dataflow analysis
                                                    * can't see that across the loop back-edge */
    u32 c;

    while (bytes >= 16) {
        h0 += (LOAD32_LE(m)) & 0x3ffffff;
        h1 += (LOAD32_LE(m + 3) >> 2) & 0x3ffffff;
        h2 += (LOAD32_LE(m + 6) >> 4) & 0x3ffffff;
        h3 += (LOAD32_LE(m + 9) >> 6) & 0x3ffffff;
        h4 += (LOAD32_LE(m + 12) >> 8) | hibit;

        d0 = (u64)h0 * r0 + (u64)h1 * s4 + (u64)h2 * s3 + (u64)h3 * s2 + (u64)h4 * s1;
        d1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s4 + (u64)h3 * s3 + (u64)h4 * s2;
        d2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 + (u64)h3 * s4 + (u64)h4 * s3;
        d3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 + (u64)h3 * r0 + (u64)h4 * s4;
        d4 = (u64)h0 * r4 + (u64)h1 * r3 + (u64)h2 * r2 + (u64)h3 * r1 + (u64)h4 * r0;

        c = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffff;
        d1 += c; c = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffff;
        d2 += c; c = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffff;
        d3 += c; c = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffff;
        d4 += c; c = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16; bytes -= 16;
    }
    p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

void poly1305_auth(u8 mac[16], const u8 *msg, size_t len, const u8 key[32])
{
    poly_ctx p;
    u32 h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4, mask;
    u64 f;
    size_t full = len & ~(size_t)15;
    u8 last[16];
    size_t rem = len - full;

    p.r[0] = (LOAD32_LE(key))          & 0x3ffffff;
    p.r[1] = (LOAD32_LE(key + 3) >> 2) & 0x3ffff03;
    p.r[2] = (LOAD32_LE(key + 6) >> 4) & 0x3ffc0ff;
    p.r[3] = (LOAD32_LE(key + 9) >> 6) & 0x3f03fff;
    p.r[4] = (LOAD32_LE(key + 12) >> 8) & 0x00fffff;
    p.h[0] = p.h[1] = p.h[2] = p.h[3] = p.h[4] = 0;
    p.pad[0] = LOAD32_LE(key + 16); p.pad[1] = LOAD32_LE(key + 20);
    p.pad[2] = LOAD32_LE(key + 24); p.pad[3] = LOAD32_LE(key + 28);

    poly_blocks(&p, msg, full, 1UL << 24);
    if (rem) {
        memset(last, 0, sizeof(last));
        memcpy(last, msg + full, rem);
        last[rem] = 1;
        poly_blocks(&p, last, 16, 0);
    }

    h0 = p.h[0]; h1 = p.h[1]; h2 = p.h[2]; h3 = p.h[3]; h4 = p.h[4];
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    mask = (g4 >> 31) - 1;         /* all ones if h >= p, else zero */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26)) & 0xffffffffUL;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffUL;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffUL;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffUL;

    f = (u64)h0 + p.pad[0];               h0 = (u32)f;
    f = (u64)h1 + p.pad[1] + (f >> 32);   h1 = (u32)f;
    f = (u64)h2 + p.pad[2] + (f >> 32);   h2 = (u32)f;
    f = (u64)h3 + p.pad[3] + (f >> 32);   h3 = (u32)f;
    STORE32_LE(mac, h0); STORE32_LE(mac + 4, h1);
    STORE32_LE(mac + 8, h2); STORE32_LE(mac + 12, h3);
    ssh_wipe(&p, sizeof(p));
}

/* --------------------- chacha20-poly1305@openssh.com --------------------- */

void chachapoly_init(chachapoly_ctx *c, const u8 key[CHACHAPOLY_KEYLEN])
{
    chacha_keysetup(&c->main, key);
    chacha_keysetup(&c->header, key + 32);
}

static void seq_iv(u32 seq, u8 iv[8])
{
    iv[0] = iv[1] = iv[2] = iv[3] = 0;
    STORE32_BE(iv + 4, seq);
}

u32 chachapoly_peek_length(chachapoly_ctx *c, u32 seq, const u8 enc_len[4])
{
    u8 iv[8], plain[4];
    seq_iv(seq, iv);
    chacha_ivsetup(&c->header, iv, 0);
    chacha_xor(&c->header, enc_len, plain, 4);
    return LOAD32_BE(plain);
}

void chachapoly_seal(chachapoly_ctx *c, u32 seq, u8 *dst, const u8 *src, size_t len)
{
    u8 iv[8], polykey[32];
    seq_iv(seq, iv);
    memset(polykey, 0, 32);
    chacha_ivsetup(&c->main, iv, 0);
    chacha_xor(&c->main, polykey, polykey, 32);

    chacha_ivsetup(&c->header, iv, 0);
    chacha_xor(&c->header, src, dst, CHACHAPOLY_AADLEN);
    chacha_ivsetup(&c->main, iv, 1);
    chacha_xor(&c->main, src + CHACHAPOLY_AADLEN, dst + CHACHAPOLY_AADLEN, len);
    poly1305_auth(dst + CHACHAPOLY_AADLEN + len, dst, CHACHAPOLY_AADLEN + len, polykey);
    ssh_wipe(polykey, sizeof(polykey));
}

int chachapoly_open(chachapoly_ctx *c, u32 seq, u8 *dst, const u8 *src, size_t len)
{
    u8 iv[8], polykey[32], tag[16];
    int bad;
    seq_iv(seq, iv);
    memset(polykey, 0, 32);
    chacha_ivsetup(&c->main, iv, 0);
    chacha_xor(&c->main, polykey, polykey, 32);

    poly1305_auth(tag, src, CHACHAPOLY_AADLEN + len, polykey);
    bad = ssh_ct_memcmp(tag, src + CHACHAPOLY_AADLEN + len, CHACHAPOLY_TAGLEN);
    ssh_wipe(polykey, sizeof(polykey));
    if (bad) return -1;

    chacha_ivsetup(&c->header, iv, 0);
    chacha_xor(&c->header, src, dst, CHACHAPOLY_AADLEN);
    chacha_ivsetup(&c->main, iv, 1);
    chacha_xor(&c->main, src + CHACHAPOLY_AADLEN, dst + CHACHAPOLY_AADLEN, len);
    return 0;
}
