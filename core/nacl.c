/*
 * X25519 and Ed25519, after TweetNaCl (public domain; D. J. Bernstein et al.).
 * Chosen for size and obviousness, not speed.  Field elements are 16 limbs of
 * 16 bits held in 64-bit signed integers.  Constants come from nacl_tab.h,
 * which tools/gen_tables.py derives from the curve parameters.
 */
#include <string.h>
#include "nacl.h"
#include "sha2.h"

typedef long long i64;
typedef i64 gf[16];

#include "nacl_tab.h"

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf gf_121665 = {0xDB41, 1};

static void set25519(gf r, const gf a)
{
    int i;
    for (i = 0; i < 16; i++) r[i] = a[i];
}

static void car25519(gf o)
{
    int i;
    i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;   /* not '<<': c may be negative */
    }
}

static void sel25519(gf p, gf q, int b)
{
    i64 t, c = ~((i64)b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(u8 *o, const gf n)
{
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = (u8)(t[i] & 0xff);
        o[2 * i + 1] = (u8)(t[i] >> 8);
    }
}

static int neq25519(const gf a, const gf b)
{
    u8 c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return ssh_ct_memcmp(c, d, 32) != 0;
}

static u8 par25519(const gf a)
{
    u8 d[32];
    pack25519(d, a);
    return (u8)(d[0] & 1);
}

static void unpack25519(gf o, const u8 *n)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fadd(gf o, const gf a, const gf b)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void fsub(gf o, const gf a, const gf b)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void fmul(gf o, const gf a, const gf b)
{
    i64 i, j, t[31];
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void fsqr(gf o, const gf a)
{
    fmul(o, a, a);
}

static void inv25519(gf o, const gf i)
{
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        fsqr(c, c);
        if (a != 2 && a != 4) fmul(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

static void pow2523(gf o, const gf i)
{
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
        fsqr(c, c);
        if (a != 1) fmul(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

/* ------------------------------ X25519 ------------------------------ */

void x25519(u8 out[32], const u8 scalar[32], const u8 point[32])
{
    u8 z[32];
    i64 x[80], r, i;
    gf a, b, c, d, e, f;

    for (i = 0; i < 31; i++) z[i] = scalar[i];
    z[31] = (u8)((scalar[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, point);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fsqr(d, e);
        fsqr(f, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fsqr(b, a);
        fsub(c, d, f);
        fmul(a, c, gf_121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fsqr(b, e);
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
    }
    for (i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv25519(x + 32, x + 32);
    fmul(x + 16, x + 16, x + 32);
    pack25519(out, x + 16);
    ssh_wipe(z, sizeof(z));
}

void x25519_base(u8 out[32], const u8 scalar[32])
{
    u8 nine[32];
    memset(nine, 0, 32);
    nine[0] = 9;
    x25519(out, scalar, nine);
}

/* ------------------------------ Ed25519 ------------------------------ */

static void ge_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    fsub(a, p[1], p[0]);
    fsub(t, q[1], q[0]);
    fmul(a, a, t);
    fadd(b, p[0], p[1]);
    fadd(t, q[0], q[1]);
    fmul(b, b, t);
    fmul(c, p[3], q[3]);
    fmul(c, c, gf_D2);
    fmul(d, p[2], q[2]);
    fadd(d, d, d);
    fsub(e, b, a);
    fsub(f, d, c);
    fadd(g, d, c);
    fadd(h, b, a);
    fmul(p[0], e, f);
    fmul(p[1], h, g);
    fmul(p[2], g, f);
    fmul(p[3], e, h);
}

static void ge_cswap(gf p[4], gf q[4], u8 b)
{
    int i;
    for (i = 0; i < 4; i++) sel25519(p[i], q[i], b);
}

static void ge_pack(u8 *r, gf p[4])
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    fmul(tx, p[0], zi);
    fmul(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (u8)(par25519(tx) << 7);
}

static void ge_scalarmult(gf p[4], gf q[4], const u8 *s)
{
    int i;
    set25519(p[0], gf0); set25519(p[1], gf1);
    set25519(p[2], gf1); set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        u8 b = (u8)((s[i / 8] >> (i & 7)) & 1);
        ge_cswap(p, q, b);
        ge_add(q, p);
        ge_add(p, p);
        ge_cswap(p, q, b);
    }
}

static void ge_scalarbase(gf p[4], const u8 *s)
{
    gf q[4];
    set25519(q[0], gf_X);
    set25519(q[1], gf_Y);
    set25519(q[2], gf1);
    fmul(q[3], gf_X, gf_Y);
    ge_scalarmult(p, q, s);
}

static const i64 L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
};

static void modL(u8 *r, i64 x[64])
{
    i64 carry, i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;  /* not '<<': carry may be negative */
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; ++j) x[j] -= carry * L[j];
    for (i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (u8)(x[i] & 255);
    }
}

static void reduce64(u8 r[64])
{
    i64 x[64], i;
    for (i = 0; i < 64; ++i) x[i] = r[i];
    for (i = 0; i < 64; ++i) r[i] = 0;
    modL(r, x);
}

void ed25519_keypair(u8 pk[32], u8 sk[64], const u8 seed[32])
{
    u8 d[64];
    gf p[4];
    sha512(seed, 32, d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;
    ge_scalarbase(p, d);
    ge_pack(pk, p);
    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);
    ssh_wipe(d, sizeof(d));
}

void ed25519_sign(u8 sig[64], const u8 *msg, size_t len, const u8 sk[64])
{
    u8 d[64], h[64], r[64];
    i64 x[64], i, j;
    gf p[4];
    sha512_ctx c;

    sha512(sk, 32, d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;

    sha512_init(&c);                       /* r = H(prefix || M) mod L */
    sha512_update(&c, d + 32, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, r);
    reduce64(r);
    ge_scalarbase(p, r);
    ge_pack(sig, p);                       /* R */

    sha512_init(&c);                       /* h = H(R || A || M) mod L */
    sha512_update(&c, sig, 32);
    sha512_update(&c, sk + 32, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, h);
    reduce64(h);

    for (i = 0; i < 64; i++) x[i] = 0;
    for (i = 0; i < 32; i++) x[i] = r[i];
    for (i = 0; i < 32; i++)
        for (j = 0; j < 32; j++) x[i + j] += (i64)h[i] * (i64)d[j];
    modL(sig + 32, x);                     /* S = r + h*a mod L */
    ssh_wipe(d, sizeof(d));
    ssh_wipe(r, sizeof(r));
}

static int unpackneg(gf r[4], const u8 p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    fsqr(num, r[1]);
    fmul(den, num, gf_D);
    fsub(num, num, r[2]);
    fadd(den, r[2], den);

    fsqr(den2, den);
    fsqr(den4, den2);
    fmul(den6, den4, den2);
    fmul(t, den6, num);
    fmul(t, t, den);

    pow2523(t, t);
    fmul(t, t, num);
    fmul(t, t, den);
    fmul(t, t, den);
    fmul(r[0], t, den);

    fsqr(chk, r[0]);
    fmul(chk, chk, den);
    if (neq25519(chk, num)) fmul(r[0], r[0], gf_I);

    fsqr(chk, r[0]);
    fmul(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7)) fsub(r[0], gf0, r[0]);
    fmul(r[3], r[0], r[1]);
    return 0;
}

int ed25519_verify(const u8 sig[64], const u8 *msg, size_t len, const u8 pk[32])
{
    u8 t[32], h[64];
    gf p[4], q[4];
    sha512_ctx c;

    if (unpackneg(q, pk)) return -1;

    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, h);
    reduce64(h);

    ge_scalarmult(p, q, h);
    ge_scalarbase(q, sig + 32);
    ge_add(p, q);
    ge_pack(t, p);
    return ssh_ct_memcmp(sig, t, 32) ? -1 : 0;
}
