#include <stdlib.h>
#include <string.h>
#include "../core/bignum.h"
#include "../core/sha2.h"
#include "test.h"
#include "bn_vectors.h"

/* Must match operand() in tools/gen_bn_vectors.py. */
static void operand(u8 *out, unsigned seed, unsigned nbytes, unsigned mode)
{
    unsigned i;
    u32 x = seed;
    if (mode == 1) { memset(out, 0xff, nbytes); return; }
    if (mode == 2) { if (nbytes > 1) { memset(out, 0, nbytes); out[0] = 0x80; out[nbytes - 1] = 1; } else out[0] = 0x81; return; }
    if (mode == 3) { memset(out, 0xff, nbytes); out[0] = 0x7f; return; }
    if (mode == 4) { memset(out, 0xff, nbytes); out[nbytes - 1] = 0xfe; return; }
    if (mode == 5) { if (nbytes > 4) { memset(out, 0, nbytes); out[3] = 1; } else out[0] = 1; return; }
    for (i = 0; i < nbytes; i++) { x = x * 1103515245UL + 12345UL; out[i] = (u8)((x >> 20) & 0xff); }
    if (mode == 0) out[nbytes - 1] |= 1;
}

static int digest_is(const bn *v, const u8 *want)
{
    u8 buf[512], d[32];
    size_t n = (size_t)(bn_bits(v) + 7) / 8;
    if (n > sizeof(buf) || bn_to_bytes(v, buf, n) != 0) return 0;
    sha256(buf, n, d);
    return memcmp(d, want, 32) == 0;
}

static void test_arith(void)
{
    unsigned i;
    for (i = 0; i < sizeof(BN_ARITH) / sizeof(BN_ARITH[0]); i++) {
        u8 ab[512], bb[512];
        bn a, b, q, r, t, hi, lo, one;
        bn_arith_case c = BN_ARITH[i];
        bn_init(&a); bn_init(&b); bn_init(&q); bn_init(&r); bn_init(&t); bn_init(&hi); bn_init(&lo); bn_init(&one);
        operand(ab, c.sa, c.la, c.ma); operand(bb, c.sb, c.lb, c.mb);
        bn_from_bytes(&a, ab, c.la); bn_from_bytes(&b, bb, c.lb);
        if (bn_is_zero(&b)) bn_set_u32(&b, 1);
        CHECK(bn_divmod(&q, &r, &a, &b) == 0);
        CHECK(digest_is(&r, BN_ARITH_EXP[i][0]));                  /* a mod b */
        CHECK(digest_is(&q, BN_ARITH_EXP[i][1]));                  /* a div b */
        bn_mul(&t, &a, &b);            CHECK(digest_is(&t, BN_ARITH_EXP[i][2]));
        bn_add(&t, &a, &b);            CHECK(digest_is(&t, BN_ARITH_EXP[i][3]));
        if (bn_cmp(&a, &b) >= 0) { hi = a; lo = b; } else { hi = b; lo = a; }
        bn_sub(&t, &hi, &lo);          CHECK(digest_is(&t, BN_ARITH_EXP[i][4]));
        bn_shl(&t, &a, 13);            CHECK(digest_is(&t, BN_ARITH_EXP[i][5]));
        bn_shr(&t, &a, 45);            CHECK(digest_is(&t, BN_ARITH_EXP[i][6]));
        /* identity: q*b + r == a */
        bn_mul(&t, &q, &b); bn_add(&t, &t, &r);
        CHECK(bn_cmp(&t, &a) == 0 && bn_cmp(&r, &b) < 0);
        bn_free(&a); bn_free(&b); bn_free(&q); bn_free(&r); bn_free(&t); bn_free(&one);
    }
}

static void test_modexp(void)
{
    unsigned i;
    for (i = 0; i < sizeof(BN_EXP) / sizeof(BN_EXP[0]); i++) {
        u8 bb[512], eb[512], mb[512];
        bn b, e, m, r;
        bn_exp_case c = BN_EXP[i];
        bn_init(&b); bn_init(&e); bn_init(&m); bn_init(&r);
        operand(bb, c.sb, c.lb, 0); operand(eb, c.se, c.le, 0); operand(mb, c.sm, c.lm, 0);
        if (c.odd) mb[c.lm - 1] |= 1; else mb[c.lm - 1] &= 0xfe;
        bn_from_bytes(&b, bb, c.lb); bn_from_bytes(&e, eb, c.le); bn_from_bytes(&m, mb, c.lm);
        if (bn_cmp(&m, &b) == 0 && 0) { }
        if (m.n == 0 || (m.n == 1 && m.d[0] < 3)) bn_set_u32(&m, c.odd ? 3 : 4);
        CHECK(bn_modexp(&r, &b, &e, &m) == 0);
        CHECK(digest_is(&r, BN_EXP_EXP[i]));
        bn_free(&b); bn_free(&e); bn_free(&m); bn_free(&r);
    }
}

static void test_misc(void)
{
    bn a, b, r;
    u8 buf[8];
    static const u8 one[1] = { 1 };
    bn_init(&a); bn_init(&b); bn_init(&r);
    CHECK(bn_is_zero(&a) && bn_bits(&a) == 0);
    bn_from_bytes(&a, (const u8 *)"\0\0\0\0\0", 5);
    CHECK(bn_is_zero(&a) && a.n == 0);                            /* leading zeros are dropped */
    bn_from_bytes(&a, (const u8 *)"\x01\x00\x00\x00\x00", 5);
    CHECK(bn_bits(&a) == 33 && bn_bit(&a, 32) && !bn_bit(&a, 31) && !bn_is_odd(&a));
    CHECK(bn_to_bytes(&a, buf, 8) == 0 && buf[0] == 0 && buf[2] == 0 && buf[3] == 1);   /* left padded */
    CHECK(bn_to_bytes(&a, buf, 4) == -1);                         /* does not fit */
    CHECK(bn_divmod(&r, NULL, &a, &b) == -1);                     /* division by zero refused */
    bn_from_bytes(&b, one, 1);
    bn_sub(&r, &a, &b);                                           /* 2^32 - 1 */
    CHECK(r.n == 1 && r.d[0] == 0xffffffffUL);
    CHECK(bn_sub(&r, &b, &a) == -1);                              /* a > b: refused, not wrapped */
    bn_set_u32(&r, 0);
    CHECK(bn_modexp(&r, &a, &b, &b) == 0 && bn_is_zero(&r));      /* anything mod 1 is 0 */
    bn_from_bytes(&a, (const u8 *)"\x05", 1);
    bn_set_u32(&b, 0);
    { bn m; bn_init(&m); bn_set_u32(&m, 13); bn_modexp(&r, &a, &b, &m); CHECK(r.n == 1 && r.d[0] == 1); bn_free(&m); }   /* x^0 = 1 */
    bn_free(&a); bn_free(&b); bn_free(&r);
}

int main(void)
{
    test_arith();
    test_modexp();
    test_misc();
    TEST_DONE("bignum");
}
