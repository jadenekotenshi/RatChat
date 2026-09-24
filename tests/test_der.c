#include <stdlib.h>
#include <string.h>
#include "../core/ssh_types.h"
#include "../core/bignum.h"
#include "../core/der.h"
#include "test.h"

static void test_read_expect(void)
{
    /* short-form length */
    {
        static const u8 buf[] = { 0x02, 0x01, 0x2a };
        const u8 *p = buf, *end = buf + sizeof(buf), *val;
        size_t len;
        int tag;
        CHECK(der_read(&p, end, &tag, &val, &len) == 0 && tag == 0x02 && len == 1 && val[0] == 0x2a);
        CHECK(p == end);
    }
    /* long-form length, two bytes */
    {
        u8 buf[4 + 300];
        const u8 *p, *end, *val;
        size_t len, i;
        int tag;
        buf[0] = 0x04; buf[1] = 0x82; buf[2] = 0x01; buf[3] = 0x2c;      /* length 0x012c = 300 */
        for (i = 0; i < 300; i++) buf[4 + i] = (u8)i;
        p = buf; end = buf + sizeof(buf);
        CHECK(der_read(&p, end, &tag, &val, &len) == 0 && tag == 0x04 && len == 300);
        CHECK(val[0] == 0 && val[299] == (u8)299 && p == end);
    }
    /* wrong tag is refused by der_expect but accepted by der_read */
    {
        static const u8 buf[] = { 0x02, 0x01, 0x05 };
        const u8 *p = buf, *end = buf + sizeof(buf), *val;
        size_t len;
        CHECK(der_expect(&p, end, 0x03, &val, &len) == -1);
        p = buf;
        CHECK(der_expect(&p, end, 0x02, &val, &len) == 0 && len == 1 && val[0] == 5);
    }
    /* truncated header, truncated value, and an over-claimed length must all fail cleanly */
    {
        static const u8 h[] = { 0x02 };                                  /* only the tag byte */
        static const u8 v[] = { 0x02, 0x05, 0x01, 0x02, 0x03 };          /* claims 5, has 3 */
        static const u8 o[] = { 0x02, 0x82, 0xff, 0xff, 0x01 };          /* claims 65535, has 1 */
        const u8 *p, *end, *val;
        size_t len;
        int tag;
        p = h; end = h + sizeof(h);
        CHECK(der_read(&p, end, &tag, &val, &len) == -1);
        p = v; end = v + sizeof(v);
        CHECK(der_read(&p, end, &tag, &val, &len) == -1);
        p = o; end = o + sizeof(o);
        CHECK(der_read(&p, end, &tag, &val, &len) == -1);
    }
    /* BER indefinite length (0x80 alone) is rejected outright, and so is a length whose
     * long-form byte count claims more than 4 bytes -- neither is "unsupported", both refuse */
    {
        static const u8 indef[] = { 0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00 };
        static const u8 huge[]  = { 0x30, 0x85, 0, 0, 0, 0, 1 };
        const u8 *p, *end, *val;
        size_t len;
        int tag;
        p = indef; end = indef + sizeof(indef);
        CHECK(der_read(&p, end, &tag, &val, &len) == -1);
        p = huge; end = huge + sizeof(huge);
        CHECK(der_read(&p, end, &tag, &val, &len) == -1);
    }
}

static void test_enter_nested(void)
{
    /* SEQUENCE { SEQUENCE { INTEGER 7 }, INTEGER 9 } -- 8 bytes of outer content: the inner
     * SEQUENCE is 5 bytes (2-byte header + 1-byte INTEGER), the trailing INTEGER is 3. */
    static const u8 buf[] = { 0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09 };
    const u8 *p = buf, *end = buf + sizeof(buf), *outer, *outer_end, *inner, *inner_end, *v;
    size_t l;
    CHECK(der_enter(&p, end, 0x30, &outer, &outer_end) == 0 && p == end);
    p = outer; end = outer_end;
    CHECK(der_enter(&p, end, 0x30, &inner, &inner_end) == 0);
    CHECK(der_int(&inner, inner_end, &v, &l) == 0 && l == 1 && v[0] == 7 && inner == inner_end);
    CHECK(der_int(&p, end, &v, &l) == 0 && l == 1 && v[0] == 9 && p == end);
    /* entering with the wrong expected tag is refused (der_expect's failure leaves *p wherever
     * der_read's own scan left it, same as ssh_key.c's original -- callers always just bail out) */
    p = buf; end = buf + sizeof(buf);
    CHECK(der_enter(&p, end, 0x31, &outer, &outer_end) == -1);
}

static void test_int(void)
{
    /* the sign-padding zero is dropped */
    {
        static const u8 buf[] = { 0x02, 0x02, 0x00, 0xff };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        CHECK(der_int(&p, end, &v, &l) == 0 && l == 1 && v[0] == 0xff);
    }
    /* a value that doesn't need padding is untouched */
    {
        static const u8 buf[] = { 0x02, 0x02, 0x01, 0x02 };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        CHECK(der_int(&p, end, &v, &l) == 0 && l == 2 && v[0] == 1 && v[1] == 2);
    }
    /* a zero-length INTEGER is refused */
    {
        static const u8 buf[] = { 0x02, 0x00 };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        CHECK(der_int(&p, end, &v, &l) == -1);
    }
    /* an all-zero value keeps exactly one byte, not zero */
    {
        static const u8 buf[] = { 0x02, 0x03, 0x00, 0x00, 0x00 };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        CHECK(der_int(&p, end, &v, &l) == 0 && l == 1 && v[0] == 0);
    }
}

static void test_bitstring(void)
{
    /* 0 unused bits: the common case for an SPKI-wrapped key */
    {
        static const u8 buf[] = { 0x03, 0x04, 0x00, 0xaa, 0xbb, 0xcc };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        int ub;
        CHECK(der_bitstring(&p, end, &v, &l, &ub) == 0 && ub == 0 && l == 3);
        CHECK(v[0] == 0xaa && v[1] == 0xbb && v[2] == 0xcc);
    }
    /* a nonzero-but-legal unused-bit count is passed through, not rejected */
    {
        static const u8 buf[] = { 0x03, 0x02, 0x06, 0xc0 };              /* 2 significant bits: "11" */
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        int ub;
        CHECK(der_bitstring(&p, end, &v, &l, &ub) == 0 && ub == 6 && l == 1 && v[0] == 0xc0);
    }
    /* an unused-bit count of 8 or more is not a valid BIT STRING */
    {
        static const u8 buf[] = { 0x03, 0x02, 0x08, 0x00 };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        int ub;
        CHECK(der_bitstring(&p, end, &v, &l, &ub) == -1);
    }
    /* a BIT STRING with no content at all (missing even the unused-bits byte) is refused */
    {
        static const u8 buf[] = { 0x03, 0x00 };
        const u8 *p = buf, *end = buf + sizeof(buf), *v;
        size_t l;
        int ub;
        CHECK(der_bitstring(&p, end, &v, &l, &ub) == -1);
    }
}

static void test_oid(void)
{
    static const u8 rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    static const u8 ec[]  = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    CHECK(der_oid_eq(rsa, sizeof(rsa), rsa, sizeof(rsa)));
    CHECK(!der_oid_eq(rsa, sizeof(rsa), ec, sizeof(ec)));
    CHECK(!der_oid_eq(rsa, sizeof(rsa) - 1, rsa, sizeof(rsa)));           /* same prefix, different length */
}

static void test_time(void)
{
    der_time t, t2;

    /* the Y2K 50/51 boundary: "50" is 1950, "49" is 2049 */
    CHECK(der_utctime((const u8 *)"500101000000Z", 13, &t) == 0 && t.year == 1950);
    CHECK(der_utctime((const u8 *)"491231235959Z", 13, &t) == 0 && t.year == 2049);
    CHECK(t.month == 12 && t.day == 31 && t.hour == 23 && t.min == 59 && t.sec == 59);
    CHECK(der_utctime((const u8 *)"000101000000Z", 13, &t) == 0 && t.year == 2000);

    /* wrong length, missing 'Z', and non-digit fields are all refused */
    CHECK(der_utctime((const u8 *)"5001010000Z", 11, &t) == -1);
    CHECK(der_utctime((const u8 *)"500101000000A", 13, &t) == -1);
    CHECK(der_utctime((const u8 *)"5001010A0000Z", 13, &t) == -1);

    /* out-of-range calendar fields are refused, not silently accepted */
    CHECK(der_utctime((const u8 *)"501301000000Z", 13, &t) == -1);        /* month 13 */
    CHECK(der_utctime((const u8 *)"500100000000Z", 13, &t) == -1);       /* day 00 */
    CHECK(der_utctime((const u8 *)"500101250000Z", 13, &t) == -1);       /* hour 25 */

    CHECK(der_generalizedtime((const u8 *)"20491231235959Z", 15, &t) == 0 &&
          t.year == 2049 && t.month == 12 && t.day == 31 && t.hour == 23 && t.min == 59 && t.sec == 59);
    CHECK(der_generalizedtime((const u8 *)"20491231235959", 14, &t) == -1);   /* missing 'Z' */

    CHECK(der_utctime((const u8 *)"500101000000Z", 13, &t) == 0);
    CHECK(der_utctime((const u8 *)"491231235959Z", 13, &t2) == 0);
    CHECK(der_time_cmp(&t, &t2) == -1 && der_time_cmp(&t2, &t) == 1 && der_time_cmp(&t, &t) == 0);
}

static void test_ecdsa_sig(void)
{
    /* SEQUENCE { INTEGER 0x0102, INTEGER 0x03 } -- 7 bytes of content: a 4-byte INTEGER
     * (2-byte header + 2-byte value) followed by a 3-byte one. */
    static const u8 buf[] = { 0x30, 0x07, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03 };
    bn r, s;
    bn_init(&r); bn_init(&s);
    CHECK(der_ecdsa_sig(buf, sizeof(buf), &r, &s) == 0);
    CHECK(r.n == 1 && r.d[0] == 0x0102);
    CHECK(s.n == 1 && s.d[0] == 0x03);
    bn_free(&r); bn_free(&s);

    /* trailing bytes inside the SEQUENCE, or after it, are both refused */
    {
        static const u8 trail_inner[] = { 0x30, 0x08, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x00 };
        static const u8 trail_outer[] = { 0x30, 0x07, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0xff };
        bn_init(&r); bn_init(&s);
        CHECK(der_ecdsa_sig(trail_inner, sizeof(trail_inner), &r, &s) == -1);
        bn_free(&r); bn_free(&s);
        bn_init(&r); bn_init(&s);
        CHECK(der_ecdsa_sig(trail_outer, sizeof(trail_outer), &r, &s) == -1);
        bn_free(&r); bn_free(&s);
    }
    /* not a SEQUENCE at all */
    {
        static const u8 notseq[] = { 0x02, 0x01, 0x01 };
        bn_init(&r); bn_init(&s);
        CHECK(der_ecdsa_sig(notseq, sizeof(notseq), &r, &s) == -1);
        bn_free(&r); bn_free(&s);
    }
}

int main(void)
{
    test_read_expect();
    test_enter_nested();
    test_int();
    test_bitstring();
    test_oid();
    test_time();
    test_ecdsa_sig();
    TEST_DONE("der");
}
