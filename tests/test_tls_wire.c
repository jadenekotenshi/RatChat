#include <stdlib.h>
#include <string.h>
#include "../core/ssh_types.h"
#include "../core/wire.h"
#include "../core/tls_wire.h"
#include "test.h"

static void test_known_encodings(void)
{
    sbuf b;
    sb_init(&b);
    CHECK(tls_put_u16(&b, 0x02bc) == 0);            /* 700 */
    CHECK(b.len == 2 && b.p[0] == 0x02 && b.p[1] == 0xbc);
    sb_clear(&b);
    CHECK(tls_put_u24(&b, 0x011170) == 0);           /* 70000 */
    CHECK(b.len == 3 && b.p[0] == 0x01 && b.p[1] == 0x11 && b.p[2] == 0x70);
    sb_clear(&b);
    CHECK(tls_put_u16(&b, 0) == 0 && b.len == 2 && b.p[0] == 0 && b.p[1] == 0);
    sb_free(&b);
}

static void test_roundtrip(void)
{
    sbuf b;
    sreader r;
    static const u8 v8[3] = { 0xaa, 0xbb, 0xcc };
    static const u8 v16[5] = { 1, 2, 3, 4, 5 };
    u8 v24[300];
    const u8 *out;
    size_t len, i;

    for (i = 0; i < sizeof(v24); i++) v24[i] = (u8)(i * 3 + 1);

    sb_init(&b);
    CHECK(tls_put_u16(&b, 0x1234) == 0);
    CHECK(tls_put_u24(&b, 0x567890) == 0);
    CHECK(tls_put_vec8(&b, v8, sizeof(v8)) == 0);
    CHECK(tls_put_vec16(&b, v16, sizeof(v16)) == 0);
    CHECK(tls_put_vec24(&b, v24, sizeof(v24)) == 0);
    CHECK(tls_put_vec8(&b, NULL, 0) == 0);           /* empty vector: no body bytes, just 0x00 */

    sr_init(&r, b.p, b.len);
    CHECK(tls_get_u16(&r) == 0x1234);
    CHECK(tls_get_u24(&r) == 0x567890);
    out = tls_get_vec8(&r, &len);
    CHECK(out != NULL && len == sizeof(v8) && memcmp(out, v8, sizeof(v8)) == 0);
    out = tls_get_vec16(&r, &len);
    CHECK(out != NULL && len == sizeof(v16) && memcmp(out, v16, sizeof(v16)) == 0);
    out = tls_get_vec24(&r, &len);
    CHECK(out != NULL && len == sizeof(v24) && memcmp(out, v24, sizeof(v24)) == 0);
    out = tls_get_vec8(&r, &len);
    CHECK(out != NULL && len == 0);
    CHECK(sr_left(&r) == 0);

    sb_free(&b);
}

static void test_length_limits(void)
{
    sbuf b;
    u8 maxvec[0xff];
    memset(maxvec, 0x42, sizeof(maxvec));

    sb_init(&b);
    CHECK(tls_put_vec8(&b, NULL, 0x100) == -1);       /* one byte over what an 8-bit prefix holds */
    CHECK(b.len == 0);                                /* refused before touching d or writing anything */
    CHECK(tls_put_vec16(&b, NULL, 0x10000) == -1);
    CHECK(b.len == 0);
    CHECK(tls_put_vec24(&b, NULL, 0x1000000) == -1);
    CHECK(b.len == 0);
    CHECK(tls_put_vec8(&b, maxvec, sizeof(maxvec)) == 0 && b.len == 1 + sizeof(maxvec));   /* exactly the max: fine */
    sb_free(&b);
}

/* A length prefix that claims more than the buffer actually has must fail cleanly, and once a
 * reader has failed it must keep failing (sreader's sticky-error rule) rather than resync. */
static void test_truncated_reads(void)
{
    sreader r;
    static const u8 buf[2] = { 0x00, 0x05 };          /* claims a 5-byte vec16, has 0 more bytes */
    const u8 *out;
    size_t len;

    sr_init(&r, buf, sizeof(buf));
    out = tls_get_vec16(&r, &len);
    CHECK(out == NULL && len == 0);
    CHECK(sr_left(&r) == 0);
    out = tls_get_vec8(&r, &len);                     /* still fails, even though this one alone would fit */
    CHECK(out == NULL && len == 0);

    {
        static const u8 short_u24[2] = { 0x01, 0x02 };  /* only 2 bytes for a 3-byte int */
        sr_init(&r, short_u24, sizeof(short_u24));
        CHECK(tls_get_u24(&r) == 0);
        CHECK(sr_left(&r) == 0);
    }
}

int main(void)
{
    test_known_encodings();
    test_roundtrip();
    test_length_limits();
    test_truncated_reads();
    TEST_DONE("tls_wire");
}
