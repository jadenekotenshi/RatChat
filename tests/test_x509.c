#include <stdlib.h>
#include <string.h>
#include "../core/ssh_types.h"
#include "../core/bignum.h"
#include "../core/rsa.h"
#include "../core/ecc.h"
#include "../core/der.h"
#include "../core/x509.h"
#include "test.h"
#include "x509_vectors.h"

static void check_dates(const x509_cert *c)
{
    CHECK(c->not_before.year == EXP_NOT_BEFORE_Y && c->not_before.month == EXP_NOT_BEFORE_MO &&
          c->not_before.day == EXP_NOT_BEFORE_D && c->not_before.hour == EXP_HMS_H &&
          c->not_before.min == EXP_HMS_M && c->not_before.sec == EXP_HMS_S);
    CHECK(c->not_after.year == EXP_NOT_AFTER_Y && c->not_after.month == EXP_NOT_AFTER_MO &&
          c->not_after.day == EXP_NOT_AFTER_D && c->not_after.hour == EXP_HMS_H &&
          c->not_after.min == EXP_HMS_M && c->not_after.sec == EXP_HMS_S);
    CHECK(der_time_cmp(&c->not_before, &c->not_after) == -1);
}

static void test_rsa_cert(void)
{
    x509_cert c;
    const char *err;
    u8 nbuf[rsa_exp_modulus_LEN];

    x509_cert_init(&c);
    CHECK(x509_parse_leaf(rsa_der, rsa_der_LEN, &c, &err) == 0);
    CHECK(c.key_type == X509_KEY_RSA);
    CHECK(strcmp(c.cn, "test-rsa.ratchat.local") == 0);
    check_dates(&c);

    /* the modulus and exponent, cross-checked against openssl's own independent parse */
    CHECK(bn_to_bytes(&c.rsa.n, nbuf, sizeof(nbuf)) == 0);
    CHECK_MEM(nbuf, rsa_exp_modulus, rsa_exp_modulus_LEN, "rsa modulus");
    CHECK(c.rsa.e.n == 1 && c.rsa.e.d[0] == rsa_exp_exponent);

    CHECK(c.der == rsa_der && c.der_len == rsa_der_LEN);
    x509_cert_free(&c);
}

static void test_ec_cert(const u8 *der, size_t der_len, int expect_curve, size_t point_len,
                          const u8 *expect_point, const char *expect_cn)
{
    x509_cert c;
    const char *err;
    u8 pt[133];
    const ec_curve *curve;

    x509_cert_init(&c);
    CHECK(x509_parse_leaf(der, der_len, &c, &err) == 0);
    CHECK(c.key_type == X509_KEY_EC);
    CHECK(c.curve == expect_curve);
    CHECK(strcmp(c.cn, expect_cn) == 0);
    check_dates(&c);

    curve = ec_curve_get(c.curve);
    CHECK(curve != NULL && ec_encode_point(curve, &c.ec_pub, pt) == 0);
    CHECK_MEM(pt, expect_point, point_len, "ec public key point");

    x509_cert_free(&c);
}

/* Every prefix of a real certificate is either the whole thing (parses) or is missing bytes the
 * outermost SEQUENCE's own declared length requires -- so every truncation must be refused. */
static void test_truncation(const u8 *der, size_t der_len)
{
    size_t n;
    for (n = 0; n < der_len; n++) {
        x509_cert c;
        const char *err;
        x509_cert_init(&c);
        CHECK(x509_parse_leaf(der, n, &c, &err) == -1);
        x509_cert_free(&c);
    }
}

/* Flips every single byte of a real certificate, one at a time, and confirms the parser never
 * reads out of bounds or crashes -- whether that particular corruption happens to still parse
 * (most don't) is not the point; surviving the whole sweep is. */
static void test_corruption(const u8 *der, size_t der_len)
{
    u8 *buf = (u8 *)malloc(der_len);
    size_t i;
    CHECK(buf != NULL);
    if (!buf) return;
    memcpy(buf, der, der_len);
    for (i = 0; i < der_len; i++) {
        x509_cert c;
        const char *err;
        buf[i] ^= 0xff;
        x509_cert_init(&c);
        x509_parse_leaf(buf, der_len, &c, &err);
        x509_cert_free(&c);
        buf[i] ^= 0xff;
    }
    CHECK(1);                                  /* reaching here: der_len corruptions, zero crashes */
    free(buf);
}

static void test_not_a_certificate(void)
{
    x509_cert c;
    const char *err;
    static const u8 empty[1] = { 0 };
    static const u8 not_seq[] = { 0x02, 0x01, 0x01 };

    x509_cert_init(&c);
    CHECK(x509_parse_leaf(empty, 0, &c, &err) == -1);
    x509_cert_free(&c);

    x509_cert_init(&c);
    CHECK(x509_parse_leaf(not_seq, sizeof(not_seq), &c, &err) == -1);
    x509_cert_free(&c);
}

int main(void)
{
    test_rsa_cert();
    test_ec_cert(ec256_der, ec256_der_LEN, EC_P256, ec256_exp_point_LEN, ec256_exp_point,
                 "test-p256.ratchat.local");
    test_ec_cert(ec384_der, ec384_der_LEN, EC_P384, ec384_exp_point_LEN, ec384_exp_point,
                 "test-p384.ratchat.local");
    test_not_a_certificate();
    test_truncation(rsa_der, rsa_der_LEN);
    test_truncation(ec256_der, ec256_der_LEN);
    test_truncation(ec384_der, ec384_der_LEN);
    test_corruption(rsa_der, rsa_der_LEN);
    test_corruption(ec256_der, ec256_der_LEN);
    test_corruption(ec384_der, ec384_der_LEN);
    TEST_DONE("x509");
}
