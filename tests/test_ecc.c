#include <stdlib.h>
#include <string.h>
#include "../core/ecc.h"
#include "../core/rng.h"
#include "test.h"
#include "ec_vectors.h"

static const unsigned char *K_[3], *KG_[3], *K2_[3], *K2KG_[3], *D_[3], *Q_[3], *SR_[3], *SS_[3], *Q2_[3], *SHARED_[3];

static void setup(void)
{
    K_[0] = K0; K_[1] = K1; K_[2] = K2;
    KG_[0] = KG0; KG_[1] = KG1; KG_[2] = KG2;
    K2_[0] = K20; K2_[1] = K21; K2_[2] = K22;
    K2KG_[0] = K2KG0; K2KG_[1] = K2KG1; K2KG_[2] = K2KG2;
    D_[0] = D0; D_[1] = D1; D_[2] = D2;
    Q_[0] = Q0; Q_[1] = Q1; Q_[2] = Q2;
    SR_[0] = SR0; SR_[1] = SR1; SR_[2] = SR2;
    SS_[0] = SS0; SS_[1] = SS1; SS_[2] = SS2;
    Q2_[0] = Q2_0; Q2_[1] = Q2_1; Q2_[2] = Q2_2;
    SHARED_[0] = SHARED0; SHARED_[1] = SHARED1; SHARED_[2] = SHARED2;
}

static int point_is(const ec_curve *c, const ec_point *p, const unsigned char *enc)
{
    unsigned char out[133];
    return !p->inf && ec_encode_point(c, p, out) == 0 && memcmp(out, enc, (size_t)(1 + 2 * c->nbytes)) == 0;
}

static void test_curve(int id)
{
    const ec_curve *c = ec_curve_get(id);
    bn k, k2, d, r, s, r2;
    ec_point P, Q, R, Q2;
    unsigned char h[64], shared[66], enc[133];
    size_t hl;
    int i;

    CHECK(c != NULL && c->nbytes == (id == 0 ? 32 : id == 1 ? 48 : 66));
    bn_init(&k); bn_init(&k2); bn_init(&d); bn_init(&r); bn_init(&s); bn_init(&r2);
    ec_point_init(&P); ec_point_init(&Q); ec_point_init(&R); ec_point_init(&Q2);
    CHECK(ec_on_curve(c, &c->gx, &c->gy));

    /* scalar multiplication vs Python */
    bn_from_bytes(&k, K_[id], (size_t)c->nbytes);
    CHECK(ec_mul_base(c, &P, &k) == 0 && point_is(c, &P, KG_[id]));
    bn_from_bytes(&k2, K2_[id], (size_t)c->nbytes);
    CHECK(ec_mul(c, &R, &k2, &P) == 0 && point_is(c, &R, K2KG_[id]));            /* k2*(k*G) */
    { bn nn; ec_point inf; bn_init(&nn); ec_point_init(&inf); bn_copy(&nn, &c->n);
      CHECK(ec_mul_base(c, &inf, &nn) == 0 && inf.inf);                           /* n*G = infinity */
      bn_free(&nn); ec_point_free(&inf); }

    /* encoding and validation */
    CHECK(ec_encode_point(c, &P, enc) == 0 && ec_decode_point(c, enc, (size_t)(1 + 2 * c->nbytes), &Q) == 0 && bn_cmp(&Q.x, &P.x) == 0);
    enc[1 + c->nbytes + 3] ^= 1;
    CHECK(ec_decode_point(c, enc, (size_t)(1 + 2 * c->nbytes), &R) == -1);          /* off the curve */
    enc[1 + c->nbytes + 3] ^= 1;
    CHECK(ec_decode_point(c, enc, (size_t)(2 * c->nbytes), &R) == -1);              /* wrong length */
    enc[0] = 2;
    CHECK(ec_decode_point(c, enc, (size_t)(1 + 2 * c->nbytes), &R) == -1);          /* compressed form refused */

    /* OpenSSL's signature verifies with OpenSSL's public key; any tampering fails */
    ec_hash(c, EC_MSG, sizeof(EC_MSG) - 1, h, &hl);
    CHECK(ec_decode_point(c, Q_[id], (size_t)(1 + 2 * c->nbytes), &Q) == 0);
    bn_from_bytes(&r, SR_[id], (size_t)c->nbytes); bn_from_bytes(&s, SS_[id], (size_t)c->nbytes);
    CHECK(ecdsa_verify(c, &Q, h, hl, &r, &s) == 0);
    h[0] ^= 1;
    CHECK(ecdsa_verify(c, &Q, h, hl, &r, &s) == -1);
    h[0] ^= 1;
    bn_copy(&r2, &r); r2.d[0] ^= 1;
    CHECK(ecdsa_verify(c, &Q, h, hl, &r2, &s) == -1);
    bn_copy(&r2, &s); r2.d[0] ^= 1;
    CHECK(ecdsa_verify(c, &Q, h, hl, &r, &r2) == -1);
    bn_set_u32(&r2, 0);
    CHECK(ecdsa_verify(c, &Q, h, hl, &r2, &s) == -1 && ecdsa_verify(c, &Q, h, hl, &r, &r2) == -1);
    CHECK(ecdsa_verify(c, &Q, h, hl, &c->n, &s) == -1);                          /* r >= n */

    /* our own signatures verify (with the key OpenSSL made), and differ from one another */
    bn_from_bytes(&d, D_[id], (size_t)c->nbytes);
    CHECK(ecdsa_sign(c, &d, h, hl, &r, &s) == 0 && ecdsa_verify(c, &Q, h, hl, &r, &s) == 0);
    CHECK(ecdsa_sign(c, &d, h, hl, &r2, &s) == 0 && bn_cmp(&r, &r2) != 0);
    ec_hash(c, (const unsigned char *)"another message", 15, h, &hl);
    CHECK(ecdsa_sign(c, &d, h, hl, &r, &s) == 0 && ecdsa_verify(c, &Q, h, hl, &r, &s) == 0);
    CHECK(ecdsa_verify(c, &Q, EC_MSG, 20, &r, &s) == -1);                        /* wrong digest */

    /* ECDH matches OpenSSL's, and is symmetric */
    CHECK(ec_decode_point(c, Q2_[id], (size_t)(1 + 2 * c->nbytes), &Q2) == 0);
    CHECK(ecdh_shared(c, &d, &Q2, shared) == 0 && memcmp(shared, SHARED_[id], (size_t)c->nbytes) == 0);
    { ec_point Qmine; unsigned char my_pub[133]; ec_point_init(&Qmine);
      ec_mul_base(c, &Qmine, &d); ec_encode_point(c, &Qmine, my_pub); CHECK(memcmp(my_pub, Q_[id], (size_t)(1 + 2 * c->nbytes)) == 0);
      ec_point_free(&Qmine); }
    { ec_point bad; ec_point_init(&bad); bn_set_u32(&bad.x, 1); bn_set_u32(&bad.y, 1); bad.inf = 0;
      CHECK(ecdh_shared(c, &d, &bad, shared) == -1);                              /* invalid peer point refused */
      ec_point_free(&bad); }

    /* random scalars are in [1, n-1] and distinct */
    for (i = 0; i < 4; i++) {
        bn a, b;
        bn_init(&a); bn_init(&b);
        CHECK(ec_random_scalar(c, &a) == 0 && !bn_is_zero(&a) && bn_cmp(&a, &c->n) < 0);
        ec_random_scalar(c, &b);
        CHECK(bn_cmp(&a, &b) != 0);
        bn_free(&a); bn_free(&b);
    }
    bn_free(&k); bn_free(&k2); bn_free(&d); bn_free(&r); bn_free(&s); bn_free(&r2);
    ec_point_free(&P); ec_point_free(&Q); ec_point_free(&R); ec_point_free(&Q2);
}

int main(void)
{
    setup();
    ssh_rng_add("ecc-test", 8, 256);
    CHECK(ec_curve_by_name("nistp256", 8) == EC_P256 && ec_curve_by_name("nistp384", 8) == EC_P384 &&
          ec_curve_by_name("nistp521", 8) == EC_P521 && ec_curve_by_name("nistp224", 8) == -1 && ec_curve_by_name("x", 1) == -1);
    test_curve(EC_P256);
    test_curve(EC_P384);
    test_curve(EC_P521);
    TEST_DONE("ecc");
}
