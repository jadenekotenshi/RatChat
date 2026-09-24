#include <stdlib.h>
#include <string.h>
#include "../core/rsa.h"
#include "test.h"
#include "rsa_vectors.h"

typedef struct { const unsigned char *n, *e, *d, *p, *q, *iqmp; size_t nl, el, dl, pl, ql, il;
                 const unsigned char *sig[3]; size_t sl; } key_vec;

#define KV(i) { RSA##i##_N, RSA##i##_E, RSA##i##_D, RSA##i##_P, RSA##i##_Q, RSA##i##_IQMP, \
    sizeof(RSA##i##_N), sizeof(RSA##i##_E), sizeof(RSA##i##_D), sizeof(RSA##i##_P), sizeof(RSA##i##_Q), sizeof(RSA##i##_IQMP), \
    { RSA##i##_SIG_SHA1, RSA##i##_SIG_SHA256, RSA##i##_SIG_SHA512 }, sizeof(RSA##i##_SIG_SHA1) }

int main(void)
{
    static const key_vec keys[3] = { KV(0), KV(1), KV(2) };
    static const int hashes[3] = { RSA_SHA1, RSA_SHA256, RSA_SHA512 };
    int ki, hi;

    for (ki = 0; ki < 3; ki++) {
        const key_vec *kv = &keys[ki];
        rsa_pub pub; rsa_priv priv;
        unsigned char sig[512];
        unsigned char bad[512];
        rsa_pub_init(&pub); rsa_priv_init(&priv);
        bn_from_bytes(&pub.n, kv->n, kv->nl); bn_from_bytes(&pub.e, kv->e, kv->el);
        bn_from_bytes(&priv.n, kv->n, kv->nl); bn_from_bytes(&priv.e, kv->e, kv->el);
        bn_from_bytes(&priv.d, kv->d, kv->dl); bn_from_bytes(&priv.p, kv->p, kv->pl);
        bn_from_bytes(&priv.q, kv->q, kv->ql); bn_from_bytes(&priv.iqmp, kv->iqmp, kv->il);
        CHECK(rsa_priv_prepare(&priv) == 0);
        CHECK(rsa_size_bytes(&pub.n) == (int)kv->sl);

        for (hi = 0; hi < 3; hi++) {
            /* OpenSSL's signature is accepted */
            CHECK(rsa_verify(&pub, hashes[hi], RSA_MSG, sizeof(RSA_MSG) - 1, kv->sig[hi], kv->sl) == 0);
            /* ours is byte-for-byte the same (PKCS#1 v1.5 is deterministic) */
            CHECK(rsa_sign(&priv, hashes[hi], RSA_MSG, sizeof(RSA_MSG) - 1, sig) == 0);
            CHECK_MEM(sig, kv->sig[hi], kv->sl, "rsa signature equals OpenSSL's");
            /* tampering is rejected */
            memcpy(bad, kv->sig[hi], kv->sl); bad[kv->sl / 2] ^= 1;
            CHECK(rsa_verify(&pub, hashes[hi], RSA_MSG, sizeof(RSA_MSG) - 1, bad, kv->sl) == -1);
            CHECK(rsa_verify(&pub, hashes[hi], RSA_MSG, sizeof(RSA_MSG) - 2, kv->sig[hi], kv->sl) == -1);      /* other message */
            CHECK(rsa_verify(&pub, hashes[(hi + 1) % 3], RSA_MSG, sizeof(RSA_MSG) - 1, kv->sig[hi], kv->sl) == -1);   /* other hash */
        }
        /* structural rejections */
        CHECK(rsa_verify(&pub, RSA_SHA256, RSA_MSG, sizeof(RSA_MSG) - 1, kv->sig[1], kv->sl - 1) == -1);   /* short */
        memset(bad, 0, sizeof(bad));
        CHECK(rsa_verify(&pub, RSA_SHA256, RSA_MSG, sizeof(RSA_MSG) - 1, bad, kv->sl) == -1);            /* zero signature */
        memset(bad, 0xff, kv->sl);
        CHECK(rsa_verify(&pub, RSA_SHA256, RSA_MSG, sizeof(RSA_MSG) - 1, bad, kv->sl) == -1);            /* >= n */
        CHECK(rsa_verify(&pub, 99, RSA_MSG, 4, kv->sig[1], kv->sl) == -1);                               /* unknown hash */
        /* a wrong CRT parameter must be caught by the verify-after-sign check, never released */
        priv.iqmp.d[0] ^= 2;
        CHECK(rsa_sign(&priv, RSA_SHA256, RSA_MSG, sizeof(RSA_MSG) - 1, sig) == -1);
        priv.iqmp.d[0] ^= 2;
        /* p*q != n is refused at load time */
        priv.p.d[0] ^= 4;
        CHECK(rsa_priv_prepare(&priv) == -1);
        priv.p.d[0] ^= 4;
        rsa_pub_free(&pub); rsa_priv_free(&priv);
    }
    /* keys that are too small are refused */
    {
        rsa_pub tiny; unsigned char s[8] = {0};
        rsa_pub_init(&tiny);
        bn_set_u32(&tiny.n, 0xfffffffbUL); bn_set_u32(&tiny.e, 65537);
        CHECK(rsa_verify(&tiny, RSA_SHA256, (const unsigned char *)"x", 1, s, 4) == -1);
        rsa_pub_free(&tiny);
    }
    TEST_DONE("rsa");
}
