#include <stdlib.h>
#include <string.h>
#include "rsa.h"
#include "sha1.h"
#include "sha2.h"

#define MIN_RSA_BITS 1024
#define MAX_RSA_BITS 16384

/* DER DigestInfo prefixes (RFC 8017 section 9.2 note 1) */
static const u8 DI_SHA1[]   = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
static const u8 DI_SHA256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
static const u8 DI_SHA512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

void rsa_pub_init(rsa_pub *k) { bn_init(&k->n); bn_init(&k->e); }
void rsa_pub_free(rsa_pub *k) { bn_free(&k->n); bn_free(&k->e); }
void rsa_priv_init(rsa_priv *k)
{
    bn_init(&k->n); bn_init(&k->e); bn_init(&k->d); bn_init(&k->p); bn_init(&k->q);
    bn_init(&k->iqmp); bn_init(&k->dp); bn_init(&k->dq);
}
void rsa_priv_free(rsa_priv *k)
{
    bn_free(&k->n); bn_free(&k->e); bn_free(&k->d); bn_free(&k->p); bn_free(&k->q);
    bn_free(&k->iqmp); bn_free(&k->dp); bn_free(&k->dq);
}

int rsa_size_bytes(const bn *n) { return (bn_bits(n) + 7) / 8; }

/* EM = 00 01 FF..FF 00 DigestInfo || H, exactly k bytes. */
static int emsa_pkcs1(int hash, const u8 *msg, size_t len, u8 *em, size_t k)
{
    u8 h[64];
    const u8 *di;
    size_t dilen, hlen, tlen;
    switch (hash) {
    case RSA_SHA1:   { sha1_ctx c; sha1_init(&c); sha1_update(&c, msg, len); sha1_final(&c, h); di = DI_SHA1; dilen = sizeof(DI_SHA1); hlen = 20; break; }
    case RSA_SHA256: sha256(msg, len, h); di = DI_SHA256; dilen = sizeof(DI_SHA256); hlen = 32; break;
    case RSA_SHA512: sha512(msg, len, h); di = DI_SHA512; dilen = sizeof(DI_SHA512); hlen = 64; break;
    default: return -1;
    }
    tlen = dilen + hlen;
    if (k < tlen + 11) return -1;
    em[0] = 0x00; em[1] = 0x01;
    memset(em + 2, 0xff, k - tlen - 3);
    em[k - tlen - 1] = 0x00;
    memcpy(em + k - tlen, di, dilen);
    memcpy(em + k - hlen, h, hlen);
    return 0;
}

static int key_size_ok(const bn *n)
{
    int bits = bn_bits(n);
    return bits >= MIN_RSA_BITS && bits <= MAX_RSA_BITS && bn_is_odd(n);
}

int rsa_verify(const rsa_pub *key, int hash, const u8 *msg, size_t len, const u8 *sig, size_t siglen)
{
    size_t k;
    u8 *em = NULL, *want = NULL;
    bn s, m;
    int rc = -1;

    if (!key_size_ok(&key->n) || bn_is_zero(&key->e) || !bn_is_odd(&key->e)) return -1;
    k = (size_t)rsa_size_bytes(&key->n);
    if (siglen != k) return -1;
    bn_init(&s); bn_init(&m);
    em = (u8 *)malloc(k); want = (u8 *)malloc(k);
    if (!em || !want) goto out;
    if (bn_from_bytes(&s, sig, siglen) < 0 || bn_cmp(&s, &key->n) >= 0) goto out;
    if (bn_modexp(&m, &s, &key->e, &key->n) < 0 || bn_to_bytes(&m, em, k) < 0) goto out;
    if (emsa_pkcs1(hash, msg, len, want, k) < 0) goto out;
    rc = ssh_ct_memcmp(em, want, k) == 0 ? 0 : -1;
out:
    bn_free(&s); bn_free(&m);
    free(em); free(want);
    return rc;
}

int rsa_priv_prepare(rsa_priv *k)
{
    bn t, one, pm1, qm1;
    int rc = -1;
    bn_init(&t); bn_init(&one); bn_init(&pm1); bn_init(&qm1);
    if (!key_size_ok(&k->n) || bn_is_zero(&k->p) || bn_is_zero(&k->q) || bn_is_zero(&k->d)) goto out;
    if (bn_mul(&t, &k->p, &k->q) < 0 || bn_cmp(&t, &k->n) != 0) goto out;        /* n must equal p*q */
    if (bn_set_u32(&one, 1) < 0 || bn_sub(&pm1, &k->p, &one) < 0 || bn_sub(&qm1, &k->q, &one) < 0) goto out;
    if (bn_mod(&k->dp, &k->d, &pm1) < 0 || bn_mod(&k->dq, &k->d, &qm1) < 0) goto out;
    rc = 0;
out:
    bn_free(&t); bn_free(&one); bn_free(&pm1); bn_free(&qm1);
    return rc;
}

int rsa_sign(const rsa_priv *key, int hash, const u8 *msg, size_t len, u8 *sig)
{
    size_t k;
    u8 *em = NULL;
    bn m, m1, m2, h, t, s, check;
    int rc = -1;

    if (!key_size_ok(&key->n)) return -1;
    k = (size_t)rsa_size_bytes(&key->n);
    bn_init(&m); bn_init(&m1); bn_init(&m2); bn_init(&h); bn_init(&t); bn_init(&s); bn_init(&check);
    em = (u8 *)malloc(k);
    if (!em || emsa_pkcs1(hash, msg, len, em, k) < 0) goto out;
    if (bn_from_bytes(&m, em, k) < 0) goto out;
    /* CRT: s = m2 + q * (iqmp * (m1 - m2) mod p) */
    if (bn_mod(&t, &m, &key->p) < 0 || bn_modexp(&m1, &t, &key->dp, &key->p) < 0) goto out;
    if (bn_mod(&t, &m, &key->q) < 0 || bn_modexp(&m2, &t, &key->dq, &key->q) < 0) goto out;
    if (bn_mod(&t, &m2, &key->p) < 0 || bn_submod(&h, &m1, &t, &key->p) < 0) goto out;
    if (bn_mulmod(&h, &h, &key->iqmp, &key->p) < 0) goto out;
    if (bn_mul(&t, &h, &key->q) < 0 || bn_add(&s, &t, &m2) < 0) goto out;
    /* a fault in the CRT computation would leak the factors: check s^e == m before releasing it */
    if (bn_modexp(&check, &s, &key->e, &key->n) < 0 || bn_cmp(&check, &m) != 0) goto out;
    if (bn_to_bytes(&s, sig, k) < 0) goto out;
    rc = 0;
out:
    bn_free(&m); bn_free(&m1); bn_free(&m2); bn_free(&h); bn_free(&t); bn_free(&s); bn_free(&check);
    if (em) { ssh_wipe(em, k); free(em); }
    return rc;
}
