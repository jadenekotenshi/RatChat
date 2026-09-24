/*
 * rsa.h -- RSA PKCS#1 v1.5 signatures (RFC 8017 RSASSA-PKCS1-v1_5) for SSH:
 * ssh-rsa (SHA-1, legacy), rsa-sha2-256 and rsa-sha2-512.
 * Verification is strict (exact padded encoding), signing uses the CRT with a
 * verify-after-sign check to catch faults.  Not constant-time / not blinded.
 */
#ifndef SSH_RSA_H
#define SSH_RSA_H

#include "bignum.h"

enum { RSA_SHA1 = 1, RSA_SHA256 = 2, RSA_SHA512 = 3 };

typedef struct { bn n, e; } rsa_pub;
typedef struct { bn n, e, d, p, q, iqmp, dp, dq; } rsa_priv;

void rsa_pub_init(rsa_pub *k);
void rsa_pub_free(rsa_pub *k);
void rsa_priv_init(rsa_priv *k);
void rsa_priv_free(rsa_priv *k);
/* After filling n, e, d, p, q, iqmp: derive dp/dq and sanity-check the key.  0 ok, -1 bad. */
int  rsa_priv_prepare(rsa_priv *k);
int  rsa_size_bytes(const bn *n);

/* 0 if `sig` is a valid signature of msg, -1 otherwise. */
int  rsa_verify(const rsa_pub *k, int hash, const u8 *msg, size_t len, const u8 *sig, size_t siglen);
/* sig receives rsa_size_bytes(n) bytes.  0 ok, -1 on failure. */
int  rsa_sign(const rsa_priv *k, int hash, const u8 *msg, size_t len, u8 *sig);

#endif
