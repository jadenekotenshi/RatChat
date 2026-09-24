/*
 * ecc.h -- NIST P-256 / P-384 / P-521: point arithmetic, ECDSA and ECDH.
 * Built on bignum.h.  Scalar multiplication is plain double-and-add (not constant-time).
 * ECDSA nonces are hedged: derived from fresh randomness AND the private key AND the message
 * hash, so a weak RNG alone cannot leak the key.
 */
#ifndef SSH_ECC_H
#define SSH_ECC_H

#include "bignum.h"

enum { EC_P256 = 0, EC_P384 = 1, EC_P521 = 2, EC_NCURVES = 3 };

typedef struct {
    int    id;
    const char *ssh_name;              /* "nistp256" -- the curve identifier used in SSH */
    int    nbytes;                     /* field element size in bytes: 32 / 48 / 66 */
    int    nbits;                      /* bit length of the group order n */
    bn     p, a, b, gx, gy, n;
} ec_curve;

typedef struct { bn x, y; int inf; } ec_point;

const ec_curve *ec_curve_get(int id);                          /* NULL on out-of-memory */
int  ec_curve_by_name(const char *ssh_name, size_t len);       /* id, or -1 */
/* Digest matching the curve: SHA-256 / SHA-384 / SHA-512.  out must hold 64 bytes. */
void ec_hash(const ec_curve *c, const u8 *msg, size_t len, u8 *out, size_t *outlen);

void ec_point_init(ec_point *p);
void ec_point_free(ec_point *p);
int  ec_on_curve(const ec_curve *c, const bn *x, const bn *y);
int  ec_mul(const ec_curve *c, ec_point *out, const bn *k, const ec_point *P);       /* out = k*P */
int  ec_mul_base(const ec_curve *c, ec_point *out, const bn *k);
/* Uncompressed encoding 04 || X || Y (1 + 2*nbytes bytes). */
int  ec_encode_point(const ec_curve *c, const ec_point *p, u8 *out);
int  ec_decode_point(const ec_curve *c, const u8 *q, size_t len, ec_point *out);     /* validates: 0 ok, -1 bad */
/* Random scalar in [1, n-1] from the entropy pool. */
int  ec_random_scalar(const ec_curve *c, bn *d);

int  ecdsa_sign(const ec_curve *c, const bn *d, const u8 *hash, size_t hlen, bn *r, bn *s);
int  ecdsa_verify(const ec_curve *c, const ec_point *Q, const u8 *hash, size_t hlen, const bn *r, const bn *s);
/* ECDH: x-coordinate of d*peer, nbytes long.  0 ok, -1 on invalid input. */
int  ecdh_shared(const ec_curve *c, const bn *d, const ec_point *peer, u8 *out);

#endif
