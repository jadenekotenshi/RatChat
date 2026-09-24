/*
 * bignum.h -- unsigned arbitrary-precision integers for RSA, ECDSA and Diffie-Hellman.
 *
 * 32-bit limbs, little-endian, heap allocated.  Deliberately small and plain: schoolbook
 * multiplication, Knuth division, Montgomery modular exponentiation.  NOT constant-time:
 * callers that handle secrets (RSA private exponents, EC scalars) accept that risk on this
 * kind of machine; see the README.
 * Every function returning int gives 0 on success and -1 on allocation failure or bad input.
 */
#ifndef SSH_BIGNUM_H
#define SSH_BIGNUM_H

#include "ssh_types.h"

typedef struct { u32 *d; int n, cap; } bn;      /* n = limbs in use (no leading zero limbs) */

void bn_init(bn *a);
void bn_free(bn *a);                            /* wipes, then frees */
int  bn_set_u32(bn *a, u32 v);
int  bn_copy(bn *r, const bn *a);
int  bn_from_bytes(bn *a, const u8 *be, size_t len);          /* big-endian magnitude */
int  bn_to_bytes(const bn *a, u8 *out, size_t len);           /* big-endian, left-padded; -1 if it does not fit */
int  bn_bits(const bn *a);                                    /* 0 for zero */
int  bn_bit(const bn *a, int i);
int  bn_is_zero(const bn *a);
int  bn_is_odd(const bn *a);
int  bn_cmp(const bn *a, const bn *b);                        /* -1, 0, 1 */

int  bn_add(bn *r, const bn *a, const bn *b);                 /* r may alias a or b */
int  bn_sub(bn *r, const bn *a, const bn *b);                 /* requires a >= b; r may alias */
int  bn_mul(bn *r, const bn *a, const bn *b);                 /* r may alias */
int  bn_divmod(bn *q, bn *r, const bn *a, const bn *b);       /* q or r may be NULL; b != 0 */
int  bn_mod(bn *r, const bn *a, const bn *m);
int  bn_addmod(bn *r, const bn *a, const bn *b, const bn *m); /* a, b < m */
int  bn_submod(bn *r, const bn *a, const bn *b, const bn *m); /* a, b < m */
int  bn_mulmod(bn *r, const bn *a, const bn *b, const bn *m);
int  bn_modexp(bn *r, const bn *base, const bn *exp, const bn *mod);   /* Montgomery when mod is odd */
int  bn_modinv_prime(bn *r, const bn *a, const bn *p);        /* a^(p-2) mod p, p prime */
int  bn_shl(bn *r, const bn *a, int bits);
int  bn_shr(bn *r, const bn *a, int bits);

#endif
