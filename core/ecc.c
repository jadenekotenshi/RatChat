#include <stdlib.h>
#include <string.h>
#include "ecc.h"
#include "sha2.h"
#include "rng.h"
#include "ecc_tab.h"

/* ------------------------------------------------------------------ */
/* curves                                                              */
/* ------------------------------------------------------------------ */

static ec_curve curves[EC_NCURVES];
static int curve_ready[EC_NCURVES];

static int load(bn *b, const u8 *bytes, size_t n) { return bn_from_bytes(b, bytes, n); }

const ec_curve *ec_curve_get(int id)
{
    ec_curve *c;
    bn three;
    if (id < 0 || id >= EC_NCURVES) return NULL;
    c = &curves[id];
    if (curve_ready[id]) return c;
    memset(c, 0, sizeof(*c));
    c->id = id;
    switch (id) {
    case EC_P256:
        c->ssh_name = "nistp256"; c->nbytes = 32;
        if (load(&c->p, EC_P256_p, 32) || load(&c->b, EC_P256_b, 32) || load(&c->gx, EC_P256_gx, 32) ||
            load(&c->gy, EC_P256_gy, 32) || load(&c->n, EC_P256_n, 32)) return NULL;
        break;
    case EC_P384:
        c->ssh_name = "nistp384"; c->nbytes = 48;
        if (load(&c->p, EC_P384_p, 48) || load(&c->b, EC_P384_b, 48) || load(&c->gx, EC_P384_gx, 48) ||
            load(&c->gy, EC_P384_gy, 48) || load(&c->n, EC_P384_n, 48)) return NULL;
        break;
    default:
        c->ssh_name = "nistp521"; c->nbytes = 66;
        if (load(&c->p, EC_P521_p, 66) || load(&c->b, EC_P521_b, 66) || load(&c->gx, EC_P521_gx, 66) ||
            load(&c->gy, EC_P521_gy, 66) || load(&c->n, EC_P521_n, 66)) return NULL;
        break;
    }
    bn_init(&three);
    if (bn_set_u32(&three, 3) < 0 || bn_sub(&c->a, &c->p, &three) < 0) { bn_free(&three); return NULL; }   /* a = p - 3 */
    bn_free(&three);
    c->nbits = bn_bits(&c->n);
    curve_ready[id] = 1;
    return c;
}

int ec_curve_by_name(const char *name, size_t len)
{
    if (len == 8 && memcmp(name, "nistp256", 8) == 0) return EC_P256;
    if (len == 8 && memcmp(name, "nistp384", 8) == 0) return EC_P384;
    if (len == 8 && memcmp(name, "nistp521", 8) == 0) return EC_P521;
    return -1;
}

void ec_hash(const ec_curve *c, const u8 *msg, size_t len, u8 *out, size_t *outlen)
{
    if (c->id == EC_P256) { sha256(msg, len, out); *outlen = 32; }
    else if (c->id == EC_P384) { sha384(msg, len, out); *outlen = 48; }
    else { sha512(msg, len, out); *outlen = 64; }
}

void ec_point_init(ec_point *p) { bn_init(&p->x); bn_init(&p->y); p->inf = 1; }
void ec_point_free(ec_point *p) { bn_free(&p->x); bn_free(&p->y); p->inf = 1; }

/* ------------------------------------------------------------------ */
/* field helpers (mod p)                                               */
/* ------------------------------------------------------------------ */

#define CHK(e) do { if ((e) < 0) goto fail; } while (0)
#define FMUL(r, a, b) bn_mulmod((r), (a), (b), &c->p)
#define FADD(r, a, b) bn_addmod((r), (a), (b), &c->p)
#define FSUB(r, a, b) bn_submod((r), (a), (b), &c->p)

int ec_on_curve(const ec_curve *c, const bn *x, const bn *y)
{
    bn l, r, t;
    int ok = 0;
    if (bn_cmp(x, &c->p) >= 0 || bn_cmp(y, &c->p) >= 0) return 0;
    bn_init(&l); bn_init(&r); bn_init(&t);
    CHK(FMUL(&l, y, y));                                            /* y^2 */
    CHK(FMUL(&t, x, x)); CHK(FMUL(&r, &t, x));                      /* x^3 */
    CHK(FMUL(&t, &c->a, x)); CHK(FADD(&r, &r, &t));                 /* + a*x */
    CHK(FADD(&r, &r, &c->b));                                       /* + b */
    ok = bn_cmp(&l, &r) == 0;
fail:
    bn_free(&l); bn_free(&r); bn_free(&t);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Jacobian arithmetic, a = -3                                         */
/* ------------------------------------------------------------------ */

typedef struct { bn X, Y, Z; int inf; } jp;

static void jp_init(jp *p) { bn_init(&p->X); bn_init(&p->Y); bn_init(&p->Z); p->inf = 1; }
static void jp_free(jp *p) { bn_free(&p->X); bn_free(&p->Y); bn_free(&p->Z); }

static int jp_double(const ec_curve *c, jp *P)
{
    bn delta, gamma, beta, alpha, t1, t2, X3, Y3, Z3;
    int rc = -1;
    if (P->inf || bn_is_zero(&P->Y)) { P->inf = 1; return 0; }
    bn_init(&delta); bn_init(&gamma); bn_init(&beta); bn_init(&alpha); bn_init(&t1); bn_init(&t2);
    bn_init(&X3); bn_init(&Y3); bn_init(&Z3);
    CHK(FMUL(&delta, &P->Z, &P->Z));                                 /* delta = Z^2 */
    CHK(FMUL(&gamma, &P->Y, &P->Y));                                 /* gamma = Y^2 */
    CHK(FMUL(&beta, &P->X, &gamma));                                 /* beta = X*gamma */
    CHK(FSUB(&t1, &P->X, &delta)); CHK(FADD(&t2, &P->X, &delta));
    CHK(FMUL(&alpha, &t1, &t2));                                     /* alpha = 3*(X-delta)*(X+delta) */
    CHK(FADD(&t1, &alpha, &alpha)); CHK(FADD(&alpha, &t1, &alpha));
    CHK(FMUL(&t1, &alpha, &alpha));                                  /* X3 = alpha^2 - 8*beta */
    CHK(FADD(&t2, &beta, &beta)); CHK(FADD(&t2, &t2, &t2)); CHK(FADD(&t2, &t2, &t2));
    CHK(FSUB(&X3, &t1, &t2));
    CHK(FADD(&t1, &P->Y, &P->Z)); CHK(FMUL(&t1, &t1, &t1));          /* Z3 = (Y+Z)^2 - gamma - delta */
    CHK(FSUB(&t1, &t1, &gamma)); CHK(FSUB(&Z3, &t1, &delta));
    CHK(FADD(&t1, &beta, &beta)); CHK(FADD(&t1, &t1, &t1));          /* 4*beta */
    CHK(FSUB(&t1, &t1, &X3)); CHK(FMUL(&t1, &alpha, &t1));           /* alpha*(4*beta - X3) */
    CHK(FMUL(&t2, &gamma, &gamma));                                  /* 8*gamma^2 */
    CHK(FADD(&t2, &t2, &t2)); CHK(FADD(&t2, &t2, &t2)); CHK(FADD(&t2, &t2, &t2));
    CHK(FSUB(&Y3, &t1, &t2));
    CHK(bn_copy(&P->X, &X3)); CHK(bn_copy(&P->Y, &Y3)); CHK(bn_copy(&P->Z, &Z3));
    rc = 0;
fail:
    bn_free(&delta); bn_free(&gamma); bn_free(&beta); bn_free(&alpha); bn_free(&t1); bn_free(&t2);
    bn_free(&X3); bn_free(&Y3); bn_free(&Z3);
    return rc;
}

/* P (Jacobian) += Q (affine, not infinity) */
static int jp_madd(const ec_curve *c, jp *P, const bn *qx, const bn *qy)
{
    bn Z1Z1, U2, S2, H, HH, I, J, r, V, X3, Y3, Z3, t;
    int rc = -1;
    if (P->inf) {
        CHK(bn_copy(&P->X, qx)); CHK(bn_copy(&P->Y, qy)); CHK(bn_set_u32(&P->Z, 1));
        P->inf = 0;
        return 0;
    }
    bn_init(&Z1Z1); bn_init(&U2); bn_init(&S2); bn_init(&H); bn_init(&HH); bn_init(&I); bn_init(&J);
    bn_init(&r); bn_init(&V); bn_init(&X3); bn_init(&Y3); bn_init(&Z3); bn_init(&t);
    CHK(FMUL(&Z1Z1, &P->Z, &P->Z));
    CHK(FMUL(&U2, qx, &Z1Z1));
    CHK(FMUL(&t, &P->Z, &Z1Z1)); CHK(FMUL(&S2, qy, &t));
    CHK(FSUB(&H, &U2, &P->X));
    CHK(FSUB(&r, &S2, &P->Y));
    if (bn_is_zero(&H)) {                                            /* same x: doubling or opposite points */
        if (bn_is_zero(&r)) { bn_free(&Z1Z1); bn_free(&U2); bn_free(&S2); bn_free(&H); bn_free(&HH); bn_free(&I);
                              bn_free(&J); bn_free(&r); bn_free(&V); bn_free(&X3); bn_free(&Y3); bn_free(&Z3); bn_free(&t);
                              return jp_double(c, P); }
        P->inf = 1;
        rc = 0;
        goto fail;
    }
    CHK(FMUL(&HH, &H, &H));
    CHK(FADD(&I, &HH, &HH)); CHK(FADD(&I, &I, &I));                  /* I = 4*HH */
    CHK(FMUL(&J, &H, &I));
    CHK(FADD(&r, &r, &r));                                           /* r = 2*(S2 - Y1) */
    CHK(FMUL(&V, &P->X, &I));
    CHK(FMUL(&X3, &r, &r)); CHK(FSUB(&X3, &X3, &J));
    CHK(FADD(&t, &V, &V)); CHK(FSUB(&X3, &X3, &t));                  /* X3 = r^2 - J - 2V */
    CHK(FSUB(&t, &V, &X3)); CHK(FMUL(&Y3, &r, &t));
    CHK(FMUL(&t, &P->Y, &J)); CHK(FADD(&t, &t, &t)); CHK(FSUB(&Y3, &Y3, &t));    /* Y3 = r*(V-X3) - 2*Y1*J */
    CHK(FADD(&t, &P->Z, &H)); CHK(FMUL(&t, &t, &t));
    CHK(FSUB(&t, &t, &Z1Z1)); CHK(FSUB(&Z3, &t, &HH));               /* Z3 = (Z1+H)^2 - Z1Z1 - HH */
    CHK(bn_copy(&P->X, &X3)); CHK(bn_copy(&P->Y, &Y3)); CHK(bn_copy(&P->Z, &Z3));
    rc = 0;
fail:
    bn_free(&Z1Z1); bn_free(&U2); bn_free(&S2); bn_free(&H); bn_free(&HH); bn_free(&I); bn_free(&J);
    bn_free(&r); bn_free(&V); bn_free(&X3); bn_free(&Y3); bn_free(&Z3); bn_free(&t);
    return rc;
}

static int jp_to_affine(const ec_curve *c, ec_point *out, const jp *P)
{
    bn zi, zi2, zi3;
    int rc = -1;
    if (P->inf) { out->inf = 1; return 0; }
    bn_init(&zi); bn_init(&zi2); bn_init(&zi3);
    CHK(bn_modinv_prime(&zi, &P->Z, &c->p));
    CHK(FMUL(&zi2, &zi, &zi)); CHK(FMUL(&zi3, &zi2, &zi));
    CHK(FMUL(&out->x, &P->X, &zi2)); CHK(FMUL(&out->y, &P->Y, &zi3));
    out->inf = 0;
    rc = 0;
fail:
    bn_free(&zi); bn_free(&zi2); bn_free(&zi3);
    return rc;
}

int ec_mul(const ec_curve *c, ec_point *out, const bn *k, const ec_point *P)
{
    jp R;
    int i, rc = -1;
    jp_init(&R);
    if (P->inf || bn_is_zero(k)) { out->inf = 1; jp_free(&R); return 0; }
    for (i = bn_bits(k) - 1; i >= 0; i--) {
        CHK(jp_double(c, &R));
        if (bn_bit(k, i)) CHK(jp_madd(c, &R, &P->x, &P->y));
    }
    rc = jp_to_affine(c, out, &R);
fail:
    jp_free(&R);
    return rc;
}

int ec_mul_base(const ec_curve *c, ec_point *out, const bn *k)
{
    ec_point G;
    int rc;
    ec_point_init(&G);
    rc = (bn_copy(&G.x, &c->gx) < 0 || bn_copy(&G.y, &c->gy) < 0) ? -1 : (G.inf = 0, ec_mul(c, out, k, &G));
    ec_point_free(&G);
    return rc;
}

/* ------------------------------------------------------------------ */
/* encoding                                                            */
/* ------------------------------------------------------------------ */

int ec_encode_point(const ec_curve *c, const ec_point *p, u8 *out)
{
    if (p->inf) return -1;
    out[0] = 4;
    if (bn_to_bytes(&p->x, out + 1, (size_t)c->nbytes) < 0) return -1;
    return bn_to_bytes(&p->y, out + 1 + c->nbytes, (size_t)c->nbytes);
}

int ec_decode_point(const ec_curve *c, const u8 *q, size_t len, ec_point *out)
{
    if (len != (size_t)(1 + 2 * c->nbytes) || q[0] != 4) return -1;
    if (bn_from_bytes(&out->x, q + 1, (size_t)c->nbytes) < 0 || bn_from_bytes(&out->y, q + 1 + c->nbytes, (size_t)c->nbytes) < 0) return -1;
    out->inf = 0;
    return ec_on_curve(c, &out->x, &out->y) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* scalars and ECDSA                                                   */
/* ------------------------------------------------------------------ */

/* k = (SHA-512 stream over `material`) reduced into [1, n-1]; 8 extra bytes make the bias negligible. */
static int scalar_from_material(const ec_curve *c, bn *k, const u8 *material, size_t mlen)
{
    u8 stream[160], blk[64], ctr;
    size_t need = (size_t)c->nbytes + 8, have = 0, take;
    bn wide, nm1, one;
    int rc = -1;
    sha512_ctx h;
    for (ctr = 0; have < need; ctr++) {
        sha512_init(&h);
        sha512_update(&h, &ctr, 1);
        sha512_update(&h, material, mlen);
        sha512_final(&h, blk);
        take = need - have < 64 ? need - have : 64;
        memcpy(stream + have, blk, take);
        have += take;
    }
    bn_init(&wide); bn_init(&nm1); bn_init(&one);
    CHK(bn_from_bytes(&wide, stream, need));
    CHK(bn_set_u32(&one, 1)); CHK(bn_sub(&nm1, &c->n, &one));
    CHK(bn_mod(&wide, &wide, &nm1));
    CHK(bn_add(k, &wide, &one));                                     /* 1 .. n-1 */
    rc = 0;
fail:
    bn_free(&wide); bn_free(&nm1); bn_free(&one);
    ssh_wipe(stream, sizeof(stream)); ssh_wipe(blk, sizeof(blk));
    return rc;
}

int ec_random_scalar(const ec_curve *c, bn *d)
{
    u8 r[64];
    if (ssh_rng_bytes(r, sizeof(r)) != 0) return -1;
    if (scalar_from_material(c, d, r, sizeof(r)) < 0) return -1;
    ssh_wipe(r, sizeof(r));
    return 0;
}

/* leftmost nbits bits of the hash, as an integer (SEC1 / FIPS 186 "bits2int") */
static int hash_to_int(const ec_curve *c, bn *e, const u8 *hash, size_t hlen)
{
    if (bn_from_bytes(e, hash, hlen) < 0) return -1;
    if ((int)(hlen * 8) > c->nbits) return bn_shr(e, e, (int)(hlen * 8) - c->nbits);
    return 0;
}

int ecdsa_sign(const ec_curve *c, const bn *d, const u8 *hash, size_t hlen, bn *r, bn *s)
{
    bn e, k, kinv, t;
    ec_point R;
    u8 material[64 + 66 + 64 + 1];
    size_t mlen;
    int tries, rc = -1;

    bn_init(&e); bn_init(&k); bn_init(&kinv); bn_init(&t); ec_point_init(&R);
    if (hlen > 64) goto fail;
    CHK(hash_to_int(c, &e, hash, hlen));
    for (tries = 0; tries < 32; tries++) {
        mlen = 0;
        if (ssh_rng_bytes(material, 32) != 0) memset(material, 0, 32);      /* hedge: still safe without it */
        mlen = 32;
        CHK(bn_to_bytes(d, material + mlen, (size_t)c->nbytes)); mlen += (size_t)c->nbytes;
        memcpy(material + mlen, hash, hlen); mlen += hlen;
        material[mlen++] = (u8)tries;
        CHK(scalar_from_material(c, &k, material, mlen));
        CHK(ec_mul_base(c, &R, &k));
        if (R.inf) continue;
        CHK(bn_mod(r, &R.x, &c->n));
        if (bn_is_zero(r)) continue;
        CHK(bn_modinv_prime(&kinv, &k, &c->n));
        CHK(bn_mulmod(&t, r, d, &c->n));                                    /* r*d */
        CHK(bn_mod(&e, &e, &c->n));
        CHK(bn_addmod(&t, &t, &e, &c->n));                                  /* e + r*d */
        CHK(bn_mulmod(s, &kinv, &t, &c->n));
        if (bn_is_zero(s)) continue;
        rc = 0;
        break;
    }
fail:
    ssh_wipe(material, sizeof(material));
    bn_free(&e); bn_free(&k); bn_free(&kinv); bn_free(&t); ec_point_free(&R);
    return rc;
}

int ecdsa_verify(const ec_curve *c, const ec_point *Q, const u8 *hash, size_t hlen, const bn *r, const bn *s)
{
    bn e, w, u1, u2, v;
    ec_point A, B;
    jp S;
    int rc = -1;

    if (bn_is_zero(r) || bn_is_zero(s) || bn_cmp(r, &c->n) >= 0 || bn_cmp(s, &c->n) >= 0 || Q->inf || hlen > 64) return -1;
    bn_init(&e); bn_init(&w); bn_init(&u1); bn_init(&u2); bn_init(&v);
    ec_point_init(&A); ec_point_init(&B); jp_init(&S);
    CHK(hash_to_int(c, &e, hash, hlen));
    CHK(bn_mod(&e, &e, &c->n));
    CHK(bn_modinv_prime(&w, s, &c->n));
    CHK(bn_mulmod(&u1, &e, &w, &c->n));
    CHK(bn_mulmod(&u2, r, &w, &c->n));
    CHK(ec_mul_base(c, &A, &u1));
    CHK(ec_mul(c, &B, &u2, Q));
    if (A.inf && B.inf) goto fail;
    if (A.inf) { CHK(bn_copy(&S.X, &B.x)); CHK(bn_copy(&S.Y, &B.y)); CHK(bn_set_u32(&S.Z, 1)); S.inf = 0; }
    else {
        CHK(bn_copy(&S.X, &A.x)); CHK(bn_copy(&S.Y, &A.y)); CHK(bn_set_u32(&S.Z, 1)); S.inf = 0;
        if (!B.inf) CHK(jp_madd(c, &S, &B.x, &B.y));
    }
    if (S.inf) goto fail;
    ec_point_free(&A);
    ec_point_init(&A);
    CHK(jp_to_affine(c, &A, &S));
    CHK(bn_mod(&v, &A.x, &c->n));
    rc = bn_cmp(&v, r) == 0 ? 0 : -1;
fail:
    bn_free(&e); bn_free(&w); bn_free(&u1); bn_free(&u2); bn_free(&v);
    ec_point_free(&A); ec_point_free(&B); jp_free(&S);
    return rc;
}

int ecdh_shared(const ec_curve *c, const bn *d, const ec_point *peer, u8 *out)
{
    ec_point R;
    int rc = -1;
    ec_point_init(&R);
    if (peer->inf || !ec_on_curve(c, &peer->x, &peer->y)) goto fail;
    CHK(ec_mul(c, &R, d, peer));
    if (R.inf) goto fail;
    rc = bn_to_bytes(&R.x, out, (size_t)c->nbytes);
fail:
    ec_point_free(&R);
    return rc;
}
