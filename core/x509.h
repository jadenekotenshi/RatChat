/*
 * x509.h -- just enough X.509 to reach one leaf certificate's public key.
 *
 * This is deliberately not a general certificate parser. RatChat's TLS trust model is TOFU
 * pinning of the whole leaf certificate's DER bytes (mirrors core/knownhosts.c's SSH host-key
 * model) -- there is no CA chain to walk, no issuer signature to verify, no revocation checking,
 * and no hostname-vs-SubjectAltName matching, so none of that is implemented. What TLS's
 * handshake mechanically requires is the leaf's SubjectPublicKeyInfo, to verify the signature the
 * server makes over the handshake transcript; the subject CN is pulled out too, best-effort, only
 * so a future trust dialog can show something more readable than a raw DER blob. Extensions
 * (including SubjectAltName) are not parsed at all.
 */
#ifndef RC_X509_H
#define RC_X509_H

#include "ssh_types.h"
#include "der.h"
#include "rsa.h"
#include "ecc.h"

enum { X509_KEY_RSA = 1, X509_KEY_EC = 2 };

#define X509_CN_MAX 128

typedef struct {
    int key_type;                  /* X509_KEY_RSA or X509_KEY_EC */
    rsa_pub rsa;                    /* valid iff key_type == X509_KEY_RSA */
    int curve;                      /* EC_P256/P384/P521; valid iff key_type == X509_KEY_EC */
    ec_point ec_pub;                 /* valid iff key_type == X509_KEY_EC */
    der_time not_before, not_after;
    char cn[X509_CN_MAX];             /* best-effort subject CN, NUL-terminated; "" if absent,
                                        * not a string type this reads, or too long to fit */
    const u8 *der;                    /* the whole certificate's DER bytes -- borrowed, not
                                        * copied; the caller must keep this buffer alive as long
                                        * as the x509_cert is used (Phase 6's pinning hashes it) */
    size_t der_len;
} x509_cert;

void x509_cert_init(x509_cert *c);
void x509_cert_free(x509_cert *c);

/* Parses one DER-encoded X.509v3 leaf certificate into *out (which must already be
 * x509_cert_init'd). Does not verify any signature. Returns 0 on success, -1 with *err set to a
 * short reason on failure -- including on truncated or corrupt input, which is always refused
 * cleanly rather than read out of bounds. */
int x509_parse_leaf(const u8 *der, size_t len, x509_cert *out, const char **err);

#endif
