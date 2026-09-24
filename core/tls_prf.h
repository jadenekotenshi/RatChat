/*
 * tls_prf.h -- RFC 5246 SS5's pseudo-random function, fixed to SHA-256.
 *
 * Every cipher suite in this project's TLS 1.2 (the ECDHE + AEAD-only set chosen in the TLS
 * plan) names SHA-256 as its PRF hash, so P_SHA384 and the TLS 1.0/1.1 legacy MD5+SHA-1 PRF are
 * never needed and are not implemented.
 *
 *   PRF(secret, label, seed) = P_SHA256(secret, label || seed)
 *   P_SHA256(secret, seed)   = HMAC_SHA256(secret, A(1) || seed) ||
 *                              HMAC_SHA256(secret, A(2) || seed) || ...
 *   A(0) = seed;  A(i) = HMAC_SHA256(secret, A(i-1))
 *
 * Used twice by the handshake (Phase 5): once to derive the 48-byte master_secret from the
 * premaster secret, and once to derive the key_block (write keys and, for AEAD suites, the
 * fixed IVs -- no MAC keys, since every suite here is AEAD) from the master_secret.
 */
#ifndef RC_TLS_PRF_H
#define RC_TLS_PRF_H

#include "ssh_types.h"

/* Writes exactly out_len bytes to out. `label` is a plain C string -- RFC 5246's labels
 * ("master secret", "key expansion", ...) are always short ASCII with no embedded NUL, so a
 * strlen()'d pointer is enough; it is never secret and never attacker-controlled. */
void tls_prf(const u8 *secret, size_t secret_len, const char *label,
             const u8 *seed, size_t seed_len, u8 *out, size_t out_len);

#endif
