/*
 * tls_aead_chacha.h -- the IETF ChaCha20-Poly1305 AEAD construction (RFC 8439), framed the way
 * TLS 1.2 uses it (RFC 7905).
 *
 * Built on chacha.c's raw chacha_keysetup/chacha_xor and poly1305_auth primitives, but NOT on
 * its chachapoly_* wrapper -- that implements chacha20-poly1305@openssh.com, a different, older
 * scheme (a 64-byte split main/header key, a 64-bit nonce + 64-bit counter state layout) that
 * predates and differs from RFC 8439's single 32-byte key + 96-bit nonce + 32-bit counter
 * layout. This module sets the chacha_ctx state directly (its `s` array is public) rather than
 * going through chacha_ivsetup, whose own (iv[8], counter) parameters are shaped for that older
 * scheme and can't express a 96-bit nonce.
 *
 * TLS's own framing (RFC 7905 SS2) sends no explicit per-record nonce at all, unlike GCM: the
 * nonce is the write_IV (12 bytes, from the key_block) XORed with the record's 64-bit sequence
 * number left-padded to 96 bits. The AAD is the same 13-byte construction as GCM's.
 */
#ifndef RC_TLS_AEAD_CHACHA_H
#define RC_TLS_AEAD_CHACHA_H

#include "ssh_types.h"

#define TLS_CHACHA_KEY_LEN 32
#define TLS_CHACHA_IV_LEN 12
#define TLS_CHACHA_TAG_LEN 16

typedef struct {
    u8 key[TLS_CHACHA_KEY_LEN];
    u8 iv[TLS_CHACHA_IV_LEN];
} tls_chacha_ctx;

void tls_chacha_init(tls_chacha_ctx *c, const u8 key[TLS_CHACHA_KEY_LEN], const u8 iv[TLS_CHACHA_IV_LEN]);

/* seq is the record's sequence number (XORed into the fixed IV to make the nonce, never sent on
 * the wire itself). aad is the same 13-byte RFC 5246 SS6.2.3.3 construction tls_aead_gcm.h's
 * functions take. Writes len bytes of ciphertext to out, followed by the 16-byte tag; in and out
 * may be the same buffer. Returns 0 on success, -1 only on allocation failure (the one-shot
 * poly1305_auth() needs the whole padded AAD||ciphertext||lengths laid out contiguously, heap
 * allocated here since a full 2^14-byte TLS record's worth wouldn't be a safe stack allocation). */
int tls_chacha_seal(const tls_chacha_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                     const u8 *in, u8 *out, size_t len);

/* in points at len ciphertext bytes followed by TLS_CHACHA_TAG_LEN tag bytes. Returns 0 and
 * writes len plaintext bytes to out on success; returns -1 on tag mismatch (out untouched) or
 * allocation failure. in and out may be the same buffer. */
int tls_chacha_open(const tls_chacha_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                     const u8 *in, u8 *out, size_t len);

#endif
