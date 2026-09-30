/*
 * tls_aead_gcm.h -- AES-GCM framed the way TLS 1.2 uses it (RFC 5288, RFC 5246 SS6.2.3.3).
 *
 * GHASH and GCM's own counter mode (GCTR: a 96-bit fixed part plus a 32-bit counter that wraps
 * mod 2^32, NOT the 128-bit-wide counter aes.h's own aes_ctr_xor implements for SSH) are both
 * implemented here from scratch on top of aes.h's public aes_encrypt_block -- StepSSH's own
 * gcm.c is deliberately not vendored/un-`static`-ed for this; see the TLS plan.
 *
 * TLS's AEAD nonce is the 4-byte fixed IV (from the key_block) concatenated with an 8-byte
 * explicit per-record value; RFC 5246 leaves that value's choice up to the implementation as
 * long as it's unique per record under a given key. This module takes it as the `seq` parameter
 * and uses the record's own 64-bit sequence number directly -- it never needs its own random
 * source and is trivially unique. (A real captured OpenSSL session used a different, seemingly
 * unrelated value for its own explicit nonce instead -- also RFC-legal, just a different choice;
 * see tls_aead_vectors.h's own note on how that was handled when testing against it.) That 8
 * bytes IS sent separately on the wire ahead of the ciphertext (unlike ChaCha20-Poly1305's TLS
 * framing, which sends no explicit nonce at all) -- this module's own in/out buffers are only
 * ever the plaintext/ciphertext, without that wire-level prefix; the caller (the record layer,
 * Phase 5) owns writing/reading it.
 */
#ifndef RC_TLS_AEAD_GCM_H
#define RC_TLS_AEAD_GCM_H

#include "ssh_types.h"
#include "aes.h"

#define TLS_GCM_TAG_LEN 16
#define TLS_GCM_FIXED_IV_LEN 4
#define TLS_GCM_EXPLICIT_NONCE_LEN 8

typedef struct {
    aes_ctr_ctx aes;                        /* round keys only; its own ctr/ks fields are unused */
    u8 h[16];                                /* GHASH subkey, AES_K(0^128) */
    u32 ht[16][4];                           /* multiply-by-H tables, one 128-bit entry per 4-bit value (tls_aead_gcm.c) */
    u32 last4[16];                           /* what shifting a 4-bit remainder out of the bottom adds back at the top */
    u8 fixed_iv[TLS_GCM_FIXED_IV_LEN];
} tls_gcm_ctx;

void tls_gcm_init(tls_gcm_ctx *c, const u8 *key, int keylen, const u8 fixed_iv[TLS_GCM_FIXED_IV_LEN]);

/* seq is the record's sequence number, used directly as the explicit nonce (see above). aad is
 * exactly the 13 bytes RFC 5246 SS6.2.3.3 defines: seq_num(8) || type(1) || version(2) ||
 * TLSCompressed.length(2) -- built by the caller, who already has all of those fields to hand.
 * Writes len bytes of ciphertext to out, followed by the TLS_GCM_TAG_LEN-byte tag; in and out
 * may be the same buffer. */
void tls_gcm_seal(const tls_gcm_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                   const u8 *in, u8 *out, size_t len);

/* in points at len ciphertext bytes followed by TLS_GCM_TAG_LEN tag bytes. Returns 0 and writes
 * len plaintext bytes to out on success; returns -1 on tag mismatch and leaves out untouched, so
 * a caller can never end up using unauthenticated plaintext by mistake. in and out may be the
 * same buffer (out is only written after the tag has already been checked against a value
 * computed from the still-intact ciphertext). */
int tls_gcm_open(const tls_gcm_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                  const u8 *in, u8 *out, size_t len);

#endif
