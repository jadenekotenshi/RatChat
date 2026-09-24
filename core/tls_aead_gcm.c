#include "tls_aead_gcm.h"
#include <string.h>

/* ---------------- GF(2^128) multiplication (NIST SP 800-38D SS6.3, bit-by-bit reference
 * algorithm) ---------------- */

static void gf_mult(const u8 x[16], const u8 y[16], u8 out[16])
{
    u8 z[16], v[16];
    int i, j;
    memset(z, 0, 16);
    memcpy(v, y, 16);
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            int k, lsb;
            if (x[i] & (1 << j)) {
                for (k = 0; k < 16; k++) z[k] ^= v[k];
            }
            lsb = v[15] & 1;
            for (k = 15; k > 0; k--) v[k] = (u8)((v[k] >> 1) | ((v[k - 1] & 1) << 7));
            v[0] = (u8)(v[0] >> 1);
            if (lsb) v[0] ^= 0xe1;
        }
    }
    memcpy(out, z, 16);
}

/* ---------------- GHASH ---------------- */

static void ghash_block(u8 y[16], const u8 h[16], const u8 block[16])
{
    u8 xored[16];
    int i;
    for (i = 0; i < 16; i++) xored[i] = (u8)(y[i] ^ block[i]);
    gf_mult(xored, h, y);
}

/* Feeds `len` bytes in 16-byte chunks, zero-padding the final partial chunk -- used for both the
 * AAD and the ciphertext sections of GHASH's input. */
static void ghash_bytes(u8 y[16], const u8 h[16], const u8 *data, size_t len)
{
    while (len >= 16) {
        ghash_block(y, h, data);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        u8 block[16];
        memset(block, 0, 16);
        memcpy(block, data, len);
        ghash_block(y, h, block);
    }
}

static void ghash(const u8 h[16], const u8 *aad, size_t aad_len, const u8 *ct, size_t ct_len, u8 out[16])
{
    u8 y[16], lenblock[16];
    u64 aad_bits = (u64)aad_len * 8, ct_bits = (u64)ct_len * 8;
    memset(y, 0, 16);
    ghash_bytes(y, h, aad, aad_len);
    ghash_bytes(y, h, ct, ct_len);
    STORE64_BE(lenblock, aad_bits);
    STORE64_BE(lenblock + 8, ct_bits);
    ghash_block(y, h, lenblock);
    memcpy(out, y, 16);
}

/* ---------------- GCTR: GCM's own counter mode (32-bit counter, wraps mod 2^32; NOT the
 * 128-bit-wide increment aes.h's own aes_ctr_xor implements) ---------------- */

static void inc32(u8 block[16])
{
    u32 ctr = LOAD32_BE(block + 12);
    ctr++;
    STORE32_BE(block + 12, ctr);
}

static void gctr(const aes_ctr_ctx *aes, const u8 icb[16], const u8 *in, u8 *out, size_t len)
{
    u8 cb[16], ks[16];
    memcpy(cb, icb, 16);
    while (len > 0) {
        size_t n = len < 16 ? len : 16;
        size_t i;
        aes_encrypt_block(aes, cb, ks);
        for (i = 0; i < n; i++) out[i] = (u8)(in[i] ^ ks[i]);
        inc32(cb);
        in += n; out += n; len -= n;
    }
}

/* ---------------- TLS-facing API ---------------- */

void tls_gcm_init(tls_gcm_ctx *c, const u8 *key, int keylen, const u8 fixed_iv[TLS_GCM_FIXED_IV_LEN])
{
    u8 zero[16];
    memset(zero, 0, 16);
    aes_ctr_init(&c->aes, key, keylen, zero);          /* the IV here only seeds aes_ctr_ctx's
                                                         * unused CTR state; only the round keys
                                                         * (used via aes_encrypt_block) matter */
    aes_encrypt_block(&c->aes, zero, c->h);
    memcpy(c->fixed_iv, fixed_iv, TLS_GCM_FIXED_IV_LEN);
}

static void build_j0(const tls_gcm_ctx *c, u64 seq, u8 j0[16])
{
    memcpy(j0, c->fixed_iv, TLS_GCM_FIXED_IV_LEN);
    STORE64_BE(j0 + TLS_GCM_FIXED_IV_LEN, seq);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
}

void tls_gcm_seal(const tls_gcm_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                   const u8 *in, u8 *out, size_t len)
{
    u8 j0[16], j0_inc[16], s[16], e_j0[16];
    build_j0(c, seq, j0);
    memcpy(j0_inc, j0, 16);
    inc32(j0_inc);
    gctr(&c->aes, j0_inc, in, out, len);
    ghash(c->h, aad, aad_len, out, len, s);
    aes_encrypt_block(&c->aes, j0, e_j0);
    { size_t i; for (i = 0; i < TLS_GCM_TAG_LEN; i++) out[len + i] = (u8)(e_j0[i] ^ s[i]); }
}

int tls_gcm_open(const tls_gcm_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                  const u8 *in, u8 *out, size_t len)
{
    u8 j0[16], j0_inc[16], s[16], e_j0[16], tag[16];
    build_j0(c, seq, j0);
    ghash(c->h, aad, aad_len, in, len, s);
    aes_encrypt_block(&c->aes, j0, e_j0);
    { size_t i; for (i = 0; i < TLS_GCM_TAG_LEN; i++) tag[i] = (u8)(e_j0[i] ^ s[i]); }
    if (ssh_ct_memcmp(tag, in + len, TLS_GCM_TAG_LEN) != 0) return -1;
    memcpy(j0_inc, j0, 16);
    inc32(j0_inc);
    gctr(&c->aes, j0_inc, in, out, len);
    return 0;
}
