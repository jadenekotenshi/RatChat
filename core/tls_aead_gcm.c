#include "tls_aead_gcm.h"
#include <string.h>

/* ---------------- GHASH: multiplication by the fixed hash subkey H ----------------
 *
 * NIST SP 800-38D's bit-by-bit algorithm (128 iterations of a 16-byte XOR and a 16-byte shift per
 * 16-byte block) made AES-GCM about 10x slower than it needed to be.  This is the same multiplication
 * done a nibble at a time ("Shoup's 4-bit tables", as in StepSSH's gcm.c, which this mirrors): 16
 * precomputed multiples of H, and 16 precomputed reductions for the four bits shifted out of the bottom
 * on each step, all in 32-bit words.  Both tables are derived in tls_gcm_init from the spec's own
 * definition -- multiplying by x is "shift right one bit, and XOR R = 11100001 || 0^120 into the top
 * whenever the bit shifted out was 1" -- so nothing here is a hand-typed constant.  A 128-bit value is
 * four big-endian words, v[0] holding the first four bytes. */

static void gf_mulx(u32 v[4])
{
    u32 lsb = v[3] & 1;
    v[3] = (v[2] << 31) | (v[3] >> 1);
    v[2] = (v[1] << 31) | (v[2] >> 1);
    v[1] = (v[0] << 31) | (v[1] >> 1);
    v[0] = (v[0] >> 1) ^ (lsb ? 0xe1000000UL : 0);
}

/* Nibble n's bits, MSB first, are the coefficients of x^0..x^3 (SP 800-38D's bit order), so the entry
 * for the single-bit nibbles 8, 4, 2, 1 is H*x^0, H*x^1, H*x^2, H*x^3 and every other entry is the XOR
 * of those it is made of. */
static void ghash_tables(tls_gcm_ctx *c)
{
    u32 v[4];
    int i, j, k, r;

    for (k = 0; k < 4; k++) { c->ht[0][k] = 0; v[k] = LOAD32_BE(c->h + 4 * k); }
    for (k = 0; k < 4; k++) c->ht[8][k] = v[k];
    for (i = 4; i > 0; i >>= 1) {
        gf_mulx(v);
        for (k = 0; k < 4; k++) c->ht[i][k] = v[k];
    }
    for (i = 2; i <= 8; i <<= 1)
        for (j = 1; j < i; j++)
            for (k = 0; k < 4; k++) c->ht[i + j][k] = c->ht[i][k] ^ c->ht[j][k];

    for (r = 0; r < 16; r++) {                       /* shift the four bits of r out through x^-4 */
        v[0] = v[1] = v[2] = 0;
        v[3] = (u32)r;
        for (i = 0; i < 4; i++) gf_mulx(v);
        c->last4[r] = v[0];
    }
}

/* x = x * H (x is one 16-byte block).  Bytes are consumed last to first, low nibble before high. */
static void gmult(const tls_gcm_ctx *c, u8 x[16])
{
    u32 z0, z1, z2, z3;
    unsigned lo, hi, rem;
    int i;

    lo = x[15] & 0xf;
    z0 = c->ht[lo][0]; z1 = c->ht[lo][1]; z2 = c->ht[lo][2]; z3 = c->ht[lo][3];
    for (i = 15; i >= 0; i--) {
        lo = x[i] & 0xf;
        hi = (unsigned)x[i] >> 4;
        if (i != 15) {
            rem = z3 & 0xf;
            z3 = (z2 << 28) | (z3 >> 4); z2 = (z1 << 28) | (z2 >> 4);
            z1 = (z0 << 28) | (z1 >> 4); z0 = (z0 >> 4) ^ c->last4[rem];
            z0 ^= c->ht[lo][0]; z1 ^= c->ht[lo][1]; z2 ^= c->ht[lo][2]; z3 ^= c->ht[lo][3];
        }
        rem = z3 & 0xf;
        z3 = (z2 << 28) | (z3 >> 4); z2 = (z1 << 28) | (z2 >> 4);
        z1 = (z0 << 28) | (z1 >> 4); z0 = (z0 >> 4) ^ c->last4[rem];
        z0 ^= c->ht[hi][0]; z1 ^= c->ht[hi][1]; z2 ^= c->ht[hi][2]; z3 ^= c->ht[hi][3];
    }
    STORE32_BE(x, z0); STORE32_BE(x + 4, z1); STORE32_BE(x + 8, z2); STORE32_BE(x + 12, z3);
}

/* y = (y ^ data) * H over `len` bytes, the last block zero-padded -- used for both the AAD and the
 * ciphertext sections of GHASH's input. */
static void ghash_bytes(const tls_gcm_ctx *c, u8 y[16], const u8 *data, size_t len)
{
    size_t off, n, i;
    for (off = 0; off < len; off += 16) {
        n = len - off < 16 ? len - off : 16;
        for (i = 0; i < n; i++) y[i] ^= data[off + i];
        gmult(c, y);
    }
}

static void ghash(const tls_gcm_ctx *c, const u8 *aad, size_t aad_len, const u8 *ct, size_t ct_len, u8 out[16])
{
    u8 y[16], lenblock[16];
    u64 aad_bits = (u64)aad_len * 8, ct_bits = (u64)ct_len * 8;
    memset(y, 0, 16);
    ghash_bytes(c, y, aad, aad_len);
    ghash_bytes(c, y, ct, ct_len);
    STORE64_BE(lenblock, aad_bits);
    STORE64_BE(lenblock + 8, ct_bits);
    ghash_bytes(c, y, lenblock, 16);
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
    ghash_tables(c);
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
    ghash(c, aad, aad_len, out, len, s);
    aes_encrypt_block(&c->aes, j0, e_j0);
    { size_t i; for (i = 0; i < TLS_GCM_TAG_LEN; i++) out[len + i] = (u8)(e_j0[i] ^ s[i]); }
}

int tls_gcm_open(const tls_gcm_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                  const u8 *in, u8 *out, size_t len)
{
    u8 j0[16], j0_inc[16], s[16], e_j0[16], tag[16];
    build_j0(c, seq, j0);
    ghash(c, aad, aad_len, in, len, s);
    aes_encrypt_block(&c->aes, j0, e_j0);
    { size_t i; for (i = 0; i < TLS_GCM_TAG_LEN; i++) tag[i] = (u8)(e_j0[i] ^ s[i]); }
    if (ssh_ct_memcmp(tag, in + len, TLS_GCM_TAG_LEN) != 0) return -1;
    memcpy(j0_inc, j0, 16);
    inc32(j0_inc);
    gctr(&c->aes, j0_inc, in, out, len);
    return 0;
}
