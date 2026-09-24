#ifndef SSH_AES_H
#define SSH_AES_H
#include "ssh_types.h"

/* AES-128/256 with CTR mode (encrypt-only key schedule; CTR needs no decrypt).
 * Byte-oriented, small, and not cache-timing hardened -- adequate for a
 * client on a 1990s workstation; prefer chacha20-poly1305 where offered. */
typedef struct {
    u32 rk[60];
    int rounds;
    u8 ctr[16];      /* big-endian counter block, incremented per block */
    u8 ks[16];       /* current keystream block */
    int used;        /* bytes of ks already consumed (16 = need a new one) */
} aes_ctr_ctx;

void aes_ctr_init(aes_ctr_ctx *c, const u8 *key, int keylen, const u8 iv[16]);
void aes_ctr_xor(aes_ctr_ctx *c, const u8 *in, u8 *out, size_t len);
/* raw single-block ECB encrypt (for tests / bcrypt-pbkdf-free uses) */
void aes_encrypt_block(const aes_ctr_ctx *c, const u8 in[16], u8 out[16]);

/* Block decryption and CBC decrypt (len must be a multiple of 16).  The context
 * from aes_ctr_init() holds the round keys for both directions. */
void aes_decrypt_block(const aes_ctr_ctx *c, const u8 in[16], u8 out[16]);
void aes_cbc_decrypt(const aes_ctr_ctx *c, const u8 iv[16], const u8 *in, u8 *out, size_t len);
/* Streaming CBC for the SSH transport: `iv` is updated to the last ciphertext block, so successive
 * calls continue one long chain (SSH chains the IV across packets).  len must be a multiple of 16;
 * in and out may be the same buffer. */
void aes_cbc_encrypt_chain(const aes_ctr_ctx *c, u8 iv[16], const u8 *in, u8 *out, size_t len);
void aes_cbc_decrypt_chain(const aes_ctr_ctx *c, u8 iv[16], const u8 *in, u8 *out, size_t len);

#endif
