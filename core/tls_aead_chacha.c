#include "tls_aead_chacha.h"
#include "chacha.h"
#include <stdlib.h>
#include <string.h>

/* Pokes chacha_ctx's public `s` array directly into RFC 8439's IETF layout (32-bit counter in
 * s[12], 96-bit nonce in s[13..15]) -- chacha_ivsetup's own (iv[8], counter) shape is for the
 * older 64-bit-nonce/64-bit-counter scheme chachapoly_* uses instead, see tls_aead_chacha.h. */
static void ietf_setup(chacha_ctx *c, const u8 key[32], const u8 nonce[12], u32 counter)
{
    chacha_keysetup(c, key);
    c->s[12] = counter;
    c->s[13] = LOAD32_LE(nonce);
    c->s[14] = LOAD32_LE(nonce + 4);
    c->s[15] = LOAD32_LE(nonce + 8);
}

void tls_chacha_init(tls_chacha_ctx *c, const u8 key[TLS_CHACHA_KEY_LEN], const u8 iv[TLS_CHACHA_IV_LEN])
{
    memcpy(c->key, key, TLS_CHACHA_KEY_LEN);
    memcpy(c->iv, iv, TLS_CHACHA_IV_LEN);
}

/* RFC 7905 SS2: the write_IV XORed with the 64-bit sequence number, left-padded to 96 bits. */
static void build_nonce(const tls_chacha_ctx *c, u64 seq, u8 nonce[12])
{
    u8 seqb[12];
    int i;
    memset(seqb, 0, 4);
    STORE64_BE(seqb + 4, seq);
    for (i = 0; i < 12; i++) nonce[i] = (u8)(c->iv[i] ^ seqb[i]);
}

static size_t pad16(size_t n) { return (16 - (n % 16)) % 16; }

static void store64_le(u8 *p, u64 v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (u8)(v >> (8 * i));
}

/* RFC 8439 SS2.6: the one-time Poly1305 key is the first 32 bytes of the keystream at block
 * counter 0 (the actual data is encrypted starting at counter 1, never counter 0). */
static void poly_key(const u8 key[32], const u8 nonce[12], u8 out[32])
{
    chacha_ctx c;
    u8 zero[32];
    memset(zero, 0, 32);
    ietf_setup(&c, key, nonce, 0);
    chacha_xor(&c, zero, out, 32);
}

/* RFC 8439 SS2.8: AAD || pad16(AAD) || ct || pad16(ct) || len(AAD) LE64 || len(ct) LE64, built
 * into a freshly malloc'd buffer (poly1305_auth() is one-shot, not incremental, and a full TLS
 * record's worth -- up to 2^14 bytes -- isn't a safe stack allocation). Caller frees it; NULL on
 * allocation failure. */
static u8 *build_mac_data(const u8 *aad, size_t aad_len, const u8 *ct, size_t ct_len, size_t *out_len)
{
    size_t pa = pad16(aad_len), pc = pad16(ct_len);
    size_t total = aad_len + pa + ct_len + pc + 16;
    u8 *buf = (u8 *)malloc(total);
    size_t off = 0;
    if (!buf) return NULL;
    memcpy(buf + off, aad, aad_len); off += aad_len;
    memset(buf + off, 0, pa); off += pa;
    memcpy(buf + off, ct, ct_len); off += ct_len;
    memset(buf + off, 0, pc); off += pc;
    store64_le(buf + off, (u64)aad_len); off += 8;
    store64_le(buf + off, (u64)ct_len); off += 8;
    *out_len = total;
    return buf;
}

int tls_chacha_seal(const tls_chacha_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                     const u8 *in, u8 *out, size_t len)
{
    u8 nonce[12], pkey[32];
    chacha_ctx cc;
    u8 *mac_data;
    size_t mac_len;

    build_nonce(c, seq, nonce);
    poly_key(c->key, nonce, pkey);
    ietf_setup(&cc, c->key, nonce, 1);
    chacha_xor(&cc, in, out, len);

    mac_data = build_mac_data(aad, aad_len, out, len, &mac_len);
    if (!mac_data) return -1;
    poly1305_auth(out + len, mac_data, mac_len, pkey);
    free(mac_data);
    ssh_wipe(pkey, sizeof(pkey));
    return 0;
}

int tls_chacha_open(const tls_chacha_ctx *c, u64 seq, const u8 *aad, size_t aad_len,
                     const u8 *in, u8 *out, size_t len)
{
    u8 nonce[12], pkey[32], tag[16];
    chacha_ctx cc;
    u8 *mac_data;
    size_t mac_len;
    int ok;

    build_nonce(c, seq, nonce);
    poly_key(c->key, nonce, pkey);

    mac_data = build_mac_data(aad, aad_len, in, len, &mac_len);
    if (!mac_data) return -1;
    poly1305_auth(tag, mac_data, mac_len, pkey);
    free(mac_data);

    ok = ssh_ct_memcmp(tag, in + len, TLS_CHACHA_TAG_LEN) == 0;
    ssh_wipe(pkey, sizeof(pkey));
    if (!ok) return -1;

    ietf_setup(&cc, c->key, nonce, 1);
    chacha_xor(&cc, in, out, len);
    return 0;
}
