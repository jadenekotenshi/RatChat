#include <string.h>
#include "aes.h"
#include "aes_tab.h"

#define XTIME(x) ((u8)(((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)))

void aes_ctr_init(aes_ctr_ctx *c, const u8 *key, int keylen, const u8 iv[16])
{
    int nk = keylen / 4, nr = nk + 6, total = 4 * (nr + 1), i;
    u32 rcon = 1, t;
    u32 *w = c->rk;

    c->rounds = nr;
    for (i = 0; i < nk; i++) w[i] = LOAD32_BE(key + 4 * i);
    for (i = nk; i < total; i++) {
        t = w[i - 1];
        if (i % nk == 0) {
            t = ((u32)SBOX[(t >> 16) & 0xff] << 24) | ((u32)SBOX[(t >> 8) & 0xff] << 16) |
                ((u32)SBOX[t & 0xff] << 8) | (u32)SBOX[(t >> 24) & 0xff];
            t ^= rcon << 24;
            rcon = XTIME(rcon) & 0xff;
        } else if (nk > 6 && i % nk == 4) {
            t = ((u32)SBOX[(t >> 24) & 0xff] << 24) | ((u32)SBOX[(t >> 16) & 0xff] << 16) |
                ((u32)SBOX[(t >> 8) & 0xff] << 8) | (u32)SBOX[t & 0xff];
        }
        w[i] = w[i - nk] ^ t;
    }
    memcpy(c->ctr, iv, 16);
    c->used = 16;
}

static void add_round_key(u8 s[16], const u32 *rk)
{
    int i;
    for (i = 0; i < 4; i++) {
        s[4 * i]     ^= (u8)(rk[i] >> 24);
        s[4 * i + 1] ^= (u8)(rk[i] >> 16);
        s[4 * i + 2] ^= (u8)(rk[i] >> 8);
        s[4 * i + 3] ^= (u8)(rk[i]);
    }
}

void aes_encrypt_block(const aes_ctr_ctx *c, const u8 in[16], u8 out[16])
{
    u8 s[16], t[16], a0, a1, a2, a3, x;
    int r, i;

    memcpy(s, in, 16);
    add_round_key(s, c->rk);
    for (r = 1; r <= c->rounds; r++) {
        /* SubBytes + ShiftRows (state is column-major: s[4*col + row]) */
        for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];
        s[0] = t[0];   s[4] = t[4];   s[8] = t[8];   s[12] = t[12];
        s[1] = t[5];   s[5] = t[9];   s[9] = t[13];  s[13] = t[1];
        s[2] = t[10];  s[6] = t[14];  s[10] = t[2];  s[14] = t[6];
        s[3] = t[15];  s[7] = t[3];   s[11] = t[7];  s[15] = t[11];
        if (r != c->rounds) {
            for (i = 0; i < 16; i += 4) {   /* MixColumns */
                a0 = s[i]; a1 = s[i + 1]; a2 = s[i + 2]; a3 = s[i + 3];
                x = (u8)(a0 ^ a1 ^ a2 ^ a3);
                s[i]     = (u8)(a0 ^ x ^ XTIME(a0 ^ a1));
                s[i + 1] = (u8)(a1 ^ x ^ XTIME(a1 ^ a2));
                s[i + 2] = (u8)(a2 ^ x ^ XTIME(a2 ^ a3));
                s[i + 3] = (u8)(a3 ^ x ^ XTIME(a3 ^ a0));
            }
        }
        add_round_key(s, c->rk + 4 * r);
    }
    memcpy(out, s, 16);
}

void aes_ctr_xor(aes_ctr_ctx *c, const u8 *in, u8 *out, size_t len)
{
    size_t i;
    int j;
    for (i = 0; i < len; i++) {
        if (c->used == 16) {
            aes_encrypt_block(c, c->ctr, c->ks);
            for (j = 15; j >= 0; j--) if (++c->ctr[j]) break;
            c->used = 0;
        }
        out[i] = (u8)(in[i] ^ c->ks[c->used++]);
    }
}

/* ---------------- decryption (for CBC-encrypted private key files) ---------------- */

static u8 gmul(u8 a, u8 b)
{
    u8 p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = XTIME(a);
        b >>= 1;
    }
    return p;
}

void aes_decrypt_block(const aes_ctr_ctx *c, const u8 in[16], u8 out[16])
{
    u8 s[16], t[16], a0, a1, a2, a3;
    int r, i;

    memcpy(s, in, 16);
    add_round_key(s, c->rk + 4 * c->rounds);
    for (r = c->rounds - 1; r >= 0; r--) {
        memcpy(t, s, 16);                                  /* InvShiftRows */
        s[0] = t[0];   s[4] = t[4];   s[8] = t[8];    s[12] = t[12];
        s[1] = t[13];  s[5] = t[1];   s[9] = t[5];    s[13] = t[9];
        s[2] = t[10];  s[6] = t[14];  s[10] = t[2];   s[14] = t[6];
        s[3] = t[7];   s[7] = t[11];  s[11] = t[15];  s[15] = t[3];
        for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];    /* InvSubBytes */
        add_round_key(s, c->rk + 4 * r);
        if (r > 0) {
            for (i = 0; i < 16; i += 4) {                  /* InvMixColumns */
                a0 = s[i]; a1 = s[i + 1]; a2 = s[i + 2]; a3 = s[i + 3];
                s[i]     = (u8)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
                s[i + 1] = (u8)(gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
                s[i + 2] = (u8)(gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11));
                s[i + 3] = (u8)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14));
            }
        }
    }
    memcpy(out, s, 16);
}

void aes_cbc_decrypt(const aes_ctr_ctx *c, const u8 iv[16], const u8 *in, u8 *out, size_t len)
{
    u8 prev[16], cur[16], plain[16];
    size_t off;
    int i;
    memcpy(prev, iv, 16);
    for (off = 0; off + 16 <= len; off += 16) {
        memcpy(cur, in + off, 16);                         /* in and out may be the same buffer */
        aes_decrypt_block(c, cur, plain);
        for (i = 0; i < 16; i++) out[off + i] = (u8)(plain[i] ^ prev[i]);
        memcpy(prev, cur, 16);
    }
}

void aes_cbc_encrypt_chain(const aes_ctr_ctx *c, u8 iv[16], const u8 *in, u8 *out, size_t len)
{
    u8 blk[16];
    size_t off;
    int i;
    for (off = 0; off + 16 <= len; off += 16) {
        for (i = 0; i < 16; i++) blk[i] = (u8)(in[off + i] ^ iv[i]);
        aes_encrypt_block(c, blk, out + off);
        memcpy(iv, out + off, 16);
    }
}

void aes_cbc_decrypt_chain(const aes_ctr_ctx *c, u8 iv[16], const u8 *in, u8 *out, size_t len)
{
    u8 cur[16], plain[16];
    size_t off;
    int i;
    for (off = 0; off + 16 <= len; off += 16) {
        memcpy(cur, in + off, 16);
        aes_decrypt_block(c, cur, plain);
        for (i = 0; i < 16; i++) out[off + i] = (u8)(plain[i] ^ iv[i]);
        memcpy(iv, cur, 16);
    }
}
