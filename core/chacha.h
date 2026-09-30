#ifndef SSH_CHACHA_H
#define SSH_CHACHA_H
#include "ssh_types.h"

typedef struct { u32 s[16]; } chacha_ctx;

void chacha_keysetup(chacha_ctx *c, const u8 key[32]);
/* iv = 8 bytes taken raw (OpenSSH passes the big-endian sequence number). */
void chacha_ivsetup(chacha_ctx *c, const u8 iv[8], u64 counter);
void chacha_xor(chacha_ctx *c, const u8 *in, u8 *out, size_t len);

void poly1305_auth(u8 mac[16], const u8 *msg, size_t len, const u8 key[32]);

/* chacha20-poly1305@openssh.com: 64-byte key = K_main(32) || K_header(32) */
#define CHACHAPOLY_KEYLEN 64
#define CHACHAPOLY_TAGLEN 16
#define CHACHAPOLY_AADLEN 4

typedef struct {
    chacha_ctx main, header;
    /* The last length peek (see chachapoly_peek_length): the sequence number, the 4 encrypted bytes
     * it was computed from, and the 4 plain bytes -- so the same packet's header is not decrypted
     * again (a full ChaCha block each time) by every re-peek while it arrives in pieces and by open. */
    int  peek_valid;
    u32  peek_seq;
    u8   peek_enc[4], peek_plain[4];
} chachapoly_ctx;

void chachapoly_init(chachapoly_ctx *c, const u8 key[CHACHAPOLY_KEYLEN]);
/* Decrypt just the 4-byte length field so the caller knows how much to read.  Remembers the result,
 * so asking again for the same packet costs nothing, and chachapoly_open reuses it. */
u32  chachapoly_peek_length(chachapoly_ctx *c, u32 seq, const u8 enc_len[4]);
/* dst/src = [len(4)][payload(len)] ; the tag is written to / read from
 * dst+4+len (seal) or src+4+len (open).  open returns 0, or -1 on MAC failure. */
void chachapoly_seal(chachapoly_ctx *c, u32 seq, u8 *dst, const u8 *src, size_t len);
int  chachapoly_open(chachapoly_ctx *c, u32 seq, u8 *dst, const u8 *src, size_t len);

#endif
