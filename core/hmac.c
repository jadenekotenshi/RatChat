#include <string.h>
#include "hmac.h"

void hmac_init(hmac_ctx *h, int kind, const u8 *key, size_t keylen)
{
    u8 k[SHA512_BLOCK], pad[SHA512_BLOCK];
    size_t block = kind == HMAC_SHA512 ? SHA512_BLOCK : SHA256_BLOCK;   /* SHA-1, SHA-256, MD5 all use 64 */
    size_t i;

    h->kind = kind;
    memset(k, 0, sizeof(k));
    if (keylen > block) {
        if (kind == HMAC_SHA512) sha512(key, keylen, k);
        else if (kind == HMAC_SHA1) { sha1_ctx t; sha1_init(&t); sha1_update(&t, key, keylen); sha1_final(&t, k); }
        else if (kind == HMAC_MD5) { md5_ctx t; md5_init(&t); md5_update(&t, key, keylen); md5_final(&t, k); }
        else sha256(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < block; i++) pad[i] = (u8)(k[i] ^ 0x36);
    switch (kind) {
    case HMAC_SHA512: sha512_init(&h->inner.s512); sha512_update(&h->inner.s512, pad, block); break;
    case HMAC_SHA1:   sha1_init(&h->inner.s1);     sha1_update(&h->inner.s1, pad, block);     break;
    case HMAC_MD5:    md5_init(&h->inner.m5);      md5_update(&h->inner.m5, pad, block);      break;
    default:          sha256_init(&h->inner.s256);  sha256_update(&h->inner.s256, pad, block); break;
    }
    for (i = 0; i < block; i++) pad[i] = (u8)(k[i] ^ 0x5c);
    switch (kind) {
    case HMAC_SHA512: sha512_init(&h->outer.s512); sha512_update(&h->outer.s512, pad, block); break;
    case HMAC_SHA1:   sha1_init(&h->outer.s1);     sha1_update(&h->outer.s1, pad, block);     break;
    case HMAC_MD5:    md5_init(&h->outer.m5);      md5_update(&h->outer.m5, pad, block);      break;
    default:          sha256_init(&h->outer.s256);  sha256_update(&h->outer.s256, pad, block); break;
    }
    ssh_wipe(k, sizeof(k));
    ssh_wipe(pad, sizeof(pad));
}

void hmac_update(hmac_ctx *h, const void *data, size_t len)
{
    switch (h->kind) {
    case HMAC_SHA512: sha512_update(&h->inner.s512, data, len); break;
    case HMAC_SHA1:   sha1_update(&h->inner.s1, data, len);     break;
    case HMAC_MD5:    md5_update(&h->inner.m5, data, len);      break;
    default:          sha256_update(&h->inner.s256, data, len); break;
    }
}

void hmac_final(hmac_ctx *h, u8 *out)
{
    u8 in[SHA512_DIGEST];
    switch (h->kind) {
    case HMAC_SHA512:
        sha512_final(&h->inner.s512, in);
        sha512_update(&h->outer.s512, in, SHA512_DIGEST);
        sha512_final(&h->outer.s512, out);
        break;
    case HMAC_SHA1:
        sha1_final(&h->inner.s1, in);
        sha1_update(&h->outer.s1, in, 20);
        sha1_final(&h->outer.s1, out);
        break;
    case HMAC_MD5:
        md5_final(&h->inner.m5, in);
        md5_update(&h->outer.m5, in, 16);
        md5_final(&h->outer.m5, out);
        break;
    default:
        sha256_final(&h->inner.s256, in);
        sha256_update(&h->outer.s256, in, SHA256_DIGEST);
        sha256_final(&h->outer.s256, out);
        break;
    }
    ssh_wipe(in, sizeof(in));
}

void hmac_sha256(const u8 *key, size_t klen, const void *data, size_t len, u8 out[32])
{
    hmac_ctx h;
    hmac_init(&h, HMAC_SHA256, key, klen);
    hmac_update(&h, data, len);
    hmac_final(&h, out);
}
