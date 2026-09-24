#ifndef SSH_SHA2_H
#define SSH_SHA2_H
#include "ssh_types.h"

#define SHA256_DIGEST 32
#define SHA256_BLOCK  64
#define SHA512_DIGEST 64
#define SHA512_BLOCK  128
#define SHA384_DIGEST 48

typedef struct { u32 h[8]; u64 len; u8 buf[SHA256_BLOCK]; u32 n; } sha256_ctx;
typedef struct { u64 h[8]; u64 len; u8 buf[SHA512_BLOCK]; u32 n; } sha512_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, u8 out[SHA256_DIGEST]);
void sha256(const void *data, size_t len, u8 out[SHA256_DIGEST]);

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const void *data, size_t len);
void sha512_final(sha512_ctx *c, u8 out[SHA512_DIGEST]);
void sha512(const void *data, size_t len, u8 out[SHA512_DIGEST]);

/* SHA-384 is SHA-512 with a different IV and a truncated output. */
typedef sha512_ctx sha384_ctx;
void sha384_init(sha384_ctx *c);
void sha384_update(sha384_ctx *c, const void *data, size_t len);
void sha384_final(sha384_ctx *c, u8 out[SHA384_DIGEST]);
void sha384(const void *data, size_t len, u8 out[SHA384_DIGEST]);

#endif
