#ifndef SSH_MD5_H
#define SSH_MD5_H
#include "ssh_types.h"

/* MD5 is broken.  It exists only because traditional PEM private keys derive their
 * encryption key from the passphrase with it (OpenSSL's EVP_BytesToKey). */
typedef struct { u32 h[4]; u64 len; u8 buf[64]; u32 n; } md5_ctx;
void md5_init(md5_ctx *c);
void md5_update(md5_ctx *c, const void *data, size_t len);
void md5_final(md5_ctx *c, u8 out[16]);

#endif
