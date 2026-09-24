#ifndef SSH_SHA1_H
#define SSH_SHA1_H
#include "ssh_types.h"

/* SHA-1 is broken for signatures.  It is here only to read hashed known_hosts
 * entries (HMAC-SHA1 of the host name) written by OpenSSH. */
typedef struct { u32 h[5]; u64 len; u8 buf[64]; u32 n; } sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const void *data, size_t len);
void sha1_final(sha1_ctx *c, u8 out[20]);
void hmac_sha1(const u8 *key, size_t klen, const void *data, size_t len, u8 out[20]);

#endif
