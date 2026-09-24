#ifndef SSH_NACL_H
#define SSH_NACL_H
#include "ssh_types.h"

/* X25519 (RFC 7748) */
void x25519(u8 out[32], const u8 scalar[32], const u8 point[32]);
void x25519_base(u8 out[32], const u8 scalar[32]);

/* Ed25519 (RFC 8032).  sk is seed(32) || pk(32). */
void ed25519_keypair(u8 pk[32], u8 sk[64], const u8 seed[32]);
void ed25519_sign(u8 sig[64], const u8 *msg, size_t len, const u8 sk[64]);
int  ed25519_verify(const u8 sig[64], const u8 *msg, size_t len, const u8 pk[32]);

#endif
