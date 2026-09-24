/*
 * tls_wire.h -- TLS's own length-prefixed vector conventions (RFC 5246 SS4.3-4.4): 1 byte
 * (session_id, compression_methods), 2 bytes (cipher_suites, extensions, most extension bodies),
 * and 3 bytes ("uint24" -- the handshake message length, and the certificate list). None of
 * these are widths StepSSH's own wire.c speaks, since every SSH wire construct is either a
 * 4-byte length (sb_put_str/sr_str) or one of the fixed-width ints it reads directly. Built as a
 * new file on top of wire.h's sbuf/sreader rather than added into wire.c itself, so wire.c stays
 * byte-diffable against StepSSH's original.
 */
#ifndef RC_TLS_WIRE_H
#define RC_TLS_WIRE_H

#include "ssh_types.h"
#include "wire.h"

int tls_put_u16(sbuf *b, u32 v);
int tls_put_u24(sbuf *b, u32 v);

/* Writes the length prefix (of the given width) followed by n raw bytes. */
int tls_put_vec8(sbuf *b, const u8 *d, size_t n);
int tls_put_vec16(sbuf *b, const u8 *d, size_t n);
int tls_put_vec24(sbuf *b, const u8 *d, size_t n);

u32 tls_get_u16(sreader *r);
u32 tls_get_u24(sreader *r);

/* Reads a length prefix (of the given width), then borrows that many bytes from the reader's
 * own buffer -- same no-copy convention as sr_str/sr_bytes. NULL (with *len set to 0) on
 * truncation; once a reader has failed once it keeps failing (sreader's own sticky-error rule),
 * so these compose safely without their own extra bounds checks. */
const u8 *tls_get_vec8(sreader *r, size_t *len);
const u8 *tls_get_vec16(sreader *r, size_t *len);
const u8 *tls_get_vec24(sreader *r, size_t *len);

#endif
