/*
 * tls_pins.h -- TOFU (trust-on-first-use) pinning of a TLS leaf certificate's whole DER, by
 * SHA-256. Mirrors core/knownhosts.h's exact model for SSH host keys -- "is this the same server
 * identity I trusted before," not "is this transitively trusted by a CA" -- but with its own
 * simpler storage format: one line per pin, "host port sha256-hex\n". No OpenSSH compatibility
 * requirement here (no hashed/wildcard host patterns, no key-type field -- there's only ever one
 * thing pinned per host:port).
 */
#ifndef RC_TLS_PINS_H
#define RC_TLS_PINS_H
#include "ssh_types.h"

enum { TLSPIN_UNKNOWN = 0, TLSPIN_MATCH = 1, TLSPIN_CHANGED = 2 };

/* Looks the pin up (case-insensitive on the host). TLSPIN_CHANGED means host:port is pinned to a
 * *different* certificate than der/der_len: treat as a possible attack, same as
 * knownhosts.h's KH_CHANGED. */
int tlspin_check(const char *path, const char *host, int port, const u8 *der, size_t der_len);
/* Appends a new pin. Returns 0 on success. The file is created with mode 0600. Does not remove
 * any existing (now-stale) pin for the same host:port -- tlspin_check() keeps scanning past a
 * CHANGED hit looking for a later match, the same way kh_check() does, so a fresh tlspin_add()
 * right after the user accepts a changed certificate is enough to make future checks match
 * again without needing to edit the file. */
int tlspin_add(const char *path, const char *host, int port, const u8 *der, size_t der_len);

#endif
