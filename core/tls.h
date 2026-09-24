/*
 * tls.h -- a sans-I/O TLS 1.2 client engine.
 *
 * Mirrors ssh.h's own shape directly: the engine never touches a socket. The application:
 *   1. feeds bytes it read from the network to tls_input(),
 *   2. sends whatever tls_output() exposes, then calls tls_output_done(),
 *   3. drains events with tls_next_event() after every call that can generate them.
 * All state lives in the tls_session, so the same engine drives a blocking test tool on the dev
 * host and the run-loop-driven AppKit app on OPENSTEP.
 *
 * Scope (see the TLS plan's "Explicit non-goals"): TLS 1.2 only, ECDHE key exchange only
 * (TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256 and the two ChaCha20-Poly1305 equivalents), no
 * renegotiation, no session resumption, no client certificates, no CA chain validation -- trust
 * is TOFU pinning of the leaf certificate (see TLS_EV_CERT and core/tls_pins.c).
 */
#ifndef RC_TLS_H
#define RC_TLS_H

#include "ssh_types.h"

typedef struct tls_session tls_session;

enum {
    TLS_EV_NONE = 0,
    TLS_EV_CERT,             /* data/len = the leaf certificate's raw DER; text = "SHA256:..."
                                fingerprint of those same DER bytes (the TOFU pin); text2 = the
                                subject CN, best-effort, "" if none. Reply with tls_cert_accept().
                                The handshake is paused until answered. */
    TLS_EV_HANDSHAKE_DONE,
    TLS_EV_DATA,              /* data/len = decrypted application data */
    TLS_EV_ERROR,             /* fatal; text = description. Session is dead. */
    TLS_EV_CLOSED             /* the peer sent close_notify; a clean shutdown, not an error */
};

typedef struct {
    int         type;
    const u8   *data;         /* valid until the next tls_next_event() */
    size_t      len;
    const char *text;
    const char *text2;
} tls_event;

/* ---- lifecycle ---- */
tls_session *tls_new(const char *hostname);      /* hostname is used for SNI (RFC 6066); a
                                                    * literal IPv4/IPv6 address skips SNI (Phase 8) */
void         tls_free(tls_session *s);
/* Queues the ClientHello. Fails if the RNG is not seeded (see rng.h). */
int          tls_start(tls_session *s);
/* Feed received bytes. Returns 0, or -1 if the session died (an ERROR event was queued). */
int          tls_input(tls_session *s, const u8 *data, size_t len);
const u8    *tls_output(tls_session *s, size_t *len);
void         tls_output_done(tls_session *s, size_t n);
int          tls_next_event(tls_session *s, tls_event *ev);
int          tls_is_closed(const tls_session *s);
int          tls_is_established(const tls_session *s);
/* Sends a close_notify alert and marks the session closed. */
void         tls_close(tls_session *s);

/* ---- certificate trust (call after TLS_EV_CERT) ---- */
void         tls_cert_accept(tls_session *s, int accept);

/* ---- application data (only once TLS_EV_HANDSHAKE_DONE has fired) ---- */
/* Queues len bytes of plaintext to be encrypted into tls_output(); returns 0, or -1 if the
 * handshake isn't done yet or the session is closed. */
int          tls_write(tls_session *s, const u8 *data, size_t len);

/* Negotiated cipher suite name, for display; "none" before the handshake completes. */
const char  *tls_cipher_name(const tls_session *s);

#endif
