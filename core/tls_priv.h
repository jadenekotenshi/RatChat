/* tls_priv.h -- internals of the TLS 1.2 engine. Not for applications. */
#ifndef RC_TLS_PRIV_H
#define RC_TLS_PRIV_H

#include "tls.h"
#include "wire.h"
#include "tls_wire.h"
#include "tls_prf.h"
#include "tls_aead_gcm.h"
#include "tls_aead_chacha.h"
#include "x509.h"
#include "der.h"
#include "rsa.h"
#include "ecc.h"
#include "nacl.h"
#include "rng.h"
#include "sha2.h"

#define TLS_MAX_RECORD 16640    /* 2^14 plaintext, plus room for AEAD overhead (explicit nonce + tag) */
#define TLS_VERSION_MAJOR 3
#define TLS_VERSION_MINOR 3
#define TLS_AAD_LEN 13          /* seq_num(8) || type(1) || version(2) || length(2), RFC 5246 SS6.2.3.3 */

enum { CT_CHANGE_CIPHER_SPEC = 20, CT_ALERT = 21, CT_HANDSHAKE = 22, CT_APPLICATION_DATA = 23 };

enum {
    HS_CLIENT_HELLO = 1, HS_SERVER_HELLO = 2, HS_CERTIFICATE = 11, HS_SERVER_KEY_EXCHANGE = 12,
    HS_CERTIFICATE_REQUEST = 13, HS_SERVER_HELLO_DONE = 14, HS_CLIENT_KEY_EXCHANGE = 16,
    HS_FINISHED = 20
};

enum { AEAD_GCM = 1, AEAD_CHACHA = 2 };

/* the cipher suites we offer, in preference order -- see the TLS plan */
#define CS_ECDHE_RSA_AES128_GCM_SHA256   0xC02F
#define CS_ECDHE_ECDSA_AES128_GCM_SHA256 0xC02B
#define CS_ECDHE_RSA_CHACHA20_POLY1305   0xCCA8
#define CS_ECDHE_ECDSA_CHACHA20_POLY1305 0xCCA9

/* named groups (RFC 8422 / IANA TLS Supported Groups) we offer, X25519 preferred */
#define GROUP_SECP256R1 0x0017
#define GROUP_X25519    0x001d

typedef struct {
    int active;
    int aead_kind;               /* AEAD_GCM or AEAD_CHACHA, valid iff active */
    tls_gcm_ctx gcm;
    tls_chacha_ctx chacha;
    u64 seq;
} tls_dir;

enum {
    TLS_ST_INIT = 0, TLS_ST_WAIT_SH, TLS_ST_WAIT_CERT, TLS_ST_WAIT_CERT_ANSWER,
    TLS_ST_WAIT_SKE, TLS_ST_WAIT_SHD, TLS_ST_WAIT_CCS, TLS_ST_WAIT_FINISHED, TLS_ST_ESTABLISHED
};

typedef struct tls_evnode {
    tls_event ev;
    u8 *data;
    char *text, *text2;
    struct tls_evnode *next;
} tls_evnode;

struct tls_session {
    sbuf in, out;
    char *hostname;

    int state;
    int started, closed, fatal;

    sbuf hs_buf;                  /* reassembled handshake-message bytes, across record boundaries */
    sbuf transcript;              /* every handshake message's raw bytes, in order, for the Finished hash */

    int cipher_suite;             /* one of the CS_* values, once ServerHello arrives */
    int aead_kind;
    int group;                    /* GROUP_X25519 or GROUP_SECP256R1, once ServerKeyExchange arrives */
    u8 client_random[32], server_random[32];

    u8 x25519_priv[32];           /* our ephemeral ECDHE key: x25519_priv, or ec_priv/ec_pub -- only
                                    * the one matching `group` is meaningful */
    bn ec_priv;
    ec_point ec_pub;
    u8 ckx_point[133];            /* our own ECDHE public value, as sent in ClientKeyExchange --
                                    * computed once ServerKeyExchange arrives, sent once
                                    * ServerHelloDone does */
    size_t ckx_point_len;

    x509_cert cert;
    int cert_decided, cert_ok;
    int got_cert_request;         /* server sent CertificateRequest; we never have one to offer, but
                                    * RFC 5246 SS7.4.6 still requires an empty Certificate reply */

    u8 master_secret[48];
    tls_dir tx, rx;

    tls_evnode *ev_head, *ev_tail, *ev_cur;
};

void tls_fail(tls_session *s, const char *msg);
void tls_push_event(tls_session *s, int type, const u8 *data, size_t len, const char *text, const char *text2);

#endif
