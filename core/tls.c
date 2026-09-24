#include "tls_priv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long)0xffffffff)
#endif

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static char *xstrdup(const char *str)
{
    size_t n = strlen(str) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, str, n);
    return p;
}

static void free_evnode(tls_evnode *n)
{
    if (!n) return;
    if (n->data) { ssh_wipe(n->data, n->ev.len); free(n->data); }
    free(n->text);
    free(n->text2);
    free(n);
}

void tls_push_event(tls_session *s, int type, const u8 *data, size_t len, const char *text, const char *text2)
{
    tls_evnode *n = (tls_evnode *)calloc(1, sizeof(*n));
    if (!n) return;
    n->ev.type = type; n->ev.len = len;
    if (data && len) {
        n->data = (u8 *)malloc(len);
        if (!n->data) { free(n); return; }
        memcpy(n->data, data, len);
    }
    if (text) n->text = xstrdup(text);
    if (text2) n->text2 = xstrdup(text2);
    n->ev.data = n->data;
    n->ev.text = n->text ? n->text : "";
    n->ev.text2 = n->text2 ? n->text2 : "";
    if (s->ev_tail) s->ev_tail->next = n; else s->ev_head = n;
    s->ev_tail = n;
}

int tls_next_event(tls_session *s, tls_event *ev)
{
    tls_evnode *n;
    if (s->ev_cur) { free_evnode(s->ev_cur); s->ev_cur = NULL; }
    n = s->ev_head;
    if (!n) return 0;
    s->ev_head = n->next;
    if (!s->ev_head) s->ev_tail = NULL;
    s->ev_cur = n;
    *ev = n->ev;
    return 1;
}

/* ------------------------------------------------------------------ */
/* record layer: send                                                  */
/* ------------------------------------------------------------------ */

static void build_aad(u8 aad[TLS_AAD_LEN], u64 seq, u8 type, u32 plen)
{
    STORE64_BE(aad, seq);
    aad[8] = type;
    aad[9] = TLS_VERSION_MAJOR; aad[10] = TLS_VERSION_MINOR;
    aad[11] = (u8)(plen >> 8); aad[12] = (u8)plen;
}

/* Frames and (once tx is active) encrypts pt/pt_len as one record, appending it to s->out. Every
 * outgoing unit -- handshake messages, ChangeCipherSpec, alerts, application data -- goes
 * through this. */
static int send_record(tls_session *s, int content_type, const u8 *pt, size_t pt_len)
{
    u8 aad[TLS_AAD_LEN];
    size_t body_len, total;
    u8 *rec;

    if (s->closed) return -1;

    if (!s->tx.active) {
        if (sb_reserve(&s->out, 5 + pt_len) < 0) { tls_fail(s, "out of memory"); return -1; }
        rec = s->out.p + s->out.len;
        rec[0] = (u8)content_type; rec[1] = TLS_VERSION_MAJOR; rec[2] = TLS_VERSION_MINOR;
        rec[3] = (u8)(pt_len >> 8); rec[4] = (u8)pt_len;
        memcpy(rec + 5, pt, pt_len);
        s->out.len += 5 + pt_len;
        return 0;
    }

    body_len = pt_len + (s->tx.aead_kind == AEAD_GCM ? TLS_GCM_EXPLICIT_NONCE_LEN + TLS_GCM_TAG_LEN : TLS_CHACHA_TAG_LEN);
    total = 5 + body_len;
    build_aad(aad, s->tx.seq, (u8)content_type, (u32)pt_len);
    if (sb_reserve(&s->out, total) < 0) { tls_fail(s, "out of memory"); return -1; }
    rec = s->out.p + s->out.len;
    rec[0] = (u8)content_type; rec[1] = TLS_VERSION_MAJOR; rec[2] = TLS_VERSION_MINOR;
    rec[3] = (u8)(body_len >> 8); rec[4] = (u8)body_len;

    if (s->tx.aead_kind == AEAD_GCM) {
        STORE64_BE(rec + 5, s->tx.seq);
        tls_gcm_seal(&s->tx.gcm, s->tx.seq, aad, TLS_AAD_LEN, pt, rec + 5 + TLS_GCM_EXPLICIT_NONCE_LEN, pt_len);
    } else if (tls_chacha_seal(&s->tx.chacha, s->tx.seq, aad, TLS_AAD_LEN, pt, rec + 5, pt_len) != 0) {
        tls_fail(s, "out of memory");
        return -1;
    }
    s->out.len += total;
    s->tx.seq++;
    return 0;
}

static void send_alert(tls_session *s, u8 level, u8 desc)
{
    u8 a[2];
    a[0] = level; a[1] = desc;
    send_record(s, CT_ALERT, a, 2);
}

void tls_fail(tls_session *s, const char *msg)
{
    if (s->closed) return;
    s->closed = 1;
    s->fatal = 1;
    tls_push_event(s, TLS_EV_ERROR, NULL, 0, msg, NULL);
    if (s->started) send_alert(s, 2, 40);             /* fatal, handshake_failure -- best effort */
}

/* Builds a handshake message (1-byte type + 3-byte length + body), appends its raw bytes to the
 * transcript (every message except the peer's Finished uses this -- see drain_handshake for
 * why that one is special), and sends it as a Handshake record. */
static int send_handshake(tls_session *s, int hs_type, const u8 *body, size_t body_len)
{
    u8 *msg;
    int rc;
    if (body_len > 0xffffff) { tls_fail(s, "outgoing handshake message too large"); return -1; }
    msg = (u8 *)malloc(4 + body_len);
    if (!msg) { tls_fail(s, "out of memory"); return -1; }
    msg[0] = (u8)hs_type;
    msg[1] = (u8)(body_len >> 16); msg[2] = (u8)(body_len >> 8); msg[3] = (u8)body_len;
    if (body_len) memcpy(msg + 4, body, body_len);
    if (sb_put(&s->transcript, msg, 4 + body_len) < 0) { tls_fail(s, "out of memory"); free(msg); return -1; }
    rc = send_record(s, CT_HANDSHAKE, msg, 4 + body_len);
    free(msg);
    return rc;
}

/* ------------------------------------------------------------------ */
/* ClientHello                                                         */
/* ------------------------------------------------------------------ */

/* RFC 6066 SS3: SNI names a host, not an address -- there is nothing meaningful to send when the
 * Server field the caller connected to was itself a literal IPv4 address (IRCConnection.m's own
 * connectToHost:...  already makes exactly this same inet_addr()/INADDR_NONE distinction to
 * decide whether to skip gethostbyname(); this engine makes it again independently rather than
 * depend on the caller telling it, since a sans-I/O engine that only ever sees `hostname` as a
 * plain string is the one thing that should stay self-contained here). IPv6 literals are not a
 * concern anywhere else in this project family either. */
static int is_ip_literal(const char *host)
{
    return inet_addr(host) != INADDR_NONE;
}

static int build_client_hello(tls_session *s)
{
    sbuf b, extb;
    int rc;

    if (ssh_rng_bytes(s->client_random, 32) != 0) {
        tls_fail(s, "not enough entropy to start a secure session");
        return -1;
    }

    sb_init(&b);
    sb_put_u8(&b, TLS_VERSION_MAJOR); sb_put_u8(&b, TLS_VERSION_MINOR);
    sb_put(&b, s->client_random, 32);
    sb_put_u8(&b, 0);                                  /* session_id: empty */

    tls_put_u16(&b, 8);                                /* cipher_suites: 4 * 2 bytes */
    tls_put_u16(&b, CS_ECDHE_RSA_AES128_GCM_SHA256);
    tls_put_u16(&b, CS_ECDHE_ECDSA_AES128_GCM_SHA256);
    tls_put_u16(&b, CS_ECDHE_RSA_CHACHA20_POLY1305);
    tls_put_u16(&b, CS_ECDHE_ECDSA_CHACHA20_POLY1305);

    sb_put_u8(&b, 1); sb_put_u8(&b, 0);                /* compression_methods: [null] */

    sb_init(&extb);
    if (s->hostname && s->hostname[0] && !is_ip_literal(s->hostname)) {
        size_t hlen = strlen(s->hostname);
        tls_put_u16(&extb, 0x0000);                    /* server_name */
        tls_put_u16(&extb, (u32)(2 + 1 + 2 + hlen));
        tls_put_u16(&extb, (u32)(1 + 2 + hlen));
        sb_put_u8(&extb, 0);                           /* name_type: host_name */
        tls_put_vec16(&extb, (const u8 *)s->hostname, hlen);
    }
    tls_put_u16(&extb, 0x000a);                        /* supported_groups */
    tls_put_u16(&extb, 6);
    tls_put_u16(&extb, 4);
    tls_put_u16(&extb, GROUP_X25519);
    tls_put_u16(&extb, GROUP_SECP256R1);

    tls_put_u16(&extb, 0x000d);                        /* signature_algorithms */
    tls_put_u16(&extb, 8);
    tls_put_u16(&extb, 6);
    tls_put_u16(&extb, 0x0401);                        /* rsa_pkcs1_sha256 */
    tls_put_u16(&extb, 0x0403);                        /* ecdsa + sha256 */
    tls_put_u16(&extb, 0x0503);                        /* ecdsa + sha384 */

    tls_put_u16(&extb, 0x000b);                        /* ec_point_formats */
    tls_put_u16(&extb, 2);
    sb_put_u8(&extb, 1);
    sb_put_u8(&extb, 0);                               /* uncompressed only */

    tls_put_u16(&extb, 0xff01);                        /* renegotiation_info, empty */
    tls_put_u16(&extb, 1);
    sb_put_u8(&extb, 0);

    if (b.oom || extb.oom) { tls_fail(s, "out of memory"); sb_free(&b); sb_free(&extb); return -1; }

    tls_put_u16(&b, (u32)extb.len);
    sb_put(&b, extb.p, extb.len);
    sb_free(&extb);

    if (b.oom) { tls_fail(s, "out of memory"); sb_free(&b); return -1; }
    rc = send_handshake(s, HS_CLIENT_HELLO, b.p, b.len);
    sb_free(&b);
    return rc;
}

/* ------------------------------------------------------------------ */
/* key derivation                                                      */
/* ------------------------------------------------------------------ */

/* RFC 5246 SS8.1/SS6.3: master_secret, then the key_block. Installs both directions' AEAD
 * contexts, but leaves tx/rx `active` untouched -- the caller flips those at the exact protocol
 * moments (our own ChangeCipherSpec for tx, the peer's for rx), never here. */
static void derive_keys(tls_session *s, const u8 *premaster, size_t premaster_len)
{
    u8 seed[64];
    u8 key_block[88];
    size_t need;
    const u8 *p = key_block;

    memcpy(seed, s->client_random, 32);
    memcpy(seed + 32, s->server_random, 32);
    tls_prf(premaster, premaster_len, "master secret", seed, 64, s->master_secret, 48);

    memcpy(seed, s->server_random, 32);
    memcpy(seed + 32, s->client_random, 32);
    need = s->aead_kind == AEAD_GCM ? 40 : 88;
    tls_prf(s->master_secret, 48, "key expansion", seed, 64, key_block, need);

    if (s->aead_kind == AEAD_GCM) {
        tls_gcm_init(&s->tx.gcm, p, 16, p + 32);
        tls_gcm_init(&s->rx.gcm, p + 16, 16, p + 36);
    } else {
        tls_chacha_init(&s->tx.chacha, p, p + 64);
        tls_chacha_init(&s->rx.chacha, p + 32, p + 76);
    }
    s->tx.aead_kind = s->rx.aead_kind = s->aead_kind;
    ssh_wipe(key_block, sizeof(key_block));
    ssh_wipe(seed, sizeof(seed));
}

/* ------------------------------------------------------------------ */
/* handshake message handlers (dispatched by drain_handshake)          */
/* ------------------------------------------------------------------ */

static int handle_server_hello(tls_session *s, const u8 *body, size_t len)
{
    sreader r;
    u32 ver, cs, ext_len;
    const u8 *rand;
    size_t sess_id_len;
    u8 comp_method;
    static const u32 offered[4] = {
        CS_ECDHE_RSA_AES128_GCM_SHA256, CS_ECDHE_ECDSA_AES128_GCM_SHA256,
        CS_ECDHE_RSA_CHACHA20_POLY1305, CS_ECDHE_ECDSA_CHACHA20_POLY1305
    };
    int i, found;

    if (s->state != TLS_ST_WAIT_SH) { tls_fail(s, "unexpected ServerHello"); return -1; }

    sr_init(&r, body, len);
    ver = tls_get_u16(&r);
    rand = sr_bytes(&r, 32);
    tls_get_vec8(&r, &sess_id_len);
    cs = tls_get_u16(&r);
    comp_method = sr_u8(&r);
    if (r.err || !rand) { tls_fail(s, "truncated ServerHello"); return -1; }
    if (ver != 0x0303) { tls_fail(s, "server does not speak TLS 1.2"); return -1; }
    if (comp_method != 0) { tls_fail(s, "server picked a non-null compression method"); return -1; }

    found = 0;
    for (i = 0; i < 4; i++) if (offered[i] == cs) { found = 1; break; }
    if (!found) { tls_fail(s, "server picked a cipher suite we did not offer"); return -1; }

    if (sr_left(&r) > 0) {                             /* extensions, present or not: skip, bounds-checked */
        ext_len = tls_get_u16(&r);
        sr_bytes(&r, ext_len);
    }
    if (r.err) { tls_fail(s, "truncated ServerHello"); return -1; }

    memcpy(s->server_random, rand, 32);
    s->cipher_suite = (int)cs;
    s->aead_kind = (cs == CS_ECDHE_RSA_AES128_GCM_SHA256 || cs == CS_ECDHE_ECDSA_AES128_GCM_SHA256) ? AEAD_GCM : AEAD_CHACHA;
    s->state = TLS_ST_WAIT_CERT;
    return 0;
}

static int handle_certificate(tls_session *s, const u8 *body, size_t len)
{
    sreader r, lr;
    const u8 *list, *first_cert;
    size_t list_len, first_cert_len;
    const char *err;
    u8 fp[32];
    static const char hexd[] = "0123456789ABCDEF";
    char fptext[80];
    int i, need_rsa;

    if (s->state != TLS_ST_WAIT_CERT) { tls_fail(s, "unexpected Certificate"); return -1; }

    sr_init(&r, body, len);
    list = tls_get_vec24(&r, &list_len);
    if (!list || r.err) { tls_fail(s, "truncated Certificate"); return -1; }
    sr_init(&lr, list, list_len);
    first_cert = tls_get_vec24(&lr, &first_cert_len);
    if (!first_cert || lr.err) { tls_fail(s, "empty certificate list"); return -1; }

    if (x509_parse_leaf(first_cert, first_cert_len, &s->cert, &err) != 0) { tls_fail(s, err); return -1; }

    need_rsa = s->cipher_suite == CS_ECDHE_RSA_AES128_GCM_SHA256 || s->cipher_suite == CS_ECDHE_RSA_CHACHA20_POLY1305;
    if ((need_rsa && s->cert.key_type != X509_KEY_RSA) || (!need_rsa && s->cert.key_type != X509_KEY_EC)) {
        tls_fail(s, "certificate key type does not match the negotiated cipher suite");
        return -1;
    }

    sha256(first_cert, first_cert_len, fp);
    strcpy(fptext, "SHA256:");
    for (i = 0; i < 32; i++) {
        fptext[7 + i * 2] = hexd[fp[i] >> 4];
        fptext[7 + i * 2 + 1] = hexd[fp[i] & 0xf];
    }
    fptext[7 + 64] = '\0';

    tls_push_event(s, TLS_EV_CERT, first_cert, first_cert_len, fptext, s->cert.cn);
    s->state = TLS_ST_WAIT_CERT_ANSWER;
    return 0;
}

static int handle_server_key_exchange(tls_session *s, const u8 *body, size_t len)
{
    sreader r;
    u8 curve_type;
    u32 named_curve;
    const u8 *point, *params_start, *sig;
    size_t point_len, params_len, sig_len;
    u32 sig_alg;
    u8 msg[256];
    int verified;

    if (s->state != TLS_ST_WAIT_SKE) { tls_fail(s, "unexpected ServerKeyExchange"); return -1; }

    sr_init(&r, body, len);
    params_start = body;
    curve_type = sr_u8(&r);
    named_curve = tls_get_u16(&r);
    point = tls_get_vec8(&r, &point_len);
    if (r.err || curve_type != 3) { tls_fail(s, "unsupported or truncated ServerKeyExchange curve params"); return -1; }
    if (named_curve != GROUP_X25519 && named_curve != GROUP_SECP256R1) {
        tls_fail(s, "server picked a key-exchange group we did not offer");
        return -1;
    }
    params_len = (size_t)(body + r.pos - params_start);

    sig_alg = tls_get_u16(&r);
    sig = tls_get_vec16(&r, &sig_len);
    if (r.err || !sig) { tls_fail(s, "truncated ServerKeyExchange signature"); return -1; }

    if (64 + params_len > sizeof(msg)) { tls_fail(s, "ServerKeyExchange params too large"); return -1; }
    memcpy(msg, s->client_random, 32);
    memcpy(msg + 32, s->server_random, 32);
    memcpy(msg + 64, params_start, params_len);

    if (s->cert.key_type == X509_KEY_RSA) {
        if (sig_alg != 0x0401) { tls_fail(s, "unexpected signature algorithm"); return -1; }
        verified = rsa_verify(&s->cert.rsa, RSA_SHA256, msg, 64 + params_len, sig, sig_len) == 0;
    } else {
        const ec_curve *c;
        u8 digest[64];
        size_t digest_len;
        bn sr_, ss_;
        if (sig_alg == 0x0403) { sha256(msg, 64 + params_len, digest); digest_len = 32; }
        else if (sig_alg == 0x0503) { sha384(msg, 64 + params_len, digest); digest_len = 48; }
        else { tls_fail(s, "unexpected signature algorithm"); return -1; }
        c = ec_curve_get(s->cert.curve);
        bn_init(&sr_); bn_init(&ss_);
        verified = c != NULL && der_ecdsa_sig(sig, sig_len, &sr_, &ss_) == 0 &&
                   ecdsa_verify(c, &s->cert.ec_pub, digest, digest_len, &sr_, &ss_) == 0;
        bn_free(&sr_); bn_free(&ss_);
    }
    if (!verified) { tls_fail(s, "ServerKeyExchange signature verification failed"); return -1; }

    s->group = (int)named_curve;
    if (s->group == GROUP_X25519) {
        u8 shared[32], pub[32];
        if (point_len != 32) { tls_fail(s, "bad x25519 point"); return -1; }
        if (ssh_rng_bytes(s->x25519_priv, 32) != 0) { tls_fail(s, "not enough entropy"); return -1; }
        x25519_base(pub, s->x25519_priv);
        x25519(shared, s->x25519_priv, point);
        derive_keys(s, shared, 32);
        memcpy(s->ckx_point, pub, 32);
        s->ckx_point_len = 32;
        ssh_wipe(shared, sizeof(shared));
    } else {
        const ec_curve *c = ec_curve_get(EC_P256);
        ec_point peer;
        u8 shared[48];
        ec_point_init(&peer);
        if (!c || ec_decode_point(c, point, point_len, &peer) != 0 ||
            ec_random_scalar(c, &s->ec_priv) != 0 || ec_mul_base(c, &s->ec_pub, &s->ec_priv) != 0 ||
            ecdh_shared(c, &s->ec_priv, &peer, shared) != 0) {
            ec_point_free(&peer);
            tls_fail(s, "ECDHE key agreement failed");
            return -1;
        }
        ec_point_free(&peer);
        derive_keys(s, shared, (size_t)c->nbytes);
        ec_encode_point(c, &s->ec_pub, s->ckx_point);
        s->ckx_point_len = (size_t)(1 + 2 * c->nbytes);
        ssh_wipe(shared, sizeof(shared));
    }

    s->state = TLS_ST_WAIT_SHD;
    return 0;
}

/* ServerHelloDone triggers our entire response flight in one go: ClientKeyExchange (still in the
 * clear), ChangeCipherSpec (always in the clear; flips tx to encrypted immediately after), then
 * Finished -- genuinely the first record encrypted under the new keys, not just labeled as such. */
static int handle_server_hello_done(tls_session *s, const u8 *body, size_t len)
{
    u8 ckx_body[134];
    u8 hash[32], verify_data[12];
    u8 ccs = 1;

    if (s->state != TLS_ST_WAIT_SHD) { tls_fail(s, "unexpected ServerHelloDone"); return -1; }
    if (len != 0) { tls_fail(s, "malformed ServerHelloDone"); return -1; }
    (void)body;

    ckx_body[0] = (u8)s->ckx_point_len;
    memcpy(ckx_body + 1, s->ckx_point, s->ckx_point_len);
    if (send_handshake(s, HS_CLIENT_KEY_EXCHANGE, ckx_body, 1 + s->ckx_point_len) != 0) return -1;

    if (send_record(s, CT_CHANGE_CIPHER_SPEC, &ccs, 1) != 0) return -1;
    s->tx.active = 1;
    s->tx.seq = 0;

    sha256(s->transcript.p, s->transcript.len, hash);
    tls_prf(s->master_secret, 48, "client finished", hash, 32, verify_data, 12);
    if (send_handshake(s, HS_FINISHED, verify_data, 12) != 0) return -1;

    s->state = TLS_ST_WAIT_CCS;
    return 0;
}

static int handle_finished(tls_session *s, const u8 *body, size_t len)
{
    u8 hash[32], expected[12];

    if (s->state != TLS_ST_WAIT_FINISHED) { tls_fail(s, "unexpected Finished"); return -1; }
    if (len != 12) { tls_fail(s, "malformed Finished"); return -1; }

    sha256(s->transcript.p, s->transcript.len, hash);
    tls_prf(s->master_secret, 48, "server finished", hash, 32, expected, 12);
    if (ssh_ct_memcmp(expected, body, 12) != 0) { tls_fail(s, "Finished verification failed"); return -1; }

    s->state = TLS_ST_ESTABLISHED;
    tls_push_event(s, TLS_EV_HANDSHAKE_DONE, NULL, 0, NULL, NULL);
    return 0;
}

/* Drains complete handshake messages (4-byte header: 1-byte type + 3-byte length) from hs_buf,
 * which may hold bytes reassembled across several records, several coalesced messages from one
 * record, or both. Stops (without error) while a TLS_EV_CERT answer is pending; tls_cert_accept()
 * re-invokes this to resume exactly where it left off. */
static int drain_handshake(tls_session *s)
{
    while (!s->closed && s->state != TLS_ST_WAIT_CERT_ANSWER && s->hs_buf.len >= 4) {
        u8 type = s->hs_buf.p[0];
        u32 body_len = ((u32)s->hs_buf.p[1] << 16) | ((u32)s->hs_buf.p[2] << 8) | s->hs_buf.p[3];
        size_t total = 4 + (size_t)body_len;
        const u8 *body;
        int rc;

        if (s->hs_buf.len < total) break;

        /* The transcript hash used to verify the peer's own Finished must not include that
         * Finished message itself (RFC 5246 SS7.4.9) -- every other message is appended before
         * its handler runs; Finished is appended only after a successful verify. */
        if (type != HS_FINISHED && sb_put(&s->transcript, s->hs_buf.p, total) < 0) {
            tls_fail(s, "out of memory");
            return -1;
        }
        body = s->hs_buf.p + 4;

        switch (type) {
        case HS_SERVER_HELLO:        rc = handle_server_hello(s, body, body_len); break;
        case HS_CERTIFICATE:         rc = handle_certificate(s, body, body_len); break;
        case HS_SERVER_KEY_EXCHANGE: rc = handle_server_key_exchange(s, body, body_len); break;
        case HS_SERVER_HELLO_DONE:   rc = handle_server_hello_done(s, body, body_len); break;
        case HS_FINISHED:            rc = handle_finished(s, body, body_len); break;
        default: tls_fail(s, "unexpected handshake message type"); rc = -1; break;
        }

        if (type == HS_FINISHED && rc == 0 && sb_put(&s->transcript, s->hs_buf.p, total) < 0) {
            tls_fail(s, "out of memory");
            rc = -1;
        }

        sb_consume(&s->hs_buf, total);
        if (rc < 0) return -1;
    }
    return 0;
}

void tls_cert_accept(tls_session *s, int accept)
{
    if (s->cert_decided || s->closed) return;
    s->cert_decided = 1;
    s->cert_ok = accept ? 1 : 0;
    if (!accept) {
        s->closed = 1;
        s->fatal = 1;
        send_alert(s, 2, 46);                          /* fatal, certificate_unknown */
        tls_push_event(s, TLS_EV_ERROR, NULL, 0, "certificate rejected", NULL);
        return;
    }
    if (s->state == TLS_ST_WAIT_CERT_ANSWER) {
        s->state = TLS_ST_WAIT_SKE;
        drain_handshake(s);
    }
}

/* ------------------------------------------------------------------ */
/* record layer: receive                                               */
/* ------------------------------------------------------------------ */

static int handle_change_cipher_spec(tls_session *s, const u8 *content, size_t len)
{
    if (s->state != TLS_ST_WAIT_CCS) { tls_fail(s, "unexpected ChangeCipherSpec"); return -1; }
    if (len != 1 || content[0] != 1) { tls_fail(s, "malformed ChangeCipherSpec"); return -1; }
    s->rx.active = 1;
    s->rx.seq = 0;
    s->state = TLS_ST_WAIT_FINISHED;
    return 0;
}

/* RFC 5246 SS7.2: names for the AlertDescription values a peer might actually send us (the ones
 * this engine's own narrow scope can provoke or receive); anything else falls back to its raw
 * numeric value rather than guessing at a name that might be wrong. */
static const char *alert_desc_name(u8 d)
{
    switch (d) {
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 22: return "record_overflow";
    case 40: return "handshake_failure";
    case 42: return "bad_certificate";
    case 43: return "unsupported_certificate";
    case 44: return "certificate_revoked";
    case 45: return "certificate_expired";
    case 46: return "certificate_unknown";
    case 47: return "illegal_parameter";
    case 48: return "unknown_ca";
    case 49: return "access_denied";
    case 50: return "decode_error";
    case 51: return "decrypt_error";
    case 70: return "protocol_version";
    case 71: return "insufficient_security";
    case 80: return "internal_error";
    case 90: return "user_canceled";
    case 110: return "unsupported_extension";
    default: return NULL;
    }
}

static int handle_alert(tls_session *s, const u8 *content, size_t len)
{
    char msg[64];
    const char *name;
    if (len != 2) { tls_fail(s, "malformed alert"); return -1; }
    if (content[1] == 0) {                             /* close_notify: a clean shutdown */
        tls_push_event(s, TLS_EV_CLOSED, NULL, 0, NULL, NULL);
        s->closed = 1;
        return 0;
    }
    name = alert_desc_name(content[1]);
    if (name) sprintf(msg, "peer sent a fatal alert: %s", name);
    else sprintf(msg, "peer sent a fatal alert (%d)", content[1]);
    tls_fail(s, msg);
    return -1;
}

static int process_plaintext_record(tls_session *s, u8 type, const u8 *content, size_t len)
{
    switch (type) {
    case CT_HANDSHAKE:
        if (sb_put(&s->hs_buf, content, len) < 0) { tls_fail(s, "out of memory"); return -1; }
        return drain_handshake(s);
    case CT_CHANGE_CIPHER_SPEC:
        return handle_change_cipher_spec(s, content, len);
    case CT_ALERT:
        return handle_alert(s, content, len);
    case CT_APPLICATION_DATA:
        if (s->state != TLS_ST_ESTABLISHED) { tls_fail(s, "unexpected application data"); return -1; }
        tls_push_event(s, TLS_EV_DATA, content, len, NULL, NULL);
        return 0;
    default:
        tls_fail(s, "unknown TLS record content type");
        return -1;
    }
}

/* Returns 1 if a complete record was consumed, 0 if more input is needed, -1 on a fatal error
 * (the session is already marked failed by then). Handles both of TLS's independent framing
 * layers together with process_plaintext_record()/drain_handshake(): this one only ever needs to
 * know "do I have a whole record yet," regardless of how the caller's TCP reads happened to chunk
 * the bytes it was handed. */
static int process_one_record(tls_session *s)
{
    u8 type;
    u32 rec_len;
    size_t total;
    const u8 *content;
    u8 aad[TLS_AAD_LEN];
    int rc;

    if (s->in.len < 5) return 0;
    type = s->in.p[0];
    rec_len = ((u32)s->in.p[3] << 8) | s->in.p[4];
    if (rec_len > TLS_MAX_RECORD) { tls_fail(s, "oversized TLS record"); return -1; }
    total = 5 + (size_t)rec_len;
    if (s->in.len < total) return 0;
    content = s->in.p + 5;

    if (!s->rx.active) {
        rc = process_plaintext_record(s, type, content, rec_len);
    } else if (s->rx.aead_kind == AEAD_GCM) {
        u8 buf[TLS_MAX_RECORD];
        u64 nonce_seq;
        size_t ct_len;
        if (rec_len < TLS_GCM_EXPLICIT_NONCE_LEN + TLS_GCM_TAG_LEN) { tls_fail(s, "truncated GCM record"); return -1; }
        nonce_seq = LOAD64_BE(content);
        ct_len = rec_len - TLS_GCM_EXPLICIT_NONCE_LEN - TLS_GCM_TAG_LEN;
        build_aad(aad, s->rx.seq, type, (u32)ct_len);
        if (tls_gcm_open(&s->rx.gcm, nonce_seq, aad, TLS_AAD_LEN, content + TLS_GCM_EXPLICIT_NONCE_LEN, buf, ct_len) != 0) {
            tls_fail(s, "bad record MAC");
            return -1;
        }
        s->rx.seq++;
        rc = process_plaintext_record(s, type, buf, ct_len);
    } else {
        u8 buf[TLS_MAX_RECORD];
        size_t ct_len;
        if (rec_len < TLS_CHACHA_TAG_LEN) { tls_fail(s, "truncated ChaCha20-Poly1305 record"); return -1; }
        ct_len = rec_len - TLS_CHACHA_TAG_LEN;
        build_aad(aad, s->rx.seq, type, (u32)ct_len);
        if (tls_chacha_open(&s->rx.chacha, s->rx.seq, aad, TLS_AAD_LEN, content, buf, ct_len) != 0) {
            tls_fail(s, "bad record MAC");
            return -1;
        }
        s->rx.seq++;
        rc = process_plaintext_record(s, type, buf, ct_len);
    }

    sb_consume(&s->in, total);
    return rc < 0 ? -1 : 1;
}

/* ------------------------------------------------------------------ */
/* lifecycle / public API                                              */
/* ------------------------------------------------------------------ */

tls_session *tls_new(const char *hostname)
{
    tls_session *s = (tls_session *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    sb_init(&s->in); sb_init(&s->out); sb_init(&s->hs_buf); sb_init(&s->transcript);
    s->hostname = xstrdup(hostname ? hostname : "");
    x509_cert_init(&s->cert);
    ec_point_init(&s->ec_pub);
    bn_init(&s->ec_priv);
    return s;
}

void tls_free(tls_session *s)
{
    tls_evnode *n, *nx;
    if (!s) return;
    for (n = s->ev_head; n; n = nx) { nx = n->next; free_evnode(n); }
    free_evnode(s->ev_cur);
    sb_free(&s->in); sb_free(&s->out); sb_free(&s->hs_buf); sb_free(&s->transcript);
    x509_cert_free(&s->cert);
    ec_point_free(&s->ec_pub);
    bn_free(&s->ec_priv);
    free(s->hostname);
    ssh_wipe(s, sizeof(*s));
    free(s);
}

int tls_start(tls_session *s)
{
    if (s->started) return 0;
    if (!ssh_rng_ready()) { tls_fail(s, "not enough entropy to start a secure session"); return -1; }
    s->started = 1;
    s->state = TLS_ST_WAIT_SH;
    return build_client_hello(s);
}

int tls_input(tls_session *s, const u8 *data, size_t len)
{
    int rc;
    if (s->closed) return s->fatal ? -1 : 0;
    if (sb_put(&s->in, data, len) < 0) { tls_fail(s, "out of memory"); return -1; }
    while (!s->closed) {
        rc = process_one_record(s);
        if (rc <= 0) break;
    }
    return s->fatal ? -1 : 0;
}

const u8 *tls_output(tls_session *s, size_t *len) { *len = s->out.len; return s->out.p; }
void tls_output_done(tls_session *s, size_t n) { sb_consume(&s->out, n); }

int tls_is_closed(const tls_session *s) { return s->closed; }
int tls_is_established(const tls_session *s) { return s->state == TLS_ST_ESTABLISHED; }

void tls_close(tls_session *s)
{
    u8 alert[2];
    if (s->closed) return;
    alert[0] = 1; alert[1] = 0;                        /* warning, close_notify */
    send_record(s, CT_ALERT, alert, 2);
    s->closed = 1;
}

int tls_write(tls_session *s, const u8 *data, size_t len)
{
    if (s->closed || s->state != TLS_ST_ESTABLISHED) return -1;
    while (len > 0) {
        size_t n = len < 16384 ? len : 16384;
        if (send_record(s, CT_APPLICATION_DATA, data, n) != 0) return -1;
        data += n; len -= n;
    }
    return 0;
}

const char *tls_cipher_name(const tls_session *s)
{
    if (s->state != TLS_ST_ESTABLISHED) return "none";
    switch (s->cipher_suite) {
    case CS_ECDHE_RSA_AES128_GCM_SHA256:   return "ECDHE-RSA-AES128-GCM-SHA256";
    case CS_ECDHE_ECDSA_AES128_GCM_SHA256: return "ECDHE-ECDSA-AES128-GCM-SHA256";
    case CS_ECDHE_RSA_CHACHA20_POLY1305:   return "ECDHE-RSA-CHACHA20-POLY1305";
    case CS_ECDHE_ECDSA_CHACHA20_POLY1305: return "ECDHE-ECDSA-CHACHA20-POLY1305";
    default: return "none";
    }
}
