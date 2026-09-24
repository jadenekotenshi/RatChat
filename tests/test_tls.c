#include <stdlib.h>
#include <string.h>
#include "../core/ssh_types.h"
#include "../core/wire.h"
#include "../core/tls_wire.h"
#include "../core/tls_priv.h"
#include "test.h"

/* Whitebox tests: this file reaches into tls_session's own fields (via tls_priv.h) rather than
 * staying behind tls.h's public API, the same way test_bignum.c/test_ecc.c reach into bn's own
 * fields -- the point here is verifying internal state transitions (which handshake state a
 * session is in) that the public API alone doesn't expose. */

static void seed_rng(void)
{
    if (ssh_rng_ready()) return;
    if (ssh_rng_seed_system() == 0) ssh_rng_add("tls test", 8, 256);
}

static size_t build_server_hello_record(u8 *out)
{
    u8 body[40];
    size_t bn = 0, msg_len;

    body[bn++] = 3; body[bn++] = 3;                    /* server_version */
    memset(body + bn, 0x42, 32); bn += 32;              /* random */
    body[bn++] = 0;                                     /* session_id: empty */
    body[bn++] = (u8)(CS_ECDHE_RSA_AES128_GCM_SHA256 >> 8);
    body[bn++] = (u8)(CS_ECDHE_RSA_AES128_GCM_SHA256 & 0xff);
    body[bn++] = 0;                                     /* compression_method: null */

    msg_len = 4 + bn;
    out[0] = CT_HANDSHAKE; out[1] = 3; out[2] = 3;
    out[3] = (u8)(msg_len >> 8); out[4] = (u8)msg_len;
    out[5] = HS_SERVER_HELLO;
    out[6] = 0; out[7] = 0; out[8] = (u8)bn;
    memcpy(out + 9, body, bn);
    return 5 + msg_len;
}

/* Every possible split point across one ServerHello record: at every prefix length short of the
 * whole thing, tls_input() must report "processed" with no error and no state change, and the
 * state must advance to WAIT_CERT only once the last byte finally arrives -- regardless of how
 * arbitrarily a caller's own TCP reads happened to chop the bytes up. */
static void test_split_delivery(void)
{
    u8 rec[64];
    size_t total, i;

    total = build_server_hello_record(rec);
    CHECK(total > 2);

    for (i = 1; i < total; i++) {
        tls_session *s = tls_new("example.com");
        tls_event ev;
        s->started = 1;
        s->state = TLS_ST_WAIT_SH;

        CHECK(tls_input(s, rec, i) == 0);
        CHECK(!s->closed);
        CHECK(s->state == TLS_ST_WAIT_SH);
        CHECK(tls_next_event(s, &ev) == 0);

        CHECK(tls_input(s, rec + i, total - i) == 0);
        CHECK(!s->closed);
        CHECK(s->state == TLS_ST_WAIT_CERT);
        tls_free(s);
    }

    {
        tls_session *s = tls_new("example.com");
        s->started = 1;
        s->state = TLS_ST_WAIT_SH;
        CHECK(tls_input(s, rec, total) == 0);
        CHECK(s->state == TLS_ST_WAIT_CERT);
        tls_free(s);
    }
}

/* One byte at a time is the extreme case of the same thing: every call in between must be a
 * clean "need more" with zero observable side effects. */
static void test_byte_at_a_time_delivery(void)
{
    u8 rec[64];
    size_t total, i;
    tls_session *s = tls_new("example.com");
    s->started = 1;
    s->state = TLS_ST_WAIT_SH;
    total = build_server_hello_record(rec);
    for (i = 0; i < total; i++) {
        CHECK(tls_input(s, rec + i, 1) == 0);
        CHECK(!s->closed);
        if (i + 1 < total) CHECK(s->state == TLS_ST_WAIT_SH);
    }
    CHECK(s->state == TLS_ST_WAIT_CERT);
    tls_free(s);
}

/* Two ServerHello records coalesced into a single tls_input() call: the first is consumed
 * (state advances to WAIT_CERT), and drain_handshake's loop re-checks state before dispatching
 * the second -- which is now a ServerHello arriving in the wrong state, correctly refused rather
 * than silently reprocessed or left unexamined in the buffer. Proves one tls_input() call can
 * walk its loop more than once, not just once per call. */
static void test_coalesced_messages_dispatch_in_order(void)
{
    u8 rec[128];
    size_t n1, n2;
    tls_session *s = tls_new("example.com");
    tls_event ev;
    int saw_error = 0;

    n1 = build_server_hello_record(rec);
    n2 = build_server_hello_record(rec + n1);
    s->started = 1;
    s->state = TLS_ST_WAIT_SH;

    CHECK(tls_input(s, rec, n1 + n2) == -1);
    CHECK(s->closed);
    while (tls_next_event(s, &ev)) if (ev.type == TLS_EV_ERROR) saw_error = 1;
    CHECK(saw_error);
    tls_free(s);
}

static void test_oversized_record_rejected(void)
{
    tls_session *s = tls_new("example.com");
    u8 hdr[5];
    tls_event ev;
    int saw_error = 0;

    s->started = 1;
    s->state = TLS_ST_WAIT_SH;
    hdr[0] = CT_HANDSHAKE; hdr[1] = 3; hdr[2] = 3;
    hdr[3] = 0xff; hdr[4] = 0xff;                       /* 65535 > TLS_MAX_RECORD */
    CHECK(tls_input(s, hdr, 5) == -1);
    CHECK(s->closed);
    while (tls_next_event(s, &ev)) if (ev.type == TLS_EV_ERROR) saw_error = 1;
    CHECK(saw_error);
    tls_free(s);
}

static void test_truncated_header_waits(void)
{
    tls_session *s = tls_new("example.com");
    static const u8 hdr[4] = { CT_HANDSHAKE, 3, 3, 0 }; /* short of the 5-byte minimum */
    s->started = 1;
    s->state = TLS_ST_WAIT_SH;
    CHECK(tls_input(s, hdr, 4) == 0);
    CHECK(!s->closed);
    CHECK(s->state == TLS_ST_WAIT_SH);
    tls_free(s);
}

/* A structural check of our own ClientHello: not a byte-for-byte comparison against a captured
 * real client's output (its own client_random makes that inherently non-reproducible without
 * controlling that randomness, which no ordinary OpenSSL tooling exposes a way to do for a real
 * `openssl s_client` run) -- this instead parses ratchat's own output the way a real server
 * would and checks it says what it should: TLS 1.2, our own generated client_random verbatim,
 * an empty session_id, all four offered suites, and a server_name extension carrying the exact
 * hostname tls_new() was given. */
static void test_client_hello_shape(void)
{
    tls_session *s;
    const u8 *out;
    size_t len, sid_len, cs_len, comp_len;
    sreader r, er, snr;
    u32 ext_len;
    const u8 *rand;
    int found_sni;
    static const char host[] = "irc.example.org";

    seed_rng();
    s = tls_new(host);
    CHECK(tls_start(s) == 0);
    out = tls_output(s, &len);
    CHECK(out != NULL && len > 9);
    CHECK(out[0] == CT_HANDSHAKE && out[1] == 3 && out[2] == 3);
    CHECK(out[5] == HS_CLIENT_HELLO);

    sr_init(&r, out + 9, len - 9);
    CHECK(tls_get_u16(&r) == 0x0303);
    rand = sr_bytes(&r, 32);
    CHECK(rand != NULL && memcmp(rand, s->client_random, 32) == 0);
    tls_get_vec8(&r, &sid_len);
    CHECK(sid_len == 0);
    tls_get_vec16(&r, &cs_len);
    CHECK(cs_len == 8);
    tls_get_vec8(&r, &comp_len);
    CHECK(comp_len == 1);
    ext_len = tls_get_u16(&r);
    CHECK(!r.err);
    CHECK(sr_left(&r) == ext_len);

    found_sni = 0;
    sr_init(&er, r.p + r.pos, ext_len);
    while (sr_left(&er) >= 4) {
        u32 etype = tls_get_u16(&er);
        size_t edata_len;
        const u8 *edata = tls_get_vec16(&er, &edata_len);
        if (!edata) break;
        if (etype == 0x0000) {
            size_t hlen;
            const u8 *nm;
            sr_init(&snr, edata, edata_len);
            tls_get_u16(&snr);                          /* server_name_list length */
            sr_u8(&snr);                                 /* name_type: host_name */
            nm = tls_get_vec16(&snr, &hlen);
            CHECK(nm != NULL && hlen == strlen(host) && memcmp(nm, host, hlen) == 0);
            found_sni = 1;
        }
    }
    CHECK(found_sni);

    tls_free(s);
}

int main(void)
{
    test_split_delivery();
    test_byte_at_a_time_delivery();
    test_coalesced_messages_dispatch_in_order();
    test_oversized_record_rejected();
    test_truncated_header_waits();
    test_client_hello_shape();
    TEST_DONE("tls");
}
