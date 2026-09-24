#include <stdlib.h>
#include <string.h>
#include "../core/ssh_types.h"
#include "../core/tls_aead_gcm.h"
#include "../core/tls_aead_chacha.h"
#include "test.h"
#include "tls_aead_vectors.h"

/* RFC 8439 SS2.8.2's own published vector, computed via real OpenSSL (see the vectors file's own
 * header). No TLS framing here -- straight nonce, no IV/seq split -- so seq=0 (XORs to nothing)
 * reproduces it exactly through tls_chacha_seal/open's TLS-shaped API. */
static void test_chacha_rfc8439(void)
{
    tls_chacha_ctx c;
    u8 out[rfc8439_pt_LEN + TLS_CHACHA_TAG_LEN];
    u8 back[rfc8439_pt_LEN];

    tls_chacha_init(&c, rfc8439_key, rfc8439_nonce);
    CHECK(tls_chacha_seal(&c, 0, rfc8439_aad, rfc8439_aad_LEN, rfc8439_pt, out, rfc8439_pt_LEN) == 0);
    CHECK_MEM(out, rfc8439_ct, rfc8439_ct_LEN, "rfc8439 ciphertext");
    CHECK_MEM(out + rfc8439_pt_LEN, rfc8439_tag, rfc8439_tag_LEN, "rfc8439 tag");

    memcpy(out, rfc8439_ct, rfc8439_ct_LEN);
    memcpy(out + rfc8439_ct_LEN, rfc8439_tag, rfc8439_tag_LEN);
    CHECK(tls_chacha_open(&c, 0, rfc8439_aad, rfc8439_aad_LEN, out, back, rfc8439_pt_LEN) == 0);
    CHECK_MEM(back, rfc8439_pt, rfc8439_pt_LEN, "rfc8439 plaintext");
}

/* A real captured TLS 1.2 GCM record (see tls_aead_vectors.h for the explicit-nonce-vs-seq_num
 * note): decrypts against the real ciphertext+tag, and re-encrypting the real plaintext
 * reproduces that same real ciphertext+tag exactly. */
static void test_gcm_real(const u8 *key, const u8 *fixed_iv, u64 seq, const u8 *aad, size_t aad_len,
                           const u8 *ct, const u8 *tag, const u8 *pt, size_t pt_len, const char *who)
{
    tls_gcm_ctx c;
    u8 in[64], out[64], back[64];

    tls_gcm_init(&c, key, 16, fixed_iv);

    memcpy(in, ct, pt_len);
    memcpy(in + pt_len, tag, TLS_GCM_TAG_LEN);
    CHECK(tls_gcm_open(&c, seq, aad, aad_len, in, back, pt_len) == 0);
    CHECK_MEM(back, pt, pt_len, who);

    CHECK(tls_gcm_seal != NULL);                       /* keep the linker honest about which symbol we call next */
    tls_gcm_seal(&c, seq, aad, aad_len, pt, out, pt_len);
    CHECK_MEM(out, ct, pt_len, who);
    CHECK_MEM(out + pt_len, tag, TLS_GCM_TAG_LEN, who);
}

/* Same shape for ChaCha20-Poly1305 -- no fixed_iv/seq split on the wire, just the write_IV and
 * the true sequence number (0, for both these captures' first records). */
static void test_chacha_real(const u8 *key, const u8 *iv, const u8 *aad, size_t aad_len,
                              const u8 *ct, const u8 *tag, const u8 *pt, size_t pt_len, const char *who)
{
    tls_chacha_ctx c;
    u8 in[64], out[64], back[64];

    tls_chacha_init(&c, key, iv);

    memcpy(in, ct, pt_len);
    memcpy(in + pt_len, tag, TLS_CHACHA_TAG_LEN);
    CHECK(tls_chacha_open(&c, 0, aad, aad_len, in, back, pt_len) == 0);
    CHECK_MEM(back, pt, pt_len, who);

    CHECK(tls_chacha_seal(&c, 0, aad, aad_len, pt, out, pt_len) == 0);
    CHECK_MEM(out, ct, pt_len, who);
    CHECK_MEM(out + pt_len, tag, TLS_CHACHA_TAG_LEN, who);
}

static void test_tamper_detection(void)
{
    tls_gcm_ctx gc;
    tls_chacha_ctx cc;
    u8 in[64], out[64];

    tls_gcm_init(&gc, gcm_client_key, 16, gcm_client_fixed_iv);
    memcpy(in, gcm_client_ct, gcm_client_ct_LEN);
    memcpy(in + gcm_client_ct_LEN, gcm_client_tag, gcm_client_tag_LEN);
    CHECK(tls_gcm_open(&gc, gcm_client_seq, gcm_client_aad, gcm_client_aad_LEN, in, out, gcm_client_ct_LEN) == 0);
    in[0] ^= 1;                                         /* tamper with the ciphertext */
    CHECK(tls_gcm_open(&gc, gcm_client_seq, gcm_client_aad, gcm_client_aad_LEN, in, out, gcm_client_ct_LEN) == -1);
    in[0] ^= 1; in[gcm_client_ct_LEN] ^= 1;              /* tamper with the tag instead */
    CHECK(tls_gcm_open(&gc, gcm_client_seq, gcm_client_aad, gcm_client_aad_LEN, in, out, gcm_client_ct_LEN) == -1);
    in[gcm_client_ct_LEN] ^= 1;
    CHECK(tls_gcm_open(&gc, gcm_client_seq + 1, gcm_client_aad, gcm_client_aad_LEN, in, out, gcm_client_ct_LEN) == -1);   /* wrong seq */
    {
        u8 bad_aad[13];
        memcpy(bad_aad, gcm_client_aad, 13);
        bad_aad[12] ^= 1;
        CHECK(tls_gcm_open(&gc, gcm_client_seq, bad_aad, 13, in, out, gcm_client_ct_LEN) == -1);   /* wrong aad */
    }

    tls_chacha_init(&cc, cc_client_key, cc_client_iv);
    memcpy(in, cc_client_ct, cc_client_ct_LEN);
    memcpy(in + cc_client_ct_LEN, cc_client_tag, cc_client_tag_LEN);
    CHECK(tls_chacha_open(&cc, 0, cc_client_aad, cc_client_aad_LEN, in, out, cc_client_ct_LEN) == 0);
    in[0] ^= 1;
    CHECK(tls_chacha_open(&cc, 0, cc_client_aad, cc_client_aad_LEN, in, out, cc_client_ct_LEN) == -1);
    in[0] ^= 1; in[cc_client_ct_LEN] ^= 1;
    CHECK(tls_chacha_open(&cc, 0, cc_client_aad, cc_client_aad_LEN, in, out, cc_client_ct_LEN) == -1);
    in[cc_client_ct_LEN] ^= 1;
    CHECK(tls_chacha_open(&cc, 1, cc_client_aad, cc_client_aad_LEN, in, out, cc_client_ct_LEN) == -1);   /* wrong seq */
}

/* Encrypt then decrypt round trip at a handful of sizes spanning zero, sub-block, exact-block,
 * and multi-block -- neither AEAD wrapper's framing is exercised by the fixed 16-byte-plaintext
 * real captures above. */
static void test_roundtrip_sizes(void)
{
    static const size_t sizes[] = { 0, 1, 15, 16, 17, 31, 32, 300, 1000 };
    unsigned i;
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        size_t n = sizes[i];
        u8 pt[1000], ct[1000 + 16], back[1000];
        u8 aad[13];
        size_t j;
        tls_gcm_ctx gc;
        tls_chacha_ctx cc;

        for (j = 0; j < n; j++) pt[j] = (u8)(j * 7 + 3);
        for (j = 0; j < 13; j++) aad[j] = (u8)(j + 1);

        tls_gcm_init(&gc, gcm_client_key, 16, gcm_client_fixed_iv);
        tls_gcm_seal(&gc, (u64)i, aad, 13, pt, ct, n);
        CHECK(tls_gcm_open(&gc, (u64)i, aad, 13, ct, back, n) == 0);
        CHECK_MEM(back, pt, n, "gcm roundtrip");

        tls_chacha_init(&cc, cc_client_key, cc_client_iv);
        CHECK(tls_chacha_seal(&cc, (u64)i, aad, 13, pt, ct, n) == 0);
        CHECK(tls_chacha_open(&cc, (u64)i, aad, 13, ct, back, n) == 0);
        CHECK_MEM(back, pt, n, "chacha roundtrip");
    }
}

int main(void)
{
    test_chacha_rfc8439();
    test_gcm_real(gcm_client_key, gcm_client_fixed_iv, gcm_client_seq, gcm_client_aad, gcm_client_aad_LEN,
                  gcm_client_ct, gcm_client_tag, gcm_client_pt, gcm_client_pt_LEN, "gcm client Finished");
    test_gcm_real(gcm_server_key, gcm_server_fixed_iv, gcm_server_seq, gcm_server_aad, gcm_server_aad_LEN,
                  gcm_server_ct, gcm_server_tag, gcm_server_pt, gcm_server_pt_LEN, "gcm server Finished");
    test_chacha_real(cc_client_key, cc_client_iv, cc_client_aad, cc_client_aad_LEN,
                     cc_client_ct, cc_client_tag, cc_client_pt, cc_client_pt_LEN, "chacha client Finished");
    test_chacha_real(cc_server_key, cc_server_iv, cc_server_aad, cc_server_aad_LEN,
                     cc_server_ct, cc_server_tag, cc_server_pt, cc_server_pt_LEN, "chacha server Finished");
    test_tamper_detection();
    test_roundtrip_sizes();
    TEST_DONE("tls_aead");
}
