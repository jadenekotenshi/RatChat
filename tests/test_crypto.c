#include <stdlib.h>
#include "../core/ssh_types.h"
#include "../core/sha2.h"
#include "../core/hmac.h"
#include "../core/aes.h"
#include "../core/chacha.h"
#include "../core/nacl.h"
#include "../core/rng.h"
#include "../core/sha1.h"
#include "../core/md5.h"
#include "test.h"
#include "vectors.h"

/* Vendored (and trimmed) from StepSSH's tests/test_crypto.c: covers exactly the primitives
 * RatChat's TLS work vendored into core/ (see the TLS plan's Phase 0) -- sha2/sha1/md5, hmac,
 * aes (block + ctr), chacha20/poly1305, x25519, ed25519, rng. StepSSH's own knownhosts/
 * blowfish/des/gcm/bcrypt/ssh_key tests are dropped along with the primitives they exercise;
 * gcm.c itself is deliberately not vendored (TLS gets its own from-scratch AEAD framing in a
 * later phase). Exit criterion for Phase 0: these pass bit-for-bit identically to StepSSH's own
 * already-hardware-confirmed copies, before any TLS-specific code exists. */

static void pattern(unsigned char *p, int n, int seed)
{
    int i;
    for (i = 0; i < n; i++) p[i] = (unsigned char)((i * 7 + 3 + seed) & 0xff);
}

static void test_sha(void)
{
    int i, j;
    u8 msg[1000], d256[32], d512[64];
    sha256_ctx c256;
    sha512_ctx c512;

    for (i = 0; i < N_SHA; i++) {
        pattern(msg, sha_lens[i], 0);
        sha256(msg, sha_lens[i], d256);
        sha512(msg, sha_lens[i], d512);
        { u8 d384[48]; sha384(msg, (size_t)sha_lens[i], d384); CHECK_MEM(d384, sha384_exp[i], 48, "sha384"); }
        CHECK_MEM(d256, sha256_exp[i], 32, "sha256");
        CHECK_MEM(d512, sha512_exp[i], 64, "sha512");
        /* same message fed in awkward pieces */
        sha256_init(&c256); sha512_init(&c512);
        for (j = 0; j < sha_lens[i]; j += 13) {
            int n = sha_lens[i] - j < 13 ? sha_lens[i] - j : 13;
            sha256_update(&c256, msg + j, n);
            sha512_update(&c512, msg + j, n);
        }
        sha256_final(&c256, d256); sha512_final(&c512, d512);
        CHECK_MEM(d256, sha256_exp[i], 32, "sha256 incremental");
        CHECK_MEM(d512, sha512_exp[i], 64, "sha512 incremental");
    }
}

static void test_hmac(void)
{
    int i;
    u8 k[200], m[200], out[64];
    hmac_ctx h;
    for (i = 0; i < N_HMAC; i++) {
        pattern(k, hmac_klens[i], 9);
        pattern(m, hmac_mlens[i], 5);
        hmac_init(&h, 0, k, hmac_klens[i]);
        hmac_update(&h, m, hmac_mlens[i]);
        hmac_final(&h, out);
        CHECK_MEM(out, hmac256_exp[i], 32, "hmac-sha256");
        hmac_init(&h, 1, k, hmac_klens[i]);
        hmac_update(&h, m, hmac_mlens[i] / 2);
        hmac_update(&h, m + hmac_mlens[i] / 2, hmac_mlens[i] - hmac_mlens[i] / 2);
        hmac_final(&h, out);
        CHECK_MEM(out, hmac512_exp[i], 64, "hmac-sha512");
        hmac_init(&h, HMAC_MD5, k, hmac_klens[i]);
        hmac_update(&h, m, hmac_mlens[i]);
        hmac_final(&h, out);
        CHECK_MEM(out, hmac_md5_exp[i], 16, "hmac-md5");
    }
}

static void test_sha1(void)
{
    int i;
    u8 msg[1000], d[20], k[200], m[200];
    sha1_ctx c;
    md5_ctx mc;
    for (i = 0; i < N_SHA; i++) {
        pattern(msg, sha_lens[i], 0);
        sha1_init(&c); sha1_update(&c, msg, (size_t)sha_lens[i]); sha1_final(&c, d);
        CHECK_MEM(d, sha1_exp[i], 20, "sha1");
        { u8 dm[16]; md5_init(&mc); md5_update(&mc, msg, (size_t)sha_lens[i]); md5_final(&mc, dm); CHECK_MEM(dm, md5_exp[i], 16, "md5"); }
    }
    for (i = 0; i < N_HMAC; i++) {
        hmac_ctx hc;
        pattern(k, hmac_klens[i], 9); pattern(m, hmac_mlens[i], 5);
        hmac_sha1(k, (size_t)hmac_klens[i], m, (size_t)hmac_mlens[i], d);
        CHECK_MEM(d, hmac1_exp[i], 20, "hmac-sha1");
        hmac_init(&hc, HMAC_SHA1, k, (size_t)hmac_klens[i]);                      /* the incremental interface the transport uses */
        hmac_update(&hc, m, (size_t)hmac_mlens[i] / 3);
        hmac_update(&hc, m + hmac_mlens[i] / 3, (size_t)hmac_mlens[i] - (size_t)hmac_mlens[i] / 3);
        hmac_final(&hc, d);
        CHECK_MEM(d, hmac1_exp[i], 20, "hmac-sha1 incremental");
    }
}

static void unhex(const char *h, u8 *out, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        int a = h[2 * i], b = h[2 * i + 1];
        a = a <= '9' ? a - '0' : (a | 32) - 'a' + 10;
        b = b <= '9' ? b - '0' : (b | 32) - 'a' + 10;
        out[i] = (u8)(a * 16 + b);
    }
}

/* FIPS-197 appendix C known answers, both directions, all three key sizes. */
static void test_aes_blocks(void)
{
    static const struct { int keylen; const char *ct; } v[] = {
        { 16, "69c4e0d86a7b0430d8cdb78070b4c55a" },
        { 24, "dda97ca4864cdfe06eaf70a0ec0d7191" },
        { 32, "8ea2b7ca516745bfeafc49904b496089" },
    };
    u8 key[32], pt[16], ct[16], out[16], zero_iv[16];
    aes_ctr_ctx c;
    int i, j;
    for (j = 0; j < 32; j++) key[j] = (u8)j;
    unhex("00112233445566778899aabbccddeeff", pt, 16);
    memset(zero_iv, 0, 16);
    for (i = 0; i < 3; i++) {
        unhex(v[i].ct, ct, 16);
        aes_ctr_init(&c, key, v[i].keylen, zero_iv);
        aes_encrypt_block(&c, pt, out);
        CHECK_MEM(out, ct, 16, "aes encrypt (FIPS-197)");
        aes_decrypt_block(&c, ct, out);
        CHECK_MEM(out, pt, 16, "aes decrypt (FIPS-197)");
    }
    /* CBC decrypt against a hand-rolled CBC encrypt built from the tested block function */
    {
        u8 plain[64], enc[64], back[64], iv[16], prev[16], blk[16];
        int b, k;
        pattern(plain, 64, 7); pattern(iv, 16, 99); pattern(key, 32, 50);
        aes_ctr_init(&c, key, 32, zero_iv);
        memcpy(prev, iv, 16);
        for (b = 0; b < 64; b += 16) {
            for (k = 0; k < 16; k++) blk[k] = (u8)(plain[b + k] ^ prev[k]);
            aes_encrypt_block(&c, blk, enc + b);
            memcpy(prev, enc + b, 16);
        }
        aes_cbc_decrypt(&c, iv, enc, back, 64);
        CHECK_MEM(back, plain, 64, "aes-cbc decrypt");
        aes_cbc_decrypt(&c, iv, enc, enc, 64);                   /* in place */
        CHECK_MEM(enc, plain, 64, "aes-cbc decrypt in place");
    }
}

/* SSH chains CBC across packets: many small chained calls must equal one big call */
static void test_cbc_chain(void)
{
    aes_ctr_ctx c;
    u8 key[16], iv0[16], iv[16], plain[160], one[160], two[160], back[160], zero[16];
    int off;
    pattern(key, 16, 3); pattern(iv0, 16, 9); pattern(plain, 160, 12); memset(zero, 0, 16);
    aes_ctr_init(&c, key, 16, zero);
    memcpy(iv, iv0, 16);
    aes_cbc_encrypt_chain(&c, iv, plain, one, 160);
    memcpy(iv, iv0, 16);
    for (off = 0; off < 160; off += 32) aes_cbc_encrypt_chain(&c, iv, plain + off, two + off, 32);   /* packets of 2 blocks */
    CHECK_MEM(one, two, 160, "cbc chained encrypt == one-shot");
    CHECK_MEM(iv, one + 144, 16, "iv ends as the last ciphertext block");
    memcpy(iv, iv0, 16);
    for (off = 0; off < 160; off += 48) aes_cbc_decrypt_chain(&c, iv, one + off, back + off, off + 48 <= 160 ? 48 : 16);
    CHECK_MEM(back, plain, 160, "cbc chained decrypt round trip");
    aes_cbc_decrypt(&c, iv0, one, back, 160);
    CHECK_MEM(back, plain, 160, "cbc chained encrypt matches the one-shot decrypt");
    memcpy(iv, iv0, 16);
    aes_cbc_decrypt_chain(&c, iv, one, one, 160);                                                     /* in place */
    CHECK_MEM(one, plain, 160, "cbc chained decrypt in place");
}

static void test_aes(void)
{
    aes_ctr_ctx c;
    u8 out[157], out2[157];
    int i;

    aes_ctr_init(&c, aes_k128, 16, aes_iv);
    aes_ctr_xor(&c, aes_plain, out, aes_plain_LEN);
    CHECK_MEM(out, aes128_ctr_exp, aes_plain_LEN, "aes-128-ctr");

    aes_ctr_init(&c, aes_k256, 32, aes_iv);
    aes_ctr_xor(&c, aes_plain, out, aes_plain_LEN);
    CHECK_MEM(out, aes256_ctr_exp, aes_plain_LEN, "aes-256-ctr");

    /* the stream must be continuous across differently-sized calls */
    aes_ctr_init(&c, aes_k256, 32, aes_iv);
    for (i = 0; i < aes_plain_LEN; i += 5) {
        int n = aes_plain_LEN - i < 5 ? aes_plain_LEN - i : 5;
        aes_ctr_xor(&c, aes_plain + i, out2 + i, n);
    }
    CHECK_MEM(out2, aes256_ctr_exp, aes_plain_LEN, "aes-256-ctr chunked");
}

static void test_chacha(void)
{
    chacha_ctx c;
    u8 zero[300], ks[300], mac[16], msg[300], sealed[64], opened[64];
    chachapoly_ctx cp;
    int i;

    memset(zero, 0, sizeof(zero));
    chacha_keysetup(&c, chacha_key);
    chacha_ivsetup(&c, chacha_iv, 1);
    chacha_xor(&c, zero, ks, 300);
    CHECK_MEM(ks, chacha_ks_exp, 300, "chacha20 keystream");

    poly1305_auth(mac, poly_msg, poly_msg_LEN, poly_key);
    CHECK_MEM(mac, poly_exp, 16, "poly1305 RFC 8439");
    for (i = 0; i < N_POLY; i++) {
        pattern(msg, poly_lens[i], 3);
        poly1305_auth(mac, msg, poly_lens[i], poly_key2);
        CHECK_MEM(mac, poly_exp2[i], 16, "poly1305");
    }

    chachapoly_init(&cp, cp_key);
    chachapoly_seal(&cp, CP_SEQ, sealed, cp_plain, cp_plain_LEN - 4);
    CHECK_MEM(sealed, cp_sealed, cp_sealed_LEN, "chachapoly seal");
    CHECK(chachapoly_peek_length(&cp, CP_SEQ, sealed) == 29);
    CHECK(chachapoly_open(&cp, CP_SEQ, opened, sealed, 29) == 0);
    CHECK_MEM(opened, cp_plain, cp_plain_LEN, "chachapoly open");
    sealed[10] ^= 1;                                     /* tamper */
    CHECK(chachapoly_open(&cp, CP_SEQ, opened, sealed, 29) == -1);
    sealed[10] ^= 1; sealed[40] ^= 0x80;                 /* tamper with the tag (bytes 33..48) */
    CHECK(chachapoly_open(&cp, CP_SEQ, opened, sealed, 29) == -1);
    sealed[40] ^= 0x80;
    CHECK(chachapoly_open(&cp, CP_SEQ + 1, opened, sealed, 29) == -1);   /* wrong seq */
}

static void test_x25519(void)
{
    u8 out[32], a[32], b[32], s1[32], s2[32];
    int i;

    x25519(out, x_a, x_u);
    CHECK_MEM(out, x_exp, 32, "x25519 RFC 7748");
    x25519_base(a, x_alice);
    x25519_base(b, x_bob);
    x25519(s1, x_alice, b);
    x25519(s2, x_bob, a);
    CHECK_MEM(s1, x_shared, 32, "x25519 shared (alice)");
    CHECK_MEM(s2, x_shared, 32, "x25519 shared (bob)");
    for (i = 0; i < N_X; i++) {
        x25519(out, x_sc[i], x_pt[i]);
        CHECK_MEM(out, x_out[i], 32, "x25519 random");
    }
}

static void test_ed25519(void)
{
    int i;
    u8 pk[32], sk[64], sig[64], msg[300];
    for (i = 0; i < N_ED; i++) {
        pattern(msg, ed_mlens[i], 17);
        ed25519_keypair(pk, sk, ed_seed[i]);
        CHECK_MEM(pk, ed_pub_exp[i], 32, "ed25519 public key");
        ed25519_sign(sig, msg, ed_mlens[i], sk);
        CHECK_MEM(sig, ed_sig_exp[i], 64, "ed25519 signature");
        CHECK(ed25519_verify(ed_sig_exp[i], msg, ed_mlens[i], ed_pub_exp[i]) == 0);
        sig[5] ^= 1;
        CHECK(ed25519_verify(sig, msg, ed_mlens[i], pk) != 0);            /* bad R */
        sig[5] ^= 1; sig[40] ^= 1;
        CHECK(ed25519_verify(sig, msg, ed_mlens[i], pk) != 0);            /* bad S */
        sig[40] ^= 1;
        if (ed_mlens[i]) {
            msg[0] ^= 1;
            CHECK(ed25519_verify(sig, msg, ed_mlens[i], pk) != 0);        /* bad msg */
        }
    }
}

static void test_rng(void)
{
    u8 a[32], b[32];
    /* Not seeded yet: must refuse rather than emit predictable bytes. */
    CHECK(!ssh_rng_ready());
    CHECK(ssh_rng_bytes(a, 32) == -1);
    ssh_rng_add("x", 1, 100);                 /* below threshold */
    CHECK(ssh_rng_bytes(a, 32) == -1);
    if (ssh_rng_seed_system() == 0) {         /* e.g. OPENSTEP: no /dev/urandom */
        printf("  note: no system entropy device here; crediting synthetic entropy for the test\n");
        ssh_rng_add("synthetic", 9, 256);
    }
    CHECK(ssh_rng_ready());
    CHECK(ssh_rng_bytes(a, 32) == 0);
    CHECK(ssh_rng_bytes(b, 32) == 0);
    CHECK(memcmp(a, b, 32) != 0);
    CHECK(ssh_ct_memcmp(a, a, 32) == 0 && ssh_ct_memcmp(a, b, 32) != 0);
}

int main(void)
{
    test_sha(); test_hmac(); test_sha1(); test_aes(); test_aes_blocks(); test_cbc_chain();
    test_chacha(); test_x25519(); test_ed25519(); test_rng();
    TEST_DONE("crypto");
}
