#include <stdlib.h>
#include <string.h>
#include "../core/ssh_types.h"
#include "../core/tls_prf.h"
#include "test.h"
#include "tls_prf_vectors.h"

/* RFC 4279 SS2: for a plain PSK cipher suite (no DH/RSA component), the premaster secret is
 * uint16(N) || zeros(N) || uint16(N) || psk, N = the PSK length. */
static void psk_premaster(const u8 *psk, size_t n, u8 *out)
{
    out[0] = (u8)(n >> 8); out[1] = (u8)n;
    memset(out + 2, 0, n);
    out[2 + n] = (u8)(n >> 8); out[3 + n] = (u8)n;
    memcpy(out + 4 + n, psk, n);
}

/* The centerpiece vector: a real OpenSSL TLS 1.2 handshake's actual master_secret, re-derived
 * here from the same premaster secret and randoms via ratchat's own tls_prf(). */
static void test_master_secret_real(void)
{
    u8 premaster[2 + tp_psk_LEN + 2 + tp_psk_LEN];
    u8 seed[tp_client_random_LEN + tp_server_random_LEN];
    u8 out[tp_master_secret_LEN];

    psk_premaster(tp_psk, tp_psk_LEN, premaster);
    memcpy(seed, tp_client_random, tp_client_random_LEN);
    memcpy(seed + tp_client_random_LEN, tp_server_random, tp_server_random_LEN);

    tls_prf(premaster, sizeof(premaster), "master secret", seed, sizeof(seed), out, sizeof(out));
    CHECK_MEM(out, tp_master_secret, tp_master_secret_LEN, "master_secret vs real openssl handshake");
}

/* "key expansion" swaps the random order (server || client, RFC 5246 SS6.3) and uses a
 * different label; both derivations exercise the identical tls_prf() body, so this also
 * confirms the label string and seed-order aren't swapped or hardcoded from the first call. */
static void test_key_expansion_real(void)
{
    u8 seed[tp_server_random_LEN + tp_client_random_LEN];
    u8 out40[tp_key_block40_LEN];
    u8 out70[tp_key_block70_LEN];

    memcpy(seed, tp_server_random, tp_server_random_LEN);
    memcpy(seed + tp_server_random_LEN, tp_client_random, tp_client_random_LEN);

    tls_prf(tp_master_secret, tp_master_secret_LEN, "key expansion", seed, sizeof(seed), out40, sizeof(out40));
    CHECK_MEM(out40, tp_key_block40, tp_key_block40_LEN, "key_block(40) vs an independent Python HMAC/SHA-256 reimplementation");

    tls_prf(tp_master_secret, tp_master_secret_LEN, "key expansion", seed, sizeof(seed), out70, sizeof(out70));
    CHECK_MEM(out70, tp_key_block70, tp_key_block70_LEN, "key_block(70) vs the same independent reimplementation");
    CHECK_MEM(out70, tp_key_block40, tp_key_block40_LEN, "key_block(70)'s own first 40 bytes == key_block(40)");
}

static void test_determinism_and_distinctness(void)
{
    u8 secret[16], seed[16], a[50], b[50], c[50];
    int i;
    for (i = 0; i < 16; i++) { secret[i] = (u8)(i * 5 + 1); seed[i] = (u8)(i * 3 + 2); }

    tls_prf(secret, sizeof(secret), "label one", seed, sizeof(seed), a, sizeof(a));
    tls_prf(secret, sizeof(secret), "label one", seed, sizeof(seed), b, sizeof(b));
    CHECK_MEM(a, b, sizeof(a), "same inputs, same output");

    tls_prf(secret, sizeof(secret), "label two", seed, sizeof(seed), c, sizeof(c));
    CHECK(memcmp(a, c, sizeof(a)) != 0);

    /* every output length, whole HMAC blocks or not, is exactly what was asked for and is a
     * strict prefix of any longer request with the same inputs (already checked above for the
     * real key_block40/70 pair; here for arbitrary short lengths too) */
    {
        u8 one[1], seventeen[17];
        tls_prf(secret, sizeof(secret), "label one", seed, sizeof(seed), one, sizeof(one));
        CHECK(one[0] == a[0]);
        tls_prf(secret, sizeof(secret), "label one", seed, sizeof(seed), seventeen, sizeof(seventeen));
        CHECK_MEM(seventeen, a, sizeof(seventeen), "17-byte prefix matches the 50-byte run");
    }
}

int main(void)
{
    test_master_secret_real();
    test_key_expansion_real();
    test_determinism_and_distinctness();
    TEST_DONE("tls_prf");
}
