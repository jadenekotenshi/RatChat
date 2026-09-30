/*
 * bench_bulk -- per-primitive cost of everything on RatChat's TLS data path, on THIS machine.
 * Run it from the project root:
 *     build/bench_bulk
 * Each row is timed for about half a second (longer only if one call is slower than that), so it
 * finishes quickly on a fast host and still completes on a 68040.  Compare the numbers before and
 * after a change, on the same machine; the record-sized rows show per-record overhead that a bulk row
 * hides.  Modelled on StepSSH's tools/bench_bulk.c, which measured the same primitives there.
 *
 * Wall-clock time from gettimeofday(); C89 so it builds under gcc 2.7.2 as well.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "../core/ssh_types.h"
#include "../core/chacha.h"
#include "../core/sha1.h"
#include "../core/sha2.h"
#include "../core/hmac.h"
#include "../core/nacl.h"
#include "../core/tls_aead_gcm.h"
#include "../core/tls_aead_chacha.h"

#define BIG 65536
#define RECMAX 16384                     /* TLS's largest record payload */

static double now_s(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

/* Seconds per call of fn, measured over enough calls to take at least `budget` seconds. */
static double measure(void (*fn)(void))
{
    const double budget = 0.5;
    double t0, t;
    long n = 1, i;
    for (;;) {
        t0 = now_s();
        for (i = 0; i < n; i++) fn();
        t = now_s() - t0;
        if (t >= budget) return t / (double)n;
        n *= (t < budget / 16.0) ? 16 : 2;
    }
}

static void row_kbs(const char *what, void (*fn)(void), double kbytes)
{
    double s = measure(fn);
    printf("  %-46s %10.1f KB/s\n", what, s > 0 ? kbytes / s : 0.0);
    fflush(stdout);
}

static void row_us(const char *what, void (*fn)(void), double kbytes)
{
    double s = measure(fn);
    printf("  %-46s %10.1f us/op  (%8.1f KB/s)\n", what, s * 1e6, s > 0 ? kbytes / s : 0.0);
    fflush(stdout);
}

static u8 buf[BIG + 64], buf2[BIG + 64], sealed[BIG + 64];
static u8 key32[32], iv12[12], aad13[13], digest[64], mac[16], pub[32];
static chacha_ctx cc;
static tls_gcm_ctx gcm128, gcm256;
static tls_chacha_ctx tcc;
static u64 seq;
static size_t plen;                       /* payload length for the record-sized rows */

static void f_chacha(void)     { chacha_xor(&cc, buf, buf, BIG); }
static void f_poly(void)       { poly1305_auth(mac, buf, BIG, key32); }
static void f_cc_seal(void)    { tls_chacha_seal(&tcc, seq++, aad13, sizeof(aad13), buf, buf2, plen); }
static void f_cc_open(void)    { tls_chacha_open(&tcc, 5, aad13, sizeof(aad13), sealed, buf2, plen); }
static void f_g128_seal(void)  { tls_gcm_seal(&gcm128, seq++, aad13, sizeof(aad13), buf, buf2, plen); }
static void f_g128_open(void)  { tls_gcm_open(&gcm128, 5, aad13, sizeof(aad13), sealed, buf2, plen); }
static void f_g256_seal(void)  { tls_gcm_seal(&gcm256, seq++, aad13, sizeof(aad13), buf, buf2, plen); }
static void f_g256_open(void)  { tls_gcm_open(&gcm256, 5, aad13, sizeof(aad13), sealed, buf2, plen); }
static void f_sha1(void)       { sha1_ctx c; sha1_init(&c); sha1_update(&c, buf, BIG); sha1_final(&c, digest); }
static void f_sha256(void)     { sha256(buf, BIG, digest); }
static void f_sha512(void)     { sha512(buf, BIG, digest); }
static void f_hmac(void)       { hmac_sha256(key32, sizeof(key32), buf, plen, digest); }
static void f_x25519(void)     { x25519_base(pub, key32); }
static void f_wipe(void)       { ssh_wipe(buf2, RECMAX); }

int main(void)
{
    int i;
    char what[80];
    static const size_t sizes[3] = { 64, 1400, RECMAX };
    static const char *szname[3] = { "64 B", "1400 B", "16 KB" };

    for (i = 0; i < 32; i++) key32[i] = (u8)(i * 7 + 1);
    for (i = 0; i < 12; i++) iv12[i] = (u8)(i + 3);
    for (i = 0; i < 13; i++) aad13[i] = (u8)(i * 3);
    memset(buf, 0x5a, sizeof(buf));

    chacha_keysetup(&cc, key32);
    chacha_ivsetup(&cc, iv12, 0);
    tls_chacha_init(&tcc, key32, iv12);
    tls_gcm_init(&gcm128, key32, 16, iv12);
    tls_gcm_init(&gcm256, key32, 32, iv12);

    printf("TLS data-path cost on this machine (wall-clock, ~0.5 s per row)\n\n");

    printf("Stream cipher and MAC halves, 64 KB\n");
    row_kbs("ChaCha20 keystream XOR", f_chacha, BIG / 1024.0);
    row_kbs("Poly1305 MAC", f_poly, BIG / 1024.0);

    printf("\nTLS ChaCha20-Poly1305, one record at a time\n");
    for (i = 0; i < 3; i++) {
        plen = sizes[i];
        sprintf(what, "seal %s", szname[i]);
        row_us(what, f_cc_seal, (double)plen / 1024.0);
    }
    for (i = 0; i < 3; i++) {
        plen = sizes[i];
        tls_chacha_seal(&tcc, 5, aad13, sizeof(aad13), buf, sealed, plen);
        sprintf(what, "open %s", szname[i]);
        row_us(what, f_cc_open, (double)plen / 1024.0);
    }

    printf("\nTLS AES-GCM, one record at a time\n");
    for (i = 0; i < 3; i++) {
        plen = sizes[i];
        sprintf(what, "aes128-gcm seal %s", szname[i]);
        row_us(what, f_g128_seal, (double)plen / 1024.0);
    }
    for (i = 0; i < 3; i++) {
        plen = sizes[i];
        tls_gcm_seal(&gcm128, 5, aad13, sizeof(aad13), buf, sealed, plen);
        sprintf(what, "aes128-gcm open %s", szname[i]);
        row_us(what, f_g128_open, (double)plen / 1024.0);
    }
    plen = 1400;
    row_us("aes256-gcm seal 1400 B", f_g256_seal, 1400 / 1024.0);
    tls_gcm_seal(&gcm256, 5, aad13, sizeof(aad13), buf, sealed, plen);
    row_us("aes256-gcm open 1400 B", f_g256_open, 1400 / 1024.0);

    printf("\nHash functions, 64 KB (handshake hash, PRF, certificate signatures)\n");
    row_kbs("SHA-1", f_sha1, BIG / 1024.0);
    row_kbs("SHA-256", f_sha256, BIG / 1024.0);
    row_kbs("SHA-512", f_sha512, BIG / 1024.0);

    printf("\nHMAC-SHA256, one call (the TLS PRF's building block)\n");
    plen = 64;
    row_us("HMAC-SHA256 64 B", f_hmac, 64 / 1024.0);
    plen = RECMAX;
    row_us("HMAC-SHA256 16 KB", f_hmac, RECMAX / 1024.0);

    printf("\nHandshake and per-record overheads\n");
    row_us("X25519: one public key / shared secret", f_x25519, 0.0);
    row_us("ssh_wipe 16 KB", f_wipe, 16.0);
    return 0;
}
