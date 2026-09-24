/*
 * tls_smoke.c -- drives a real tls_session, as a real TCP client, through a full TLS 1.2
 * handshake against a REAL local `openssl s_server` (spawned by this program itself). The
 * strongest single check core/tls.c gets: a real RSA-2048 certificate, a real ECDHE key
 * exchange, and a real signature -- all independently produced by OpenSSL, not by this project.
 *
 * This is the practical stand-in for the TLS plan's own aspiration of "feed a captured real
 * handshake's server bytes into tls_input() and confirm tls_output() reproduces the real
 * client's bytes exactly": that specific comparison turns out not to be achievable with ordinary
 * OpenSSL tooling, because a captured session never reveals the real client's own ephemeral
 * ECDHE private key (SSLKEYLOGFILE logs client_random and the derived master_secret, never the
 * premaster secret or either side's ephemeral scalar) -- there is nothing to replay against.
 * What's fully achievable, and arguably stronger evidence of correctness, is what this program
 * does instead: complete a real live handshake against real OpenSSL end to end, then read
 * OpenSSL's own -keylogfile and confirm ratchat's own independently derived master_secret is
 * bit-for-bit the same value OpenSSL itself thinks was negotiated -- for both TLS_ECDHE_RSA
 * suites (the two GCM/ChaCha20 hash choices), each against a fresh child s_server.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "../core/tls_priv.h"

static int t_pass, t_fail;
#define CHECK(cond) do { if (cond) t_pass++; else { t_fail++; \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static void seed_rng(void)
{
    if (ssh_rng_ready()) return;
    if (ssh_rng_seed_system() == 0) ssh_rng_add("tls smoke", 9, 256);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    return (c | 0x20) - 'a' + 10;
}

static size_t hex2bin(const char *hex, u8 *out, size_t maxout)
{
    size_t n = strlen(hex) / 2, i;
    if (n > maxout) n = maxout;
    for (i = 0; i < n; i++) out[i] = (u8)(hexval(hex[2 * i]) << 4 | hexval(hex[2 * i + 1]));
    return n;
}

/* Reads the last CLIENT_RANDOM line of an SSLKEYLOGFILE and checks it against this session's
 * own client_random and master_secret. */
static int check_keylog(const char *path, const tls_session *s)
{
    FILE *f = fopen(path, "r");
    char line[512];
    char found_random[512] = "", found_secret[512] = "";
    u8 kr[32], km[48];

    if (!f) { fprintf(stderr, "  could not open keylog %s\n", path); return 0; }
    while (fgets(line, sizeof(line), f)) {
        char rnd[128], sec[128];
        if (sscanf(line, "CLIENT_RANDOM %127s %127s", rnd, sec) == 2) {
            strcpy(found_random, rnd);
            strcpy(found_secret, sec);
        }
    }
    fclose(f);
    if (!found_random[0]) { fprintf(stderr, "  no CLIENT_RANDOM line in %s\n", path); return 0; }

    hex2bin(found_random, kr, sizeof(kr));
    hex2bin(found_secret, km, sizeof(km));
    CHECK(memcmp(kr, s->client_random, 32) == 0);
    CHECK(memcmp(km, s->master_secret, 48) == 0);
    return 1;
}

static int connect_retrying(int port)
{
    int i;
    for (i = 0; i < 50; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        struct timeval tv;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((unsigned short)port);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            tv.tv_sec = 5; tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            return fd;
        }
        close(fd);
        usleep(100000);
    }
    return -1;
}

static int run_one_handshake(const char *cert, const char *key, const char *cipher,
                             int port, const char *keylog)
{
    pid_t child;
    int fd, status, rc = 0;
    tls_session *s;
    char portbuf[16];

    sprintf(portbuf, "%d", port);
    {
        /* s_server relays stdin to the client (SSL_write) even with -quiet; an immediately
         * EOF'd /dev/null makes it call SSL_write with length 0, which OpenSSL treats as an
         * error and tears the connection down. A pipe whose write end we just never touch
         * blocks its read() forever instead, so it never gets that far. */
        int pfd[2];
        if (pipe(pfd) != 0) { fprintf(stderr, "pipe failed\n"); return -1; }
        child = fork();
        if (child == 0) {
            int logfd = open("build/tls_smoke_server.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
            close(pfd[1]);
            dup2(pfd[0], 0);
            if (logfd >= 0) { dup2(logfd, 1); dup2(logfd, 2); }
            execlp("openssl", "openssl", "s_server", "-cert", cert, "-key", key,
                   "-tls1_2", "-cipher", cipher, "-accept", portbuf, "-keylogfile", keylog,
                   "-quiet", "-naccept", "1", (char *)NULL);
            _exit(127);
        }
        close(pfd[0]);
    }
    if (child < 0) { fprintf(stderr, "fork failed\n"); return -1; }

    fd = connect_retrying(port);
    if (fd < 0) { fprintf(stderr, "could not connect to child openssl s_server\n"); goto done; }

    s = tls_new("localhost");
    if (tls_start(s) != 0) { fprintf(stderr, "tls_start failed\n"); goto done_free; }

    for (;;) {
        const u8 *out;
        size_t outlen;
        u8 buf[8192];
        ssize_t n;
        tls_event ev;
        int done = 0, failed = 0;

        out = tls_output(s, &outlen);
        if (outlen > 0) {
            if (send(fd, out, outlen, 0) != (ssize_t)outlen) { fprintf(stderr, "send failed\n"); goto done_free; }
            tls_output_done(s, outlen);
        }
        while (tls_next_event(s, &ev)) {
            if (ev.type == TLS_EV_CERT) tls_cert_accept(s, 1);
            else if (ev.type == TLS_EV_HANDSHAKE_DONE) done = 1;
            else if (ev.type == TLS_EV_ERROR) { fprintf(stderr, "TLS_EV_ERROR: %s\n", ev.text); failed = 1; }
        }
        if (failed) goto done_free;
        /* tls_cert_accept() above may have just produced ClientKeyExchange/CCS/Finished --
         * flush that before blocking in recv(), or we'd wait forever for a reply the peer is
         * itself waiting on us to send first. */
        out = tls_output(s, &outlen);
        if (outlen > 0) {
            if (send(fd, out, outlen, 0) != (ssize_t)outlen) { fprintf(stderr, "send failed\n"); goto done_free; }
            tls_output_done(s, outlen);
        }
        if (done) break;

        n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            fprintf(stderr, "recv failed or closed early (n=%ld, errno=%d %s)\n", (long)n, errno, strerror(errno));
            goto done_free;
        }
        if (tls_input(s, buf, (size_t)n) != 0) {
            tls_event ev2;
            fprintf(stderr, "tls_input failed\n");
            while (tls_next_event(s, &ev2)) if (ev2.type == TLS_EV_ERROR) fprintf(stderr, "  error: %s\n", ev2.text);
            goto done_free;
        }
    }

    CHECK(tls_is_established(s));
    CHECK(check_keylog(keylog, s));

    {
        static const u8 hello[] = "hello from ratchat\n";
        CHECK(tls_write(s, hello, sizeof(hello) - 1) == 0);
        {
            const u8 *out2; size_t outlen2;
            out2 = tls_output(s, &outlen2);
            if (outlen2 > 0) { send(fd, out2, outlen2, 0); tls_output_done(s, outlen2); }
        }
    }

    rc = t_fail == 0 ? 0 : -1;

done_free:
    tls_free(s);
    close(fd);
done:
    kill(child, SIGTERM);
    waitpid(child, &status, 0);
    return rc;
}

int main(void)
{
    seed_rng();

    printf("== ECDHE-RSA-AES128-GCM-SHA256 ==\n");
    run_one_handshake("build/tls_smoke.pem", "build/tls_smoke.key",
                      "ECDHE-RSA-AES128-GCM-SHA256", 15801, "build/tls_smoke_gcm.keylog");

    printf("== ECDHE-RSA-CHACHA20-POLY1305 ==\n");
    run_one_handshake("build/tls_smoke.pem", "build/tls_smoke.key",
                      "ECDHE-RSA-CHACHA20-POLY1305", 15802, "build/tls_smoke_chacha.keylog");

    printf("tls_smoke: %d passed, %d failed\n", t_pass, t_fail);
    return t_fail ? 1 : 0;
}
