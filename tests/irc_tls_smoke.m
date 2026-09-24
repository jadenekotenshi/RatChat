/*
 * irc_tls_smoke.m -- drives a real AppController/IRCConnection stack, with TLS turned on, against
 * a real local `openssl s_server` (spawned by this program itself), on the host. Mirrors
 * irc_smoke.m's own philosophy (a real listener, real non-blocking sockets, the real 20ms poll
 * loop) plus tls_smoke.c's own technique for using real OpenSSL as the TLS peer, applied here to
 * the actual app-layer wiring (IRCConnection's useTLS path, ConnectController's "Use TLS" switch
 * plumbing, AppController's TLS pin store) rather than to core/tls.c directly.
 *
 * The TLS_EV_CERT trust dialog is a real, synchronous, modal NSRunAlertPanel -- there is no
 * headless way to click it, so this test pre-seeds a matching pin (computed by the Makefile via
 * `openssl x509 ... | openssl dgst -sha256`, the same value core/tls_pins.c itself would compute)
 * before connecting, so tlspin_check() returns TLSPIN_MATCH and the dialog never appears. (An
 * unseeded RNG hits the exact same dialog from a different angle: tls_start() fails fast with
 * "not enough entropy," which AppController's own existing -ircConnection:didFailWithError:
 * reports via the *same* NSRunAlertPanel -- this took a real lldb backtrace of a "hung" first
 * draft to actually track down, since nothing about it looks like a hang from the caller's side;
 * see the RNG seeding below, the fix once found.)
 * usage: irc_tls_smoke <port> <cert.pem> <key.pem> <pins-file>
 */
#import "Compat.h"
#import "AppController.h"
#import "IRCConnection.h"
#import "IRCChannelSession.h"
#import "TerminalView.h"
#include "rng.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void PSmoveto(float x, float y) { }
void PSshow(const char *s) { }
@implementation NSFont (OpenStepHostStub)
- (float)widthOfString:(NSString *)s { return [self maximumAdvancement].width; }
@end

static void spin(double seconds)
{
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
}

static IRCChannelSession *find_session(AppController *ac, NSString *target)
{
    NSArray *sessions = [ac valueForKey:@"sessions"];
    NSEnumerator *e = [sessions objectEnumerator];
    IRCChannelSession *cs;
    while ((cs = [e nextObject])) {
        if (target == nil && [cs kind] == IRC_TARGET_STATUS) return cs;
        if (target && [[cs target] isEqualToString:target]) return cs;
    }
    return nil;
}

static int wait_for_session(AppController *ac, NSString *target, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        if (find_session(ac, target)) return 1;
        spin(0.02);
        waited += 0.02;
    }
    return 0;
}

static int pass, fail;
#define EXPECT(cond, what) do { if (cond) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s\n", what); } } while (0)

/* Waits until `needle` shows up in the server's own log file -- the real proof that bytes we
 * encrypted and sent were correctly decrypted by real, independent OpenSSL. */
static int log_contains(const char *path, const char *needle, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        FILE *f = fopen(path, "r");
        if (f) {
            char line[2048];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, needle)) { fclose(f); return 1; }
            }
            fclose(f);
        }
        spin(0.05);
        waited += 0.05;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int port, serverToClientPipe[2];
    pid_t child;
    AppController *ac;
    IRCChannelSession *status;
    const char *cert, *key, *pinsFile, *logPath = "build/irc_tls_smoke_server.log";

    if (argc != 5) { fprintf(stderr, "usage: irc_tls_smoke <port> <cert.pem> <key.pem> <pins-file>\n"); return 1; }
    port = atoi(argv[1]); cert = argv[2]; key = argv[3]; pinsFile = argv[4];

    if (!ssh_rng_ready()) {
        if (ssh_rng_seed_system() == 0) ssh_rng_add("irc tls smoke", 14, 256);
    }

    /* Fork the real openssl s_server *before* touching Cocoa/AppKit at all: fork() in a process
     * that has already initialized NSApplication/the Objective-C runtime's own internal locks is
     * a well-known hazard. tls_smoke.c, pure C with no Cocoa involvement at all, never had to
     * think about this. A blocking pipe on the child's stdin (instead of an immediately-EOF
     * /dev/null) matters too: s_server relays stdin to the client via SSL_write even with
     * -quiet, and an EOF'd stdin makes it call SSL_write with length 0, which is treated as an
     * error and tears the connection down -- see tls_smoke.c's own header for how that was
     * found. Keeping the write end open is also how this test later scripts a welcome line back
     * to the client once it's registered enough to want one. */
    if (pipe(serverToClientPipe) != 0) { fprintf(stderr, "pipe failed\n"); return 1; }
    child = fork();
    if (child == 0) {
        char portbuf[16];
        int logfd = open(logPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        sprintf(portbuf, "%d", port);
        close(serverToClientPipe[1]);
        dup2(serverToClientPipe[0], 0);
        if (logfd >= 0) { dup2(logfd, 1); dup2(logfd, 2); }
        execlp("openssl", "openssl", "s_server", "-cert", cert, "-key", key,
               "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-accept", portbuf,
               "-msg", "-debug", "-quiet", "-naccept", "1", (char *)NULL);
        _exit(127);
    }
    close(serverToClientPipe[0]);

    [NSApplication sharedApplication];
    ac = [[AppController alloc] init];
    [ac setTLSPinsPath:[NSString stringWithCString:pinsFile]];
    [ac connectController:nil didRequestHost:@"127.0.0.1" port:port nick:@"ratty" user:@"ratty"
                  realName:@"Rat Chat User" useTLS:YES];

    EXPECT(log_contains(logPath, "NICK ratty", 10.0), "the TLS handshake completes and NICK reaches the real server, decrypted correctly");
    EXPECT(log_contains(logPath, "USER ratty", 2.0), "USER reaches the real server too");

    /* Script the server's own welcome line back over the same TLS connection, the same way
     * irc_smoke.m's fake server scripts a plaintext one -- proving the decrypt side of the round
     * trip too, not just the encrypt side the log check above already covers. */
    write(serverToClientPipe[1], ":fake.server 001 ratty :Welcome to fake IRC\r\n", 46);
    EXPECT(wait_for_session(ac, nil, 5.0), "the scripted 001 (decrypted, over real TLS) completes registration and opens the status window");
    status = find_session(ac, nil);
    EXPECT(status != nil, "the status session exists");

    [ac disconnect:nil];
    kill(child, SIGTERM);
    waitpid(child, NULL, 0);

    printf("irc tls smoke: %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
