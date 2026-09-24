/*
 * entropy_gate_smoke.m -- confirms AppController actually gates a TLS connection attempt on a
 * real, un-seeded RNG pool, rather than either (a) letting tls_start() fail fast the way it used
 * to before -showEntropyPanel existed (the real-hardware bug: "Could not start the TLS handshake"
 * connecting to a real network, traced to OPENSTEP 4.2 having no /dev/urandom worth trusting and
 * RatChat's app layer never seeding core/rng.c at all), or (b) silently skipping the seeding step
 * and connecting anyway with an under-seeded pool. Also confirms a *plaintext* connection is never
 * gated on RNG readiness at all -- IRC itself needs no randomness, only TLS does.
 *
 * This is the one test in the suite that depends on running first in a fresh process: core/rng.c's
 * pool is process-global static state with no reset function, and every other smoke test seeds it
 * deliberately before connecting (see irc_tls_smoke.m's own header). This file must never call any
 * ssh_rng_* function before the "not ready" assertions below, or the whole point of the test is
 * lost silently rather than loudly.
 * usage: entropy_gate_smoke
 */
#import "Compat.h"
#import "AppController.h"
#import "IRCConnection.h"
#include "rng.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void PSmoveto(float x, float y) { }
void PSshow(const char *s) { }
@implementation NSFont (OpenStepHostStub)
- (float)widthOfString:(NSString *)s { return [self maximumAdvancement].width; }
@end

static void spin(double seconds)
{
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
}

static int pass, fail;
#define EXPECT(cond, what) do { if (cond) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s\n", what); } } while (0)

/* A real listening socket that never accepts -- enough for a real non-blocking connect() to
 * succeed at the TCP level (the OS completes the handshake out of the listen backlog on its own)
 * without this test needing to speak IRC or TLS back; nothing here needs a handshake to actually
 * finish, only to confirm a real connection attempt was (or wasn't) made. */
static int make_listener(int *outPort)
{
    int fd;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    if (listen(fd, 1) != 0) { close(fd); return -1; }
    if (getsockname(fd, (struct sockaddr *)&sa, &salen) != 0) { close(fd); return -1; }
    *outPort = ntohs(sa.sin_port);
    return fd;
}

int main(void)
{
    int listenFdPlain, listenFdTLS, portPlain, portTLS;
    AppController *acPlain, *acTLS;
    id conn, panel;

    EXPECT(!ssh_rng_ready(), "the RNG pool starts out not ready (this test seeds nothing itself)");

    /* Two separate listeners, one per scenario below: neither is ever accept()ed (nothing here
     * needs the handshake to finish), and sharing one listener's small backlog between two
     * never-accepted connections would make the second connect() itself unreliable -- a test
     * hygiene issue, not anything AppController does wrong. */
    listenFdPlain = make_listener(&portPlain);
    listenFdTLS = make_listener(&portTLS);
    EXPECT(listenFdPlain >= 0 && listenFdTLS >= 0, "two real local listeners are up for the connection attempts below");

    [NSApplication sharedApplication];

    /* --- plaintext: must never gate on RNG readiness --- */
    acPlain = [[AppController alloc] init];
    [acPlain connectController:nil didRequestHost:@"127.0.0.1" port:portPlain nick:@"ratty"
                           user:@"ratty" realName:@"Rat Chat User" useTLS:NO];
    conn = [acPlain valueForKey:@"connection"];
    EXPECT(conn != nil, "a plaintext connection is attempted immediately, entropy pool or not");
    panel = [acPlain valueForKey:@"entropyPanel"];
    EXPECT(panel == nil, "the entropy panel never appears for a plaintext connection");
    EXPECT(!ssh_rng_ready(), "the RNG pool is still untouched after a plaintext connection attempt");
    [acPlain disconnect:nil];

    /* --- TLS, with the pool still not ready: must gate, not fail fast or connect anyway --- */
    acTLS = [[AppController alloc] init];
    [acTLS connectController:nil didRequestHost:@"127.0.0.1" port:portTLS nick:@"ratty"
                         user:@"ratty" realName:@"Rat Chat User" useTLS:YES];
    conn = [acTLS valueForKey:@"connection"];
    EXPECT(conn == nil, "a TLS connection is NOT attempted yet while the RNG pool isn't ready");
    panel = [acTLS valueForKey:@"entropyPanel"];
    EXPECT(panel != nil, "the entropy-seeding panel is shown instead");
    EXPECT([[acTLS valueForKey:@"pendingHost"] isEqualToString:@"127.0.0.1"],
           "the requested host was stashed for once entropy is ready");
    EXPECT([[acTLS valueForKey:@"pendingPort"] intValue] == portTLS,
           "the requested port was stashed too");
    EXPECT([[acTLS valueForKey:@"pendingNick"] isEqualToString:@"ratty"],
           "and the requested nick");

    /* Simulate what EntropyMeter's own mouse/key handlers do once the pool crosses the credited-
     * bits threshold: credit real bits (not junk), then invoke the same callback they call. */
    ssh_rng_add("entropy gate smoke test seed", 30, 256);
    EXPECT(ssh_rng_ready(), "the pool is credited enough now (test-supplied, standing in for mouse wiggling)");
    [acTLS entropyReady];

    conn = [acTLS valueForKey:@"connection"];
    EXPECT(conn != nil, "the stashed TLS connection is attempted once the pool is ready");
    panel = [acTLS valueForKey:@"entropyPanel"];
    EXPECT(panel == nil, "the entropy panel is torn down");
    spin(0.3);
    EXPECT([[conn valueForKey:@"state"] intValue] == IRC_TLS_HANDSHAKING,
           "the real TCP connect succeeded and a real TLS handshake actually started");
    [acTLS disconnect:nil];

    close(listenFdPlain);
    close(listenFdTLS);
    printf("entropy gate smoke: %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
