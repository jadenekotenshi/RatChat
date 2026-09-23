/*
 * irc_smoke.m -- drives a real AppController/IRCConnection/IRCChannelSession stack against a
 * scripted fake IRC server (a real TCP listener on 127.0.0.1, not a mock), on the host. Mirrors
 * pty_smoke.m's philosophy: exercise the actual runtime behavior (a real non-blocking connect,
 * real recv()/send(), the real 20ms poll loop) rather than trusting it "looks like" SSHSession's
 * already-proven pattern.
 * usage: irc_smoke
 */
#import "Compat.h"
#import "AppController.h"
#import "IRCConnection.h"
#import "IRCChannelSession.h"
#import "TerminalView.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

/* ---------------------------------------------------------------- */
/* a tiny fake IRC server: a real listening socket, non-blocking accept/recv, line-buffered */

typedef struct { int listenFd, fd; char buf[4096]; size_t len; } FakeServer;

static int fs_listen(FakeServer *fs, int *outPort)
{
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    int flags;

    memset(fs, 0, sizeof(*fs));
    fs->fd = -1;
    fs->listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (fs->listenFd < 0) return 0;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fs->listenFd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return 0;
    if (listen(fs->listenFd, 1) != 0) return 0;
    if (getsockname(fs->listenFd, (struct sockaddr *)&sa, &salen) != 0) return 0;
    *outPort = ntohs(sa.sin_port);
    flags = fcntl(fs->listenFd, F_GETFL, 0);
    fcntl(fs->listenFd, F_SETFL, flags | O_NONBLOCK);
    return 1;
}

static int fs_accept(FakeServer *fs, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        int c = accept(fs->listenFd, NULL, NULL);
        if (c >= 0) {
            int flags = fcntl(c, F_GETFL, 0);
            fcntl(c, F_SETFL, flags | O_NONBLOCK);
            fs->fd = c;
            return 1;
        }
        spin(0.02);
        waited += 0.02;
    }
    return 0;
}

static void fs_send(FakeServer *fs, const char *line)
{
    char buf[512];
    size_t n = strlen(line);
    memcpy(buf, line, n);
    buf[n++] = '\r'; buf[n++] = '\n';
    send(fs->fd, buf, n, 0);
}

/* Waits for a complete line containing `needle` to arrive from the client. */
static int fs_expect(FakeServer *fs, NSString *needle, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        char tmp[2048];
        int n = recv(fs->fd, tmp, sizeof(tmp), 0);
        if (n > 0) {
            size_t room = sizeof(fs->buf) - fs->len;
            size_t take = (size_t)n < room ? (size_t)n : room;
            memcpy(fs->buf + fs->len, tmp, take);
            fs->len += take;
        }
        {
            /* Only the matched needle and anything before it is consumed -- NICK and USER, e.g.,
             * are queued together and typically arrive in one recv() chunk, so a later fs_expect
             * for USER must still see whatever followed NICK in that same chunk. */
            NSString *have = [[[NSString alloc] initWithBytes:fs->buf length:fs->len
                                                       encoding:NSASCIIStringEncoding] autorelease];
            NSRange r = [have rangeOfString:needle];
            if (r.length > 0) {
                size_t consumed = r.location + r.length;
                memmove(fs->buf, fs->buf + consumed, fs->len - consumed);
                fs->len -= consumed;
                return 1;
            }
        }
        spin(0.02);
        waited += 0.02;
    }
    return 0;
}

/* ---------------------------------------------------------------- */
/* peeking at AppController's private state -- KVC is fine here: this file only ever builds for
 * the host test target, never for the real OPENSTEP build (see Makefile, not Makefile.openstep). */

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

static TerminalView *find_terminal(NSWindow *w)
{
    NSEnumerator *e = [[[w contentView] subviews] objectEnumerator];
    id v;
    while ((v = [e nextObject])) if ([v isKindOfClass:[TerminalView class]]) return v;
    return nil;
}

static NSString *screen_text(IRCChannelSession *cs)
{
    TerminalView *tv = find_terminal([cs window]);
    [tv selectAll:nil];
    return [tv selectedText];
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

static int wait_for_text(IRCChannelSession *cs, NSString *needle, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        if ([screen_text(cs) rangeOfString:needle].length > 0) return 1;
        spin(0.02);
        waited += 0.02;
    }
    return 0;
}

static int pass, fail;
#define EXPECT(cond, what) do { if (cond) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s\n", what); } } while (0)

int main(void)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    FakeServer fs;
    int port;
    AppController *ac;
    IRCChannelSession *status, *chan;

    [NSApplication sharedApplication];
    EXPECT(fs_listen(&fs, &port), "a fake IRC server can bind and listen on 127.0.0.1");

    ac = [[AppController alloc] init];
    [ac connectController:nil didRequestHost:@"127.0.0.1" port:port nick:@"ratty" user:@"ratty"
                  realName:@"Rat Chat User"];
    EXPECT(fs_accept(&fs, 5.0), "the fake server accepts a real, non-blocking connect from IRCConnection");

    EXPECT(fs_expect(&fs, @"NICK ratty", 5.0), "registration sends NICK");
    EXPECT(fs_expect(&fs, @"USER ratty", 2.0), "registration sends USER");
    fs_send(&fs, ":fake.server 001 ratty :Welcome to the fake network");
    EXPECT(wait_for_session(ac, nil, 5.0), "registration (001) opens the status window");
    status = find_session(ac, nil);
    EXPECT(wait_for_text(status, @"Connected to 127.0.0.1 as ratty", 5.0),
           "the status window shows the connection banner");

    /* Simulate the user typing "/join #test" in the status window. */
    [ac channelSession:status didSubmitLine:@"/join #test"];
    EXPECT(fs_expect(&fs, @"JOIN #test", 5.0), "/join sends a real JOIN command over the socket");
    fs_send(&fs, ":ratty!ratty@localhost JOIN #test");
    EXPECT(wait_for_session(ac, @"#test", 5.0), "the server's JOIN confirmation opens a channel window");
    chan = find_session(ac, @"#test");
    EXPECT(wait_for_text(chan, @"Joined #test", 2.0), "the channel window shows the join confirmation");

    /* Someone else's message, and a CTCP ACTION, arrive from the fake server. */
    fs_send(&fs, ":alice!alice@example.com PRIVMSG #test :hello there");
    EXPECT(wait_for_text(chan, @"<alice> hello there", 5.0), "an incoming channel PRIVMSG is displayed");
    fs_send(&fs, ":alice!alice@example.com PRIVMSG #test :\001ACTION waves\001");
    EXPECT(wait_for_text(chan, @"* alice waves", 5.0), "a CTCP ACTION is displayed as \"* nick action\"");

    /* The user replies; the outgoing PRIVMSG must reach the real socket, and echo locally too
     * (the server never echoes a client's own PRIVMSG back). */
    [ac channelSession:chan didSubmitLine:@"hi alice"];
    EXPECT(fs_expect(&fs, @"PRIVMSG #test :hi alice", 5.0), "typed text sends a real PRIVMSG over the socket");
    EXPECT(wait_for_text(chan, @"<ratty> hi alice", 2.0), "the outgoing message is echoed locally");

    /* /me and /nick */
    [ac channelSession:chan didSubmitLine:@"/me tests things"];
    EXPECT(fs_expect(&fs, @"\001ACTION tests things\001", 5.0), "/me sends a CTCP ACTION");
    EXPECT(wait_for_text(chan, @"* ratty tests things", 2.0), "/me echoes locally as an action");

    [ac channelSession:chan didSubmitLine:@"/nick rattier"];
    EXPECT(fs_expect(&fs, @"NICK rattier", 5.0), "/nick sends a real NICK command");
    fs_send(&fs, ":ratty!ratty@localhost NICK rattier");
    EXPECT(wait_for_text(status, @"You are now known as rattier", 5.0), "the server's NICK confirmation updates our own nick");

    /* Disconnect: QUIT goes out, and the socket end is noticed. */
    [ac disconnect:nil];
    EXPECT(fs_expect(&fs, @"QUIT", 5.0), "/disconnect sends a real QUIT command");
    EXPECT(wait_for_text(status, @"Disconnected.", 5.0), "losing the connection is reflected in the status window");

    printf("irc smoke: %d passed, %d failed\n", pass, fail);
    [pool release];
    return fail ? 1 : 0;
}
