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

/* collects what a view sends to its host */
@interface Sink : NSObject { int total; } - (int)total; @end
@implementation Sink
- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n { total += n; }
- (void)terminalView:(id)tv resizedToCols:(int)c rows:(int)r { }
- (int)total { return total; }
@end

static void put(TerminalView *tv, const char *s) { [tv writeBytes:(const unsigned char *)s length:(int)strlen(s)]; }

/* pixels of a rectangle of the view, drawn on their own, equal those of the same area of the whole view drawn at once */
static int partial_matches_full(TerminalView *tv, NSRect part)
{
    NSBitmapImageRep *full = [tv bitmapImageRepForCachingDisplayInRect:[tv bounds]];
    NSBitmapImageRep *piece = [tv bitmapImageRepForCachingDisplayInRect:part];
    int x, y, ox, oy;

    [tv cacheDisplayInRect:[tv bounds] toBitmapImageRep:full];
    [tv cacheDisplayInRect:part toBitmapImageRep:piece];
    if ([piece pixelsWide] != (int)part.size.width || [full pixelsWide] != (int)[tv bounds].size.width) return 1;   /* (scaled screen: skip) */
    ox = (int)part.origin.x;
    oy = (int)([tv bounds].size.height - NSMaxY(part));
    for (y = 0; y < [piece pixelsHigh]; y++) {
        for (x = 0; x < [piece pixelsWide]; x++) {
            NSColor *a = [[piece colorAtX:x y:y] colorUsingColorSpaceName:NSCalibratedRGBColorSpace];
            NSColor *b = [[full colorAtX:ox + x y:oy + y] colorUsingColorSpaceName:NSCalibratedRGBColorSpace];

            if (fabs([a redComponent] - [b redComponent]) + fabs([a greenComponent] - [b greenComponent]) +
                fabs([a blueComponent] - [b blueComponent]) > 0.02) return 0;
        }
    }
    return 1;
}

int main(void)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    FakeServer fs;
    int port;
    AppController *ac;
    IRCChannelSession *status, *chan;

    [NSApplication sharedApplication];

    /* ---- the redraw frame cap, dirty columns and the paste confirmation, on a view of its own ---- */
    {
        TerminalView *v = [[TerminalView alloc] initWithFrame:NSMakeRect(0, 0, 640, 400)];
        Sink *sink = [[Sink alloc] init];
        int before, i;
        float full, small;
        NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 640, 400) styleMask:NSTitledWindowMask
                                                     backing:NSBackingStoreBuffered defer:NO];

        [[w contentView] addSubview:v];
        [v setDelegate:sink];
        [v setMaxFPS:10.0];                                         /* a frame every 100 ms */
        EXPECT([v maxFPS] > 9.9 && [v maxFPS] < 10.1, "the frame cap is settable");
        put(v, "a");
        EXPECT([v flushCount] == 1, "the first output after quiet redraws at once");
        before = [v flushCount];
        for (i = 0; i < 200; i++) put(v, "x");
        [v flushDisplayIfDue];
        EXPECT([v flushCount] == before, "a burst of output inside one frame interval is not redrawn per write");
        spin(0.15);
        [v flushDisplayIfDue];
        EXPECT([v flushCount] == before + 1, "...but once the interval has passed the pending output is redrawn, once");
        [v flushDisplayIfDue];
        EXPECT([v flushCount] == before + 1, "nothing pending, nothing redrawn");
        /* a deferred redraw happens on its own, with nobody ticking */
        put(v, "q");
        put(v, "r");
        before = [v flushCount];
        spin(0.25);
        EXPECT([v flushCount] == before + 1, "output deferred by the cap is redrawn by the view's own timer, without any tick");
        [v setMaxFPS:0.0];
        before = [v flushCount];
        for (i = 0; i < 5; i++) put(v, "y");
        EXPECT([v flushCount] == before + 5, "with the cap off every write redraws");
        [v setMaxFPS:10.0];
        spin(0.15);

        /* dirty columns: one character changing redraws a few cells, not the row */
        put(v, "\033[2J\033[1;1H");
        spin(0.15);
        put(v, "0123456789012345678901234567890123456789012345678901234567890123456789");
        [v flushDisplay];
        full = [v lastFlushArea];
        spin(0.15);
        put(v, "\033[1;40Hz");
        [v flushDisplay];
        small = [v lastFlushArea];
        EXPECT(small > 0.0 && small * 4.0 < full, "one changed character asks AppKit to redraw a few cells, not the whole row");
        put(v, "\033[2J");
        [v flushDisplay];
        EXPECT([v lastFlushArea] >= [v bounds].size.width * [v bounds].size.height * 0.5, "clearing the screen redraws all of it");

        /* a column-limited redraw paints exactly what the full one does (coloured cells, so there is something to compare) */
        put(v, "\033[2J\033[1;1H");
        for (i = 0; i < 6; i++) put(v, "\033[41m  \033[42m  \033[44m  \033[46m  \033[0m AB \033[1;45mCD\033[0m  \n");
        [v flushDisplay];
        {
            NSRect b = [v bounds];
            NSRect piece = NSMakeRect(60.0, b.size.height - 90.0, 130.0, 40.0);

            EXPECT(partial_matches_full(v, piece), "a redraw limited to some columns paints the same pixels as a full redraw there");
            piece = NSMakeRect(3.0, b.size.height - 40.0, 40.0, 30.0);
            EXPECT(partial_matches_full(v, piece), "...also at the left edge");
        }

        /* pasting several lines asks first (unless the shell takes bracketed paste); one line never does */
        {
            NSPasteboard *pb = [NSPasteboard generalPasteboard];

            [pb declareTypes:[NSArray arrayWithObject:NSStringPboardType] owner:nil];
            [pb setString:@"ls\npwd\n" forType:NSStringPboardType];
            [v setPasteAnswer:0];
            before = [sink total];
            [v paste:nil];
            EXPECT([sink total] == before, "pasting two lines and answering Cancel sends nothing");
            [v setPasteAnswer:1];
            [v paste:nil];
            EXPECT([sink total] > before, "...and answering Paste sends it");
            [pb declareTypes:[NSArray arrayWithObject:NSStringPboardType] owner:nil];
            [pb setString:@"ls\n" forType:NSStringPboardType];
            [v setPasteAnswer:0];
            before = [sink total];
            [v paste:nil];
            EXPECT([sink total] > before, "a single line (even with its newline) is pasted without asking");
            [pb declareTypes:[NSArray arrayWithObject:NSStringPboardType] owner:nil];
            [pb setString:@"a\r\nb\r\nc" forType:NSStringPboardType];
            before = [sink total];
            [v paste:nil];
            EXPECT([sink total] == before, "CRLF lines count as lines");
            [v setConfirmsMultilinePaste:NO];
            [v paste:nil];
            EXPECT([sink total] > before, "the confirmation can be switched off");
            [v setConfirmsMultilinePaste:YES];
            [v terminal]->bracketed_paste = 1;
            before = [sink total];
            [v paste:nil];
            EXPECT([sink total] > before, "with bracketed paste on the shell holds the paste back itself, so nothing is asked");
        }
        [w release];
        [sink release];
        [v release];
    }

    EXPECT(fs_listen(&fs, &port), "a fake IRC server can bind and listen on 127.0.0.1");

    ac = [[AppController alloc] init];
    [ac connectController:nil didRequestHost:@"127.0.0.1" port:port nick:@"ratty" user:@"ratty"
                  realName:@"Rat Chat User" useTLS:NO];
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

    /* NAMES (353, possibly several lines, then 366) populates the channel's own member list --
     * checked directly against the tracked array, not the screen, since this has no visible line
     * of its own. alice arrives op-prefixed ("@alice"), matching a real server's own NAMES
     * format, and must still be stored as plain "alice" -- the prefix is stripped so it matches
     * exactly what a later JOIN/PART/QUIT/NICK message prefix for her would say. */
    fs_send(&fs, ":fake.server 353 ratty = #test :ratty @alice bob");
    fs_send(&fs, ":fake.server 366 ratty #test :End of /NAMES list.");
    spin(0.3);
    EXPECT([[chan members] containsObject:@"ratty"] && [[chan members] containsObject:@"alice"] &&
           [[chan members] containsObject:@"bob"], "RPL_NAMREPLY/RPL_ENDOFNAMES populates the channel member list (@-prefix stripped)");

    /* A JOIN from someone new adds a member; a PART removes one -- both reflected in the tracked
     * list, not just the displayed system line. */
    fs_send(&fs, ":carol!carol@example.com JOIN #test");
    EXPECT(wait_for_text(chan, @"carol has joined #test", 5.0), "someone else's JOIN is shown");
    spin(0.2);
    EXPECT([[chan members] containsObject:@"carol"], "someone else's JOIN adds them to the member list");

    fs_send(&fs, ":bob!bob@example.com PART #test :done for now");
    EXPECT(wait_for_text(chan, @"bob has left #test (done for now)", 5.0), "someone else's PART is shown");
    spin(0.2);
    EXPECT(![[chan members] containsObject:@"bob"], "PART removes them from the member list");

    /* Someone else's message, and a CTCP ACTION, arrive from the fake server. */
    fs_send(&fs, ":alice!alice@example.com PRIVMSG #test :hello there");
    EXPECT(wait_for_text(chan, @"<alice> hello there", 5.0), "an incoming channel PRIVMSG is displayed");
    fs_send(&fs, ":alice!alice@example.com PRIVMSG #test :\001ACTION waves\001");
    EXPECT(wait_for_text(chan, @"* alice waves", 5.0), "a CTCP ACTION is displayed as \"* nick action\"");

    /* A CTCP VERSION request is answered automatically with a NOTICE (never a PRIVMSG, per CTCP
     * convention), addressed back to the requester directly, not the channel it arrived through --
     * and it must not pop open a query window for alice (checked further down: no query for her). */
    fs_send(&fs, ":alice!alice@example.com PRIVMSG #test :\001VERSION\001");
    EXPECT(fs_expect(&fs, @"NOTICE alice :\001VERSION RatChat", 5.0), "a CTCP VERSION request gets an automatic NOTICE reply");
    EXPECT(find_session(ac, @"alice") == nil, "a CTCP request does not open a query window for the requester");

    /* The user replies; the outgoing PRIVMSG must reach the real socket, and echo locally too
     * (the server never echoes a client's own PRIVMSG back). */
    [ac channelSession:chan didSubmitLine:@"hi alice"];
    EXPECT(fs_expect(&fs, @"PRIVMSG #test :hi alice", 5.0), "typed text sends a real PRIVMSG over the socket");
    EXPECT(wait_for_text(chan, @"<ratty> hi alice", 2.0), "the outgoing message is echoed locally");

    /* /me and /nick */
    [ac channelSession:chan didSubmitLine:@"/me tests things"];
    EXPECT(fs_expect(&fs, @"\001ACTION tests things\001", 5.0), "/me sends a CTCP ACTION");
    EXPECT(wait_for_text(chan, @"* ratty tests things", 2.0), "/me echoes locally as an action");

    /* Tab-completion and Up/Down history recall both live behind the NSControl delegate hook
     * (-control:textView:doCommandBySelector:), driven here the same way AppKit would drive it
     * for a real Tab/Up keypress in the field editor -- not the higher-level -channelSession:
     * didSubmitLine:/-inputSubmitted: shortcuts everything above uses. alice is still a member
     * (added via NAMES, never removed), so "al"+Tab should complete unambiguously. */
    {
        NSTextField *field = [chan valueForKey:@"inputField"];
        [field setStringValue:@"al"];
        [chan control:nil textView:nil doCommandBySelector:@selector(insertTab:)];
        EXPECT([[field stringValue] isEqualToString:@"alice: "],
               "Tab-completes an unambiguous member prefix, with a \": \" separator at line start");
        [field setStringValue:[[field stringValue] stringByAppendingString:@"hey"]];
        [chan inputSubmitted:nil];
        EXPECT(fs_expect(&fs, @"PRIVMSG #test :alice: hey", 5.0), "the Tab-completed line is sent correctly");

        /* Up-arrow recalls the last submitted line; Enter re-submits it verbatim. */
        [chan control:nil textView:nil doCommandBySelector:@selector(moveUp:)];
        EXPECT([[field stringValue] isEqualToString:@"alice: hey"], "Up-arrow recalls the last submitted line");
        [chan inputSubmitted:nil];
        EXPECT(fs_expect(&fs, @"PRIVMSG #test :alice: hey", 5.0), "the recalled line re-sends correctly");
    }

    /* A QUIT for someone tracked as a channel member (alice, from NAMES) must show up in that
     * channel's own window now, not just the status window -- the gap the member list was
     * specifically added to close. */
    fs_send(&fs, ":alice!alice@example.com QUIT :leaving");
    EXPECT(wait_for_text(chan, @"alice has quit (leaving)", 5.0), "a member's QUIT is shown in their channel window");
    spin(0.2);
    EXPECT(![[chan members] containsObject:@"alice"], "QUIT removes them from the member list");

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
