#import "IRCConnection.h"
#import "UIHelpers.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "oscompat.h"

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long)0xffffffff)
#endif

#ifdef OPENSTEP
typedef int sock_len_t;                    /* 4.4BSD-era getsockopt takes int * */
#else
typedef socklen_t sock_len_t;
#endif

#define TICK_SECONDS    0.02
#define CONNECT_TIMEOUT 30
#define TICKS_PER_SEC   50

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface IRCConnection (Private)
- (void)connected;
- (void)pump;
- (void)flushPending;
- (void)queueBytes:(const unsigned char *)bytes length:(int)n;
- (void)handleLine:(const char *)line;
- (void)endWithMessage:(NSString *)msg;
@end

@implementation IRCConnection

- (id)initWithDelegate:(id)aDelegate
{
    self = [super init];
    if (!self) return nil;
    delegate = aDelegate;
    fd = -1;
    state = IRC_DISCONNECTED;
    return self;
}

- (void)dealloc
{
    [self shutdown];
    if (pendingOut) free(pendingOut);
    [host release]; [nick release]; [user release]; [realName release];
    [super dealloc];
}

- (BOOL)isConnected { return state == IRC_CONNECTED; }
- (NSString *)host { return host; }
- (NSString *)nick { return nick; }

- (BOOL)connectToHost:(NSString *)aHost port:(int)aPort nick:(NSString *)aNick
                  user:(NSString *)aUser realName:(NSString *)aRealName
{
    struct sockaddr_in sa;
    unsigned long addr;
    struct hostent *he;
    const char *h;
    int flags, rc;

    if (state != IRC_DISCONNECTED) return NO;

    host = [aHost retain]; port = aPort;
    nick = [aNick retain]; user = [aUser retain]; realName = [aRealName retain];
    h = [host cString];

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    addr = inet_addr(h);
    if (addr != INADDR_NONE) {
        sa.sin_addr.s_addr = addr;
    } else {
        he = gethostbyname(h);                     /* IPv4 only; may block briefly */
        if (!he || he->h_addrtype != AF_INET || he->h_length != 4) {
            [self endWithMessage:[NSString stringWithFormat:@"Cannot resolve host name '%@'", host]];
            return NO;
        }
        memcpy(&sa.sin_addr, he->h_addr, 4);
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { [self endWithMessage:@"Cannot create socket"]; return NO; }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    state = IRC_CONNECTING;
    connectDeadline = ticks + CONNECT_TIMEOUT * TICKS_PER_SEC;
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) [self connected];
    else if (errno != EINPROGRESS) {
        [self endWithMessage:[NSString stringWithFormat:@"Connection failed: %s", strerror(errno)]];
        return NO;
    }

    timer = [[NSTimer scheduledTimerWithTimeInterval:TICK_SECONDS target:self
                                            selector:@selector(tick:) userInfo:nil repeats:YES] retain];
    return YES;
}

- (void)connected
{
    char line[IRC_MAX_LINE];
    int n;

    state = IRC_REGISTERING;
    n = irc_fmt_nick(line, sizeof(line), [nick cString]);
    if (n > 0) [self queueBytes:(const unsigned char *)line length:n];
    n = irc_fmt_user(line, sizeof(line), [user cString], [realName cString]);
    if (n > 0) [self queueBytes:(const unsigned char *)line length:n];
    [self flushPending];
}

/* ---------------------------------------------------------------- */
/* the poll loop -- same shape as SSHSession's own                  */

- (void)tick:(NSTimer *)t
{
    if (inTick || state == IRC_ENDED) return;
    inTick = 1;
    ticks++;

    if (state == IRC_CONNECTING && fd >= 0) {
        fd_set wf;
        struct timeval tv;
        int err = 0;
        sock_len_t len = sizeof(err);
        FD_ZERO(&wf);
        FD_SET(fd, &wf);
        tv.tv_sec = 0; tv.tv_usec = 0;
        if (select(fd + 1, NULL, &wf, NULL, &tv) > 0) {
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
            if (err) [self endWithMessage:[NSString stringWithFormat:@"Connection failed: %s", strerror(err)]];
            else [self connected];
        } else if ((int)(ticks - connectDeadline) > 0) {
            [self endWithMessage:@"Connection timed out"];
        }
    } else if (state == IRC_REGISTERING || state == IRC_CONNECTED) {
        [self pump];
    }
    inTick = 0;
}

- (void)pump
{
    unsigned char buf[4096];
    int i, n;

    [self flushPending];
    for (i = 0; i < 8 && state != IRC_ENDED; i++) {
        n = recv(fd, (char *)buf, sizeof(buf), 0);
        if (n > 0) {
            size_t room = sizeof(inbuf) - inbufLen;
            size_t take = (size_t)n < room ? (size_t)n : room;
            char *nl;
            memcpy(inbuf + inbufLen, buf, take);
            inbufLen += take;
            if (take < (size_t)n) {                 /* a line longer than inbuf: drop and resync */
                SSTrace("IRCConnection: inbound line too long, discarding %u bytes", (unsigned)inbufLen);
                inbufLen = 0;
            }
            while ((nl = (char *)memchr(inbuf, '\n', inbufLen)) != NULL) {
                char line[IRC_MAX_LINE];
                size_t lineLen = (size_t)(nl - inbuf);
                size_t consumed = lineLen + 1;
                if (lineLen > 0 && inbuf[lineLen - 1] == '\r') lineLen--;
                if (lineLen >= sizeof(line)) lineLen = sizeof(line) - 1;
                memcpy(line, inbuf, lineLen);
                line[lineLen] = '\0';
                memmove(inbuf, inbuf + consumed, inbufLen - consumed);
                inbufLen -= consumed;
                [self handleLine:line];
                if (state == IRC_ENDED) return;
            }
        } else if (n == 0) {
            [self endWithMessage:@"Connection closed by remote host"];
            return;
        } else if (errno == EWOULDBLOCK || errno == EINTR) {
            break;
        } else {
            [self endWithMessage:[NSString stringWithFormat:@"Network error: %s", strerror(errno)]];
            return;
        }
    }
    [self flushPending];
}

- (void)handleLine:(const char *)line
{
    irc_message msg;

    if (!irc_parse_line(line, &msg)) return;

    if (strcmp(msg.command, "PING") == 0) {          /* protocol housekeeping: never forwarded */
        char pong[IRC_MAX_LINE];
        int n = irc_fmt_pong(pong, sizeof(pong), msg.nparams > 0 ? msg.params[0] : "");
        if (n > 0) [self queueBytes:(const unsigned char *)pong length:n];
        return;
    }
    if (state == IRC_REGISTERING && strcmp(msg.command, "001") == 0) {
        state = IRC_CONNECTED;
        if ([delegate respondsToSelector:@selector(ircConnectionDidRegister:)])
            [delegate ircConnectionDidRegister:self];
    }
    if ([delegate respondsToSelector:@selector(ircConnection:didReceiveMessage:)])
        [delegate ircConnection:self didReceiveMessage:&msg];
}

/* ---------------------------------------------------------------- */
/* outbound: same backpressure shape as PTYSession's pending buffer */

- (void)sendCommand:(const char *)line length:(int)len
{
    if (state != IRC_REGISTERING && state != IRC_CONNECTED) return;
    [self queueBytes:(const unsigned char *)line length:len];
    [self flushPending];
}

- (void)queueBytes:(const unsigned char *)bytes length:(int)n
{
    if (n <= 0) return;
    if (pendingLen + (size_t)n > pendingCap) {
        size_t newCap = pendingLen + (size_t)n;
        unsigned char *p = (unsigned char *)realloc(pendingOut, newCap);
        if (!p) return;                              /* drop rather than crash; the line is lost */
        pendingOut = p; pendingCap = newCap;
    }
    memcpy(pendingOut + pendingLen, bytes, (size_t)n);
    pendingLen += (size_t)n;
}

- (void)flushPending
{
    int w;
    if (fd < 0 || pendingLen == 0) return;
    w = send(fd, (char *)pendingOut, pendingLen, 0);
    if (w > 0) {
        memmove(pendingOut, pendingOut + w, pendingLen - (size_t)w);
        pendingLen -= (size_t)w;
    } else if (w < 0 && errno != EWOULDBLOCK && errno != EINTR) {
        [self endWithMessage:[NSString stringWithFormat:@"Network error: %s", strerror(errno)]];
    }
}

/* ---------------------------------------------------------------- */
/* teardown                                                          */

- (void)endWithMessage:(NSString *)msg
{
    if (state == IRC_ENDED) return;
    state = IRC_ENDED;
    [timer invalidate]; [timer release]; timer = nil;
    if (fd >= 0) { close(fd); fd = -1; }
    if (msg && [delegate respondsToSelector:@selector(ircConnection:didFailWithError:)])
        [delegate ircConnection:self didFailWithError:msg];
    if ([delegate respondsToSelector:@selector(ircConnectionDidEnd:)])
        [delegate ircConnectionDidEnd:self];
}

- (void)disconnectWithReason:(NSString *)reason
{
    if (state == IRC_REGISTERING || state == IRC_CONNECTED) {
        char line[IRC_MAX_LINE];
        int n = irc_fmt_quit(line, sizeof(line), reason ? [reason cString] : NULL);
        if (n > 0) { [self queueBytes:(const unsigned char *)line length:n]; [self flushPending]; }
    }
    [self endWithMessage:nil];
}

- (void)shutdown
{
    [timer invalidate]; [timer release]; timer = nil;
    if (fd >= 0) { close(fd); fd = -1; }
    state = IRC_ENDED;
}

@end
