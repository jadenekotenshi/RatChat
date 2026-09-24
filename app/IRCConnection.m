#import "IRCConnection.h"
#import "UIHelpers.h"
#include <stdio.h>
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
#include "tls_pins.h"
#include "x509.h"
#include "der.h"
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
- (void)feedPlaintext:(const unsigned char *)bytes length:(int)n;
- (void)handleLine:(const char *)line;
- (void)endWithMessage:(NSString *)msg;
- (void)sendRegistration;
- (void)flushTLSOutput;
- (BOOL)drainTLSEvents;                       /* returns NO if the connection ended while draining */
- (void)handleTLSCert:(const tls_event *)ev;
- (NSString *)tlsValidityWarningForCert:(const tls_event *)ev;
@end

@implementation IRCConnection

- (id)initWithDelegate:(id)aDelegate tlsPinsPath:(NSString *)aTlsPinsPath
{
    self = [super init];
    if (!self) return nil;
    delegate = aDelegate;
    fd = -1;
    state = IRC_DISCONNECTED;
    tlsPinsPath = [aTlsPinsPath retain];
    return self;
}

- (void)dealloc
{
    [self shutdown];
    if (pendingOut) free(pendingOut);
    if (tls) tls_free(tls);
    [host release]; [nick release]; [user release]; [realName release]; [tlsPinsPath release];
    [super dealloc];
}

- (BOOL)isConnected { return state == IRC_CONNECTED; }
- (NSString *)host { return host; }
- (NSString *)nick { return nick; }

- (NSString *)localAddress
{
    struct sockaddr_in sa;
    sock_len_t len = sizeof(sa);
    if (fd < 0 || getsockname(fd, (struct sockaddr *)&sa, &len) != 0) return nil;
    return [NSString stringWithCString:inet_ntoa(sa.sin_addr)];
}

- (BOOL)connectToHost:(NSString *)aHost port:(int)aPort nick:(NSString *)aNick
                  user:(NSString *)aUser realName:(NSString *)aRealName useTLS:(BOOL)wantTLS
{
    struct sockaddr_in sa;
    unsigned long addr;
    struct hostent *he;
    const char *h;
    int flags, rc;

    if (state != IRC_DISCONNECTED) return NO;

    host = [aHost retain]; port = aPort;
    nick = [aNick retain]; user = [aUser retain]; realName = [aRealName retain];
    useTLS = wantTLS;
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
    if (useTLS) {
        state = IRC_TLS_HANDSHAKING;
        tlsDeadline = ticks + CONNECT_TIMEOUT * TICKS_PER_SEC;
        tls = tls_new([host cString]);
        if (!tls || tls_start(tls) != 0) {
            [self endWithMessage:@"Could not start the TLS handshake"];
            return;
        }
        [self flushTLSOutput];
        return;
    }
    state = IRC_REGISTERING;
    [self sendRegistration];
}

- (void)sendRegistration
{
    char line[IRC_MAX_LINE];
    int n;

    n = irc_fmt_nick(line, sizeof(line), [nick cString]);
    if (n > 0) [self sendCommand:line length:n];
    n = irc_fmt_user(line, sizeof(line), [user cString], [realName cString]);
    if (n > 0) [self sendCommand:line length:n];
}

/* ---------------------------------------------------------------- */
/* TLS: everything else in this file stays as-is -- the record layer is
 * entirely on the far side of tls_input()/tls_output(), so the existing
 * non-blocking connect/select/recv/send machinery above and the inbuf
 * line-splitting below never need to know TLS is involved at all. */

- (void)flushTLSOutput
{
    const unsigned char *out;
    size_t outlen;
    if (!tls) return;
    out = tls_output(tls, &outlen);
    if (outlen > 0) {
        [self queueBytes:out length:(int)outlen];
        tls_output_done(tls, outlen);
    }
    [self flushPending];
}

/* Drains every event tls_input() just produced. Returns NO if the connection ended (a fatal
 * error, or the peer's close_notify) so the caller can stop touching `self` right away -- the
 * same shape SSHSession.m's own -processEvents uses for ssh_next_event(). */
- (BOOL)drainTLSEvents
{
    tls_event ev;
    while (tls_next_event(tls, &ev)) {
        switch (ev.type) {
        case TLS_EV_CERT:
            [self handleTLSCert:&ev];
            break;
        case TLS_EV_HANDSHAKE_DONE:
            state = IRC_REGISTERING;
            [self sendRegistration];
            break;
        case TLS_EV_DATA:
            [self feedPlaintext:ev.data length:(int)ev.len];
            if (state == IRC_ENDED) return NO;
            break;
        case TLS_EV_ERROR:
            [self endWithMessage:[NSString stringWithFormat:@"TLS error: %s", ev.text]];
            return NO;
        case TLS_EV_CLOSED:
            [self endWithMessage:@"Connection closed by remote host"];
            return NO;
        default:
            break;
        }
        if (state == IRC_ENDED) return NO;
    }
    return YES;
}

/* Best-effort, display-only, never gates anything: OPENSTEP's own NSCalendarDate reliability is
 * unconfirmed [V] (nothing in this project family has exercised more of it than ui_timestamp()'s
 * own single "%H:%M" format so far), and a certificate's validity window plays no part in this
 * project's TOFU trust decision anyway (see the TLS plan -- pinning is about "is this the same
 * server identity," not chain/date validation). If this parse or comparison fails or comes out
 * wrong for any reason, the only possible outcome is a missing or misleading FYI line in the
 * dialog text, never a wrongly accepted or wrongly rejected certificate. Local time vs. the
 * certificate's own UTC times is a real, accepted imprecision here (up to ~14 hours skew) --
 * fine for a warning about a validity window that is ordinarily months or years wide. */
- (NSString *)tlsValidityWarningForCert:(const tls_event *)ev
{
    NSString *warning = @"";
    x509_cert cert;
    const char *err;

    x509_cert_init(&cert);
    if (x509_parse_leaf(ev->data, ev->len, &cert, &err) == 0) {
        NSCalendarDate *now = [NSCalendarDate calendarDate];
        NSString *nowStr = [now descriptionWithCalendarFormat:@"%Y %m %d %H %M %S"];
        der_time nowt;
        if (sscanf([nowStr cString], "%d %d %d %d %d %d",
                   &nowt.year, &nowt.month, &nowt.day, &nowt.hour, &nowt.min, &nowt.sec) == 6) {
            if (der_time_cmp(&nowt, &cert.not_before) < 0) {
                warning = @"\n\nWARNING: this certificate is not yet valid.";
            } else if (der_time_cmp(&nowt, &cert.not_after) > 0) {
                warning = @"\n\nWARNING: this certificate has expired.";
            }
        }
    }
    x509_cert_free(&cert);
    return warning;
}

/* Mirrors SSHSession.m's own -handleHostKey: exactly: check the pin store first (a MATCH never
 * prompts at all), differentiate an unseen certificate from a changed one, and only tlspin_add()
 * on the "Connect"/first-trust path -- a changed certificate is never written back automatically. */
- (void)handleTLSCert:(const tls_event *)ev
{
    NSString *fp = [NSString stringWithCString:ev->text];
    NSString *cn = [NSString stringWithCString:ev->text2];
    NSString *warning = [self tlsValidityWarningForCert:ev];
    int r = tlspin_check([tlsPinsPath cString], [host cString], port, ev->data, ev->len);
    int ans;

    if (r == TLSPIN_MATCH) { tls_cert_accept(tls, 1); return; }

    if (r == TLSPIN_UNKNOWN) {
        ans = NSRunAlertPanel(@"Unknown certificate",
            @"The authenticity of host '%@' can't be established.\n\nSubject: %@\nFingerprint: %@%@\n\n\
If you trust this host, connect to remember its certificate.",
            @"Connect", @"Cancel", nil, host, cn, fp, warning);
        if (ans == NSAlertDefaultReturn) {
            tlspin_add([tlsPinsPath cString], [host cString], port, ev->data, ev->len);
            tls_cert_accept(tls, 1);
        } else {
            tls_cert_accept(tls, 0);
        }
        return;
    }

    /* TLSPIN_CHANGED: the safe answer is the default button. */
    ans = NSRunAlertPanel(@"WARNING: CERTIFICATE HAS CHANGED",
        @"The certificate for '%@' is different from the one saved in %@.\n\n\
Someone may be eavesdropping on this connection, or the host's certificate was legitimately renewed.\n\n\
New fingerprint:\n%@%@",
        @"Cancel", @"Connect Once", nil, host, tlsPinsPath, fp, warning);
    tls_cert_accept(tls, ans == NSAlertAlternateReturn ? 1 : 0);
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
    } else if (state == IRC_TLS_HANDSHAKING && (int)(ticks - tlsDeadline) > 0) {
        [self endWithMessage:@"TLS handshake timed out"];
    } else if (state == IRC_TLS_HANDSHAKING || state == IRC_REGISTERING || state == IRC_CONNECTED) {
        [self pump];
    }
    inTick = 0;
}

- (void)pump
{
    unsigned char buf[4096];
    int i, n;

    [self flushPending];
    if (useTLS) [self flushTLSOutput];
    for (i = 0; i < 8 && state != IRC_ENDED; i++) {
        n = recv(fd, (char *)buf, sizeof(buf), 0);
        if (n > 0) {
            if (useTLS) {
                if (tls_input(tls, buf, (size_t)n) != 0) {
                    tls_event ev;
                    NSString *msg = @"TLS error";
                    while (tls_next_event(tls, &ev)) if (ev.type == TLS_EV_ERROR) msg = [NSString stringWithFormat:@"TLS error: %s", ev.text];
                    [self endWithMessage:msg];
                    return;
                }
                if (![self drainTLSEvents]) return;
                [self flushTLSOutput];
            } else {
                [self feedPlaintext:buf length:n];
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
    if (useTLS) [self flushTLSOutput];
}

/* The same newline-splitting inbuf this file always had -- now reachable either straight from a
 * plaintext recv() or from TLS_EV_DATA's decrypted bytes; irc_parse_line never sees anything but
 * plaintext either way. */
- (void)feedPlaintext:(const unsigned char *)bytes length:(int)n
{
    size_t room = sizeof(inbuf) - inbufLen;
    size_t take = (size_t)n < room ? (size_t)n : room;
    char *nl;
    memcpy(inbuf + inbufLen, bytes, take);
    inbufLen += take;
    if (take < (size_t)n) {                         /* a line longer than inbuf: drop and resync */
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
}

- (void)handleLine:(const char *)line
{
    irc_message msg;

    if (!irc_parse_line(line, &msg)) return;

    if (strcmp(msg.command, "PING") == 0) {          /* protocol housekeeping: never forwarded */
        char pong[IRC_MAX_LINE];
        int n = irc_fmt_pong(pong, sizeof(pong), msg.nparams > 0 ? msg.params[0] : "");
        if (n > 0) [self sendCommand:pong length:n];  /* through TLS when useTLS, same as anything else we send */
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
    if (useTLS) {
        if (tls_write(tls, (const unsigned char *)line, (size_t)len) != 0) return;
        [self flushTLSOutput];
    } else {
        [self queueBytes:(const unsigned char *)line length:len];
        [self flushPending];
    }
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
        if (n > 0) [self sendCommand:line length:n];
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
