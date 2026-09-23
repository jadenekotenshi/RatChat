#import "Compat.h"
#include "irc_parse.h"

/* One raw TCP connection to one IRC server -- mirrors SSHSession's own socket handling closely on
 * purpose (the same non-blocking connect/select/recv/send pattern, the same 20ms NSTimer poll
 * loop, proven reliable on real OPENSTEP hardware), minus everything SSH-specific: no crypto
 * handshake, no channel multiplexing, just newline-terminated text in and out.
 *
 * Owns no window itself -- IRCChannelSession (one instance per open channel or query window)
 * registers with this as its delegate for the target(s) it cares about. AppController owns the
 * one IRCConnection for the app's one server connection (see AskUserQuestion: "single server,
 * multiple channel windows" was the chosen scope). */

enum { IRC_DISCONNECTED, IRC_CONNECTING, IRC_REGISTERING, IRC_CONNECTED, IRC_ENDED };

@interface IRCConnection : NSObject
{
    int      fd;
    int      state;
    NSTimer *timer;
    id       delegate;
    long     ticks, connectDeadline;
    int      inTick;

    char    inbuf[4096];             /* accumulates partial lines across reads */
    size_t  inbufLen;

    unsigned char *pendingOut;       /* backpressure queue: send() couldn't take it all at once */
    size_t         pendingLen, pendingCap;

    NSString *host;
    int       port;
    NSString *nick;                  /* requested nick; may differ from the server's actual grant */
    NSString *user;
    NSString *realName;
}
- (id)initWithDelegate:(id)aDelegate;
- (BOOL)connectToHost:(NSString *)aHost port:(int)aPort nick:(NSString *)aNick
                  user:(NSString *)aUser realName:(NSString *)aRealName;
- (void)sendCommand:(const char *)line length:(int)len;      /* pre-formatted, already has \r\n */
- (BOOL)isConnected;
- (NSString *)host;
- (NSString *)nick;
- (NSString *)localAddress;    /* our own address as this socket's local endpoint (for DCC offers) */
- (void)disconnectWithReason:(NSString *)reason;             /* sends QUIT, then tears down */
- (void)shutdown;                                             /* no QUIT; just closes the socket */
@end

@interface NSObject (IRCConnectionDelegate)
/* `msg` is only valid for the duration of this call -- it points into a stack buffer reused for
 * the next line, so copy anything needed out of it (as NSStrings) before returning. */
- (void)ircConnection:(IRCConnection *)c didReceiveMessage:(const irc_message *)msg;
- (void)ircConnectionDidRegister:(IRCConnection *)c;          /* numeric 001: registration complete */
- (void)ircConnection:(IRCConnection *)c didFailWithError:(NSString *)message;
- (void)ircConnectionDidEnd:(IRCConnection *)c;
@end
