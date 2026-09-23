#import "Compat.h"
#import "TerminalView.h"

enum { IRC_TARGET_STATUS, IRC_TARGET_CHANNEL, IRC_TARGET_QUERY };

/* One window: a channel, a private-message query, or the server "status" window (target=nil).
 * Mirrors PTYSession/SSHSession closely on purpose -- one class owns its window, its
 * TerminalView, and is the window's own close delegate -- with one real difference neither of
 * those needed: a pty's kernel line discipline (or, for SSHSession, the remote shell) echoes
 * typed input for free. A raw IRC socket doesn't echo anything back, so this class does its own
 * minimal local line editing (printable chars, backspace, Enter) before ever telling its owner
 * a line was submitted -- see -terminalView:sendBytes:length: in the .m. */
@interface IRCChannelSession : NSObject
{
    id             owner;
    NSString      *target;             /* channel name ("#foo"), a nick (query), or nil (status) */
    int            kind;               /* IRC_TARGET_* */

    NSWindow      *window;
    TerminalView  *termView;
    NSScroller    *scroller;

    char           lineBuf[512];
    int            lineLen;
}
- (id)initWithOwner:(id)anOwner target:(NSString *)aTarget kind:(int)aKind;
- (void)buildWindow;
- (NSString *)target;
- (int)kind;
- (NSWindow *)window;
- (void)appendLine:(NSString *)text;               /* a fully-formatted line, e.g. "<nick> hi" */
- (void)appendSystemLine:(NSString *)text;          /* joins/parts/notices/errors: dimmer styling */
- (void)shutdown;
@end

@interface NSObject (IRCChannelSessionOwner)
- (void)channelSessionDidEnd:(IRCChannelSession *)cs;
- (void)channelSession:(IRCChannelSession *)cs didSubmitLine:(NSString *)text;
@end
