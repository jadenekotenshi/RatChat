#import "Compat.h"
#import "TerminalView.h"

enum { IRC_TARGET_STATUS, IRC_TARGET_CHANNEL, IRC_TARGET_QUERY };
enum { IRC_LINE_MESSAGE, IRC_LINE_ACTION, IRC_LINE_NOTICE };

/* One window: a channel, a private-message query, or the server "status" window (target=nil).
 * Mirrors PTYSession/SSHSession closely on purpose -- one class owns its window, its
 * TerminalView, and is the window's own close delegate -- with one real difference neither of
 * those needed: a pty's kernel line discipline (or, for SSHSession, the remote shell) echoes
 * typed input for free. A raw IRC socket doesn't echo anything back, so this class does its own
 * minimal local line editing (printable chars, backspace, Enter, Tab-completion, Up/Down history)
 * before ever telling its owner a line was submitted -- see -terminalView:sendBytes:length: in
 * the .m. Channel windows (not status/query) also carry a member list, kept in sync by the owner
 * from NAMES replies and JOIN/PART/QUIT/NICK. */
@interface IRCChannelSession : NSObject
{
    id             owner;
    NSString      *target;             /* channel name ("#foo"), a nick (query), or nil (status) */
    int            kind;               /* IRC_TARGET_* */

    NSWindow      *window;
    TerminalView  *termView;
    NSScroller    *scroller;
    NSTableView   *memberTable;         /* channel windows only */
    NSMutableArray *members;            /* sorted nicks; channel windows only */

    char           lineBuf[512];
    int            lineLen;

    NSMutableArray *history;            /* previously submitted lines, oldest first */
    int             historyPos;         /* -1: not browsing; else an index into history, from the end */
    char            savedLine[512];     /* the in-progress line, stashed while browsing history */
    int             savedLineLen;
}
- (id)initWithOwner:(id)anOwner target:(NSString *)aTarget kind:(int)aKind;
- (void)buildWindow;
- (NSString *)target;
- (int)kind;
- (NSWindow *)window;
- (void)appendMessage:(NSString *)text fromNick:(NSString *)nick style:(int)style isOwn:(BOOL)isOwn;
- (void)appendSystemLine:(NSString *)text;          /* joins/parts/notices/errors: dimmer styling */
- (void)setMembers:(NSArray *)names;                /* wholesale replace, e.g. from a NAMES reply */
- (void)addMember:(NSString *)nick;
- (void)removeMember:(NSString *)nick;              /* case-insensitive; harmless if not present */
- (void)renameMemberFrom:(NSString *)oldNick to:(NSString *)newNick;
- (NSArray *)members;
- (void)shutdown;
@end

@interface NSObject (IRCChannelSessionOwner)
- (void)channelSessionDidEnd:(IRCChannelSession *)cs;
- (void)channelSession:(IRCChannelSession *)cs didSubmitLine:(NSString *)text;
@end
