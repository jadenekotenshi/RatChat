#import "Compat.h"
#import "IRCConnection.h"
#import "IRCChannelSession.h"
#import "ConnectController.h"

/* Owns the app's one server connection (see AskUserQuestion: "single server, multiple channel
 * windows" was the chosen scope) and every open IRCChannelSession window. Is IRCConnection's
 * delegate -- the central router that decides which window a parsed message belongs to, formats
 * it for display, and creates query/channel windows on demand -- and each IRCChannelSession's
 * owner -- dispatching submitted lines as either a slash command or a plain PRIVMSG. */
@interface AppController : NSObject
{
    IRCConnection      *connection;
    ConnectController  *connectController;
    NSMutableArray     *sessions;             /* every open IRCChannelSession, including status */
    IRCChannelSession  *statusSession;
    NSString           *myNick;
    int                 nickRetries;          /* auto-"_"-suffix retries on ERR_NICKNAMEINUSE */
}
- (void)buildMenu;
@end
