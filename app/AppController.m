#import "AppController.h"
#import "UIHelpers.h"
#include <string.h>

static NSString *S(const char *s) { return ui_string_from_utf8(s); }

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface AppController (Private)
- (void)showConnectPanel:(id)sender;
- (IRCChannelSession *)sessionForTarget:(NSString *)t kind:(int)k createIfNeeded:(BOOL)create;
- (void)setMyNick:(NSString *)n;
- (void)sendPrivmsg:(NSString *)text toSession:(IRCChannelSession *)cs echo:(BOOL)echo;
- (void)handlePrivmsgOrNotice:(const irc_message *)msg isNotice:(BOOL)isNotice;
- (void)handleNumeric:(const irc_message *)msg;
- (void)dispatchCommandLine:(NSString *)rest fromSession:(IRCChannelSession *)cs;
@end

@implementation AppController

- (id)init
{
    self = [super init];
    if (!self) return nil;
    sessions = [[NSMutableArray alloc] init];
    return self;
}

- (void)dealloc
{
    [sessions release];
    [connection release];
    [connectController release];
    [myNick release];
    [super dealloc];
}

- (void)setMyNick:(NSString *)n
{
    if (myNick == n) return;
    [myNick release];
    myNick = [n retain];
}

/* ---------------------------------------------------------------- */
/* menus                                                            */

- (void)addItem:(NSString *)title action:(SEL)action key:(NSString *)key
         target:(id)target toMenu:(NSMenu *)menu
{
    id item = [menu addItemWithTitle:title action:action keyEquivalent:key];
    if (target) [item setTarget:target];
}

- (NSMenu *)submenuNamed:(NSString *)title inMenu:(NSMenu *)parent
{
    NSMenu *sub = [[NSMenu alloc] initWithTitle:title];
    id item = [parent addItemWithTitle:title action:NULL keyEquivalent:@""];
    [parent setSubmenu:sub forItem:item];
    return [sub autorelease];
}

- (void)buildMenu
{
    NSMenu *main = [[[NSMenu alloc] initWithTitle:@"RatChat"] autorelease];
    NSMenu *m;

    m = [self submenuNamed:@"Server" inMenu:main];
    [self addItem:@"Connect..." action:@selector(showConnectPanel:) key:@"n" target:self toMenu:m];
    [self addItem:@"Disconnect" action:@selector(disconnect:) key:@"d" target:self toMenu:m];

    m = [self submenuNamed:@"Edit" inMenu:main];
    [self addItem:@"Copy" action:@selector(copy:) key:@"c" target:nil toMenu:m];
    [self addItem:@"Paste" action:@selector(paste:) key:@"v" target:nil toMenu:m];
    [self addItem:@"Select All" action:@selector(selectAll:) key:@"a" target:nil toMenu:m];
    [self addItem:@"Clear Scrollback" action:@selector(clearScrollback:) key:@"k" target:nil toMenu:m];

    m = [self submenuNamed:@"Windows" inMenu:main];
    [self addItem:@"Arrange in Front" action:@selector(arrangeInFront:) key:@"" target:nil toMenu:m];
    [self addItem:@"Miniaturize Window" action:@selector(performMiniaturize:) key:@"m" target:nil toMenu:m];
    [NSApp setWindowsMenu:m];

    m = [self submenuNamed:@"Services" inMenu:main];
    [NSApp setServicesMenu:m];

    [self addItem:@"Hide" action:@selector(hide:) key:@"h" target:NSApp toMenu:main];
    [self addItem:@"Quit" action:@selector(terminate:) key:@"q" target:NSApp toMenu:main];

    [NSApp setMainMenu:main];
}

/* ---------------------------------------------------------------- */
/* startup / connecting                                             */

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    NSLog(@"RatChat: applicationDidFinishLaunching");
    SSTrace("applicationDidFinishLaunching");
    [self showConnectPanel:nil];
}

- (void)showConnectPanel:(id)sender
{
    if (!connectController) connectController = [[ConnectController alloc] initWithOwner:self];
    [connectController showPanel];
}

- (void)disconnect:(id)sender
{
    if (connection) [connection disconnectWithReason:@"Leaving"];
}

- (void)connectController:(ConnectController *)cc didRequestHost:(NSString *)h port:(int)p
                      nick:(NSString *)n user:(NSString *)u realName:(NSString *)r
{
    if (connection) {
        NSRunAlertPanel(@"Already connected", @"Disconnect first before connecting to another server.",
                        @"OK", nil, nil);
        return;
    }
    [self setMyNick:n];
    nickRetries = 0;
    connection = [[IRCConnection alloc] initWithDelegate:self];
    if (![connection connectToHost:h port:p nick:n user:u realName:r]) {
        [connection release]; connection = nil;
    }
}

/* ---------------------------------------------------------------- */
/* IRCConnectionDelegate                                            */

- (void)ircConnectionDidRegister:(IRCConnection *)c
{
    statusSession = [self sessionForTarget:nil kind:IRC_TARGET_STATUS createIfNeeded:YES];
    [statusSession appendSystemLine:[NSString stringWithFormat:@"Connected to %@ as %@", [c host], myNick]];
}

- (void)ircConnection:(IRCConnection *)c didFailWithError:(NSString *)message
{
    NSRunAlertPanel(@"Connection Error", @"%@", @"OK", nil, nil, message);
}

- (void)ircConnectionDidEnd:(IRCConnection *)c
{
    [connection release]; connection = nil;
    if (statusSession) [statusSession appendSystemLine:@"Disconnected."];
}

- (void)ircConnection:(IRCConnection *)c didReceiveMessage:(const irc_message *)msg
{
    if (strcmp(msg->command, "PRIVMSG") == 0) { [self handlePrivmsgOrNotice:msg isNotice:NO]; return; }
    if (strcmp(msg->command, "NOTICE") == 0) { [self handlePrivmsgOrNotice:msg isNotice:YES]; return; }

    if (strcmp(msg->command, "JOIN") == 0) {
        NSString *chan = msg->nparams > 0 ? S(msg->params[0]) : @"";
        NSString *joiner = msg->has_prefix ? S(msg->prefix.nick) : @"";
        if ([joiner isEqualToString:myNick]) {
            IRCChannelSession *cs = [self sessionForTarget:chan kind:IRC_TARGET_CHANNEL createIfNeeded:YES];
            [cs appendSystemLine:[NSString stringWithFormat:@"Joined %@", chan]];
        } else {
            IRCChannelSession *cs = [self sessionForTarget:chan kind:IRC_TARGET_CHANNEL createIfNeeded:NO];
            if (cs) [cs appendSystemLine:[NSString stringWithFormat:@"%@ has joined %@", joiner, chan]];
        }
        return;
    }
    if (strcmp(msg->command, "PART") == 0) {
        NSString *chan = msg->nparams > 0 ? S(msg->params[0]) : @"";
        NSString *leaver = msg->has_prefix ? S(msg->prefix.nick) : @"";
        NSString *reason = msg->nparams > 1 ? S(msg->params[1]) : @"";
        NSString *suffix = [reason length] ? [NSString stringWithFormat:@" (%@)", reason] : @"";
        IRCChannelSession *cs = [self sessionForTarget:chan kind:IRC_TARGET_CHANNEL createIfNeeded:NO];
        if (!cs) return;
        if ([leaver isEqualToString:myNick])
            [cs appendSystemLine:[NSString stringWithFormat:@"You have left %@%@", chan, suffix]];
        else
            [cs appendSystemLine:[NSString stringWithFormat:@"%@ has left %@%@", leaver, chan, suffix]];
        return;
    }
    if (strcmp(msg->command, "QUIT") == 0) {
        /* Not routed to individual channel windows -- would need per-channel membership tracking
         * (no NAMES-list UI exists yet, see README). Shown in the status window only for now. */
        NSString *who = msg->has_prefix ? S(msg->prefix.nick) : @"";
        NSString *reason = msg->nparams > 0 ? S(msg->params[0]) : @"";
        NSString *suffix = [reason length] ? [NSString stringWithFormat:@" (%@)", reason] : @"";
        if (statusSession) [statusSession appendSystemLine:[NSString stringWithFormat:@"%@ has quit%@", who, suffix]];
        return;
    }
    if (strcmp(msg->command, "NICK") == 0) {
        NSString *oldNick = msg->has_prefix ? S(msg->prefix.nick) : @"";
        NSString *newNick = msg->nparams > 0 ? S(msg->params[0]) : @"";
        if ([oldNick isEqualToString:myNick]) {
            [self setMyNick:newNick];
            if (statusSession) [statusSession appendSystemLine:[NSString stringWithFormat:@"You are now known as %@", newNick]];
        } else if (statusSession) {
            [statusSession appendSystemLine:[NSString stringWithFormat:@"%@ is now known as %@", oldNick, newNick]];
        }
        return;
    }
    if (strcmp(msg->command, "TOPIC") == 0) {
        NSString *chan = msg->nparams > 0 ? S(msg->params[0]) : @"";
        NSString *setter = msg->has_prefix ? S(msg->prefix.nick) : @"someone";
        NSString *topic = msg->nparams > 1 ? S(msg->params[1]) : @"";
        IRCChannelSession *cs = [self sessionForTarget:chan kind:IRC_TARGET_CHANNEL createIfNeeded:NO];
        if (cs) [cs appendSystemLine:[NSString stringWithFormat:@"%@ changed the topic to: %@", setter, topic]];
        return;
    }
    if (strcmp(msg->command, "MODE") == 0) {
        NSString *tgt = msg->nparams > 0 ? S(msg->params[0]) : @"";
        NSString *setter = msg->has_prefix ? S(msg->prefix.nick) : @"server";
        NSMutableString *rest = [NSMutableString string];
        int i;
        IRCChannelSession *cs;
        for (i = 1; i < msg->nparams; i++) {
            if (i > 1) [rest appendString:@" "];
            [rest appendString:S(msg->params[i])];
        }
        cs = (msg->nparams > 0 && irc_is_channel(msg->params[0]))
             ? [self sessionForTarget:tgt kind:IRC_TARGET_CHANNEL createIfNeeded:NO] : statusSession;
        if (!cs) cs = statusSession;
        if (cs) [cs appendSystemLine:[NSString stringWithFormat:@"%@ sets mode %@ %@", setter, tgt, rest]];
        return;
    }
    if (strcmp(msg->command, "433") == 0 && ![c isConnected]) {          /* nickname in use, mid-registration */
        char line[IRC_MAX_LINE];
        int n;
        nickRetries++;
        if (nickRetries > 9) return;                                     /* give up silently; server will time us out */
        [self setMyNick:[myNick stringByAppendingString:@"_"]];
        n = irc_fmt_nick(line, sizeof(line), [myNick cString]);
        if (n > 0) [connection sendCommand:line length:n];
        return;
    }

    [self handleNumeric:msg];
}

- (void)handlePrivmsgOrNotice:(const irc_message *)msg isNotice:(BOOL)isNotice
{
    NSString *fromNick = msg->has_prefix ? S(msg->prefix.nick) : @"server";
    IRCChannelSession *cs;
    char textBuf[IRC_MAX_LINE];

    textBuf[0] = '\0';
    if (msg->nparams > 1) { strncpy(textBuf, msg->params[1], sizeof(textBuf) - 1); textBuf[sizeof(textBuf) - 1] = '\0'; }

    if (msg->nparams == 0) return;
    if (irc_is_channel(msg->params[0])) {
        cs = [self sessionForTarget:S(msg->params[0]) kind:IRC_TARGET_CHANNEL createIfNeeded:NO];
        if (!cs) cs = statusSession;
    } else {
        cs = [self sessionForTarget:fromNick kind:IRC_TARGET_QUERY createIfNeeded:YES];
    }
    if (!cs) return;

    if (irc_is_ctcp(textBuf)) {
        const char *verb, *body;
        irc_ctcp_strip(textBuf, &verb, &body);
        if (strcmp(verb, "ACTION") == 0) {
            [cs appendLine:[NSString stringWithFormat:@"* %@ %@", fromNick, S(body)]];
        } else if (!isNotice) {
            /* Other CTCP requests (VERSION, PING, TIME, ...) are noted but not auto-answered yet. */
            if (statusSession) [statusSession appendSystemLine:[NSString stringWithFormat:@"CTCP %s from %@", verb, fromNick]];
        }
        return;
    }
    [cs appendLine:[NSString stringWithFormat:isNotice ? @"-%@- %@" : @"<%@> %@", fromNick, S(textBuf)]];
}

- (void)handleNumeric:(const irc_message *)msg
{
    NSMutableString *line;
    int i;
    if (!statusSession) return;
    line = [NSMutableString string];
    for (i = 1; i < msg->nparams; i++) {
        if (i > 1) [line appendString:@" "];
        [line appendString:S(msg->params[i])];
    }
    [statusSession appendSystemLine:[NSString stringWithFormat:@"[%s] %@", msg->command, line]];
}

/* ---------------------------------------------------------------- */
/* IRCChannelSessionOwner                                           */

- (void)channelSessionDidEnd:(IRCChannelSession *)cs
{
    [[cs retain] autorelease];                           /* still on the stack in windowWillClose: */
    if (cs == statusSession) statusSession = nil;
    if ([cs kind] == IRC_TARGET_CHANNEL && connection && [connection isConnected]) {
        char line[IRC_MAX_LINE];
        int n = irc_fmt_part(line, sizeof(line), [[cs target] cString], NULL);
        if (n > 0) [connection sendCommand:line length:n];
    }
    [sessions removeObject:cs];
}

- (void)channelSession:(IRCChannelSession *)cs didSubmitLine:(NSString *)text
{
    BOOL isEscapedSlash = [text length] > 1 && [text characterAtIndex:0] == '/' && [text characterAtIndex:1] == '/';
    if ([text length] > 0 && [text characterAtIndex:0] == '/' && !isEscapedSlash) {
        [self dispatchCommandLine:[text substringFromIndex:1] fromSession:cs];
        return;
    }
    [self sendPrivmsg:(isEscapedSlash ? [text substringFromIndex:1] : text) toSession:cs echo:YES];
}

- (void)sendPrivmsg:(NSString *)text toSession:(IRCChannelSession *)cs echo:(BOOL)echo
{
    char line[IRC_MAX_LINE];
    int n;
    if (!connection || ![connection isConnected] || [cs kind] == IRC_TARGET_STATUS) {
        NSRunAlertPanel(@"Not in a channel", @"Use /join <channel> or /msg <nick> <text> first.", @"OK", nil, nil);
        return;
    }
    n = irc_fmt_privmsg(line, sizeof(line), [[cs target] cString], UI_CPATH(text));
    if (n > 0) [connection sendCommand:line length:n];
    if (echo) [cs appendLine:[NSString stringWithFormat:@"<%@> %@", myNick, text]];
}

- (void)dispatchCommandLine:(NSString *)rest fromSession:(IRCChannelSession *)cs
{
    NSRange sp = [rest rangeOfString:@" "];
    NSString *cmd = (sp.location == NSNotFound) ? rest : [rest substringToIndex:sp.location];
    NSString *arg = (sp.location == NSNotFound) ? @"" : ui_trim([rest substringFromIndex:sp.location + 1]);
    NSString *upperCmd = [cmd uppercaseString];
    char line[IRC_MAX_LINE];
    int n;

    if (![upperCmd isEqualToString:@"QUIT"] && (!connection || ![connection isConnected])) {
        NSRunAlertPanel(@"Not connected", @"Connect to a server first.", @"OK", nil, nil);
        return;
    }

    if ([upperCmd isEqualToString:@"JOIN"]) {
        NSRange sp2 = [arg rangeOfString:@" "];
        NSString *chan = (sp2.location == NSNotFound) ? arg : [arg substringToIndex:sp2.location];
        NSString *key = (sp2.location == NSNotFound) ? nil : ui_trim([arg substringFromIndex:sp2.location + 1]);
        if ([chan length] == 0) { NSRunAlertPanel(@"Join", @"Usage: /join #channel [key]", @"OK", nil, nil); return; }
        n = irc_fmt_join(line, sizeof(line), [chan cString], key ? [key cString] : NULL);
        if (n > 0) [connection sendCommand:line length:n];
        return;
    }
    if ([upperCmd isEqualToString:@"PART"]) {
        NSString *chan = ([arg length] > 0) ? arg : (([cs kind] == IRC_TARGET_CHANNEL) ? [cs target] : nil);
        if (!chan) {
            NSRunAlertPanel(@"Part", @"Usage: /part [#channel] -- or run it from the channel's own window.", @"OK", nil, nil);
            return;
        }
        n = irc_fmt_part(line, sizeof(line), [chan cString], NULL);
        if (n > 0) [connection sendCommand:line length:n];
        return;
    }
    if ([upperCmd isEqualToString:@"MSG"]) {
        NSRange sp2 = [arg rangeOfString:@" "];
        NSString *tgt, *body;
        IRCChannelSession *dest;
        if (sp2.location == NSNotFound) { NSRunAlertPanel(@"Message", @"Usage: /msg <nick> <text>", @"OK", nil, nil); return; }
        tgt = [arg substringToIndex:sp2.location];
        body = ui_trim([arg substringFromIndex:sp2.location + 1]);
        dest = [self sessionForTarget:tgt kind:(irc_is_channel([tgt cString]) ? IRC_TARGET_CHANNEL : IRC_TARGET_QUERY)
                       createIfNeeded:YES];
        [self sendPrivmsg:body toSession:dest echo:YES];
        return;
    }
    if ([upperCmd isEqualToString:@"ME"]) {
        if ([cs kind] == IRC_TARGET_STATUS) { NSRunAlertPanel(@"Action", @"Not in a channel.", @"OK", nil, nil); return; }
        n = irc_fmt_action(line, sizeof(line), [[cs target] cString], UI_CPATH(arg));
        if (n > 0) [connection sendCommand:line length:n];
        [cs appendLine:[NSString stringWithFormat:@"* %@ %@", myNick, arg]];
        return;
    }
    if ([upperCmd isEqualToString:@"NICK"]) {
        if ([arg length] == 0) { NSRunAlertPanel(@"Nick", @"Usage: /nick <newnick>", @"OK", nil, nil); return; }
        n = irc_fmt_nick(line, sizeof(line), [arg cString]);
        if (n > 0) [connection sendCommand:line length:n];
        return;
    }
    if ([upperCmd isEqualToString:@"QUIT"]) {
        if (connection) [connection disconnectWithReason:([arg length] ? arg : nil)];
        return;
    }
    if ([upperCmd isEqualToString:@"CLOSE"]) {
        if ([cs kind] == IRC_TARGET_CHANNEL && connection && [connection isConnected]) {
            n = irc_fmt_part(line, sizeof(line), [[cs target] cString], NULL);
            if (n > 0) [connection sendCommand:line length:n];
        }
        [[cs window] close];
        return;
    }
    if ([upperCmd isEqualToString:@"RAW"] || [upperCmd isEqualToString:@"QUOTE"]) {
        n = irc_fmt_raw(line, sizeof(line), UI_CPATH(arg));
        if (n > 0) [connection sendCommand:line length:n];
        return;
    }

    /* Unknown /command: pass it through as a raw protocol line, matching most real IRC clients --
     * there are many commands (WHOIS, WHO, LIST, AWAY, KICK, INVITE, ...) not worth hand-coding
     * one by one when the server already knows what to do with the raw line. */
    n = irc_fmt_raw(line, sizeof(line), UI_CPATH(rest));
    if (n > 0) [connection sendCommand:line length:n];
}

/* ---------------------------------------------------------------- */
/* session lookup / creation                                        */

- (IRCChannelSession *)sessionForTarget:(NSString *)t kind:(int)k createIfNeeded:(BOOL)create
{
    int i;
    IRCChannelSession *cs;

    if (k == IRC_TARGET_STATUS) {
        if (!statusSession && create) {
            statusSession = [[IRCChannelSession alloc] initWithOwner:self target:nil kind:IRC_TARGET_STATUS];
            [statusSession buildWindow];
            [sessions addObject:statusSession];
            [statusSession release];
        }
        return statusSession;
    }
    for (i = 0; i < (int)[sessions count]; i++) {
        cs = [sessions objectAtIndex:i];
        if ([cs kind] == k && [[cs target] caseInsensitiveCompare:t] == NSOrderedSame) return cs;
    }
    if (!create) return nil;
    cs = [[IRCChannelSession alloc] initWithOwner:self target:t kind:k];
    [cs buildWindow];
    [sessions addObject:cs];
    [cs release];
    return cs;
}

@end
