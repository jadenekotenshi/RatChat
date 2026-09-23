#import "IRCChannelSession.h"
#import "UIHelpers.h"

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface IRCChannelSession (Private)
- (void)buildWindow;
- (void)writeFormattedLine:(NSString *)text dim:(BOOL)dim;
@end

@implementation IRCChannelSession

- (id)initWithOwner:(id)anOwner target:(NSString *)aTarget kind:(int)aKind
{
    self = [super init];
    if (!self) return nil;
    owner = anOwner;
    target = [aTarget retain];
    kind = aKind;
    return self;
}

- (void)dealloc
{
    [self shutdown];
    [target release];
    [window release]; [termView release]; [scroller release];
    [super dealloc];
}

- (NSString *)target { return target; }
- (int)kind { return kind; }
- (NSWindow *)window { return window; }

/* ---------------------------------------------------------------- */
/* window (mirrors PTYSession's buildWindow closely)                */

- (void)buildWindow
{
    static float offset = 0.0;
    NSSize cs;
    float sw = [NSScroller scrollerWidth];
    NSRect content;
    NSView *container;
    NSRect scr = [[NSScreen mainScreen] frame];

    termView = [[TerminalView alloc] initWithFrame:NSMakeRect(0, 0, 100, 100)];
    [termView setUTF8:YES];             /* IRC message text: usually UTF-8, see UIHelpers.h */
    cs = [termView contentSizeForCols:80 rows:24];
    content = NSMakeRect(0, 0, cs.width + sw, cs.height);

    window = [[NSWindow alloc] initWithContentRect:content
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(200, 100)];
    if ([window respondsToSelector:@selector(setResizeIncrements:)])
        [window setResizeIncrements:NSMakeSize(1, 1)];

    container = [[NSView alloc] initWithFrame:content];
    [termView setFrame:NSMakeRect(0, 0, cs.width, cs.height)];
    [termView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    scroller = [[NSScroller alloc] initWithFrame:NSMakeRect(cs.width, 0, sw, cs.height)];
    [scroller setAutoresizingMask:(NSViewHeightSizable | NSViewMinXMargin)];
    [container addSubview:termView];
    [container addSubview:scroller];
    [window setContentView:container];
    [container release];

    [termView setDelegate:self];
    [termView setScroller:scroller];
    [window setTitle:(kind == IRC_TARGET_STATUS ? @"Server" : target)];
    [window setFrameTopLeftPoint:NSMakePoint(scr.origin.x + 60 + offset, NSMaxY(scr) - 40 - offset)];
    offset += 24.0;
    if (offset > 240.0) offset = 0.0;
    [window makeKeyAndOrderFront:nil];
    [window makeFirstResponder:termView];
}

/* ---------------------------------------------------------------- */
/* display                                                           */

/* Erases whatever the user has typed so far (if anything), writes `text` as its own line, then
 * re-echoes the in-progress input so the user can keep typing where they left off -- otherwise an
 * incoming message arriving mid-keystroke would interleave with, and corrupt, the user's own not-
 * yet-submitted line (the classic problem any raw-terminal chat program has to solve, since there
 * is no line-discipline doing this for us the way a pty gave PTYSession for free). */
- (void)writeFormattedLine:(NSString *)text dim:(BOOL)dim
{
    static const unsigned char eraseOne[3] = { 0x08, ' ', 0x08 };
    static const unsigned char crlf[2] = { '\r', '\n' };
    static const unsigned char dimOn[4]  = { 0x1b, '[', '2', 'm' };
    static const unsigned char dimOff[4] = { 0x1b, '[', '0', 'm' };
    int i;
    const char *cstr = UI_CPATH(text);

    for (i = 0; i < lineLen; i++) [termView writeBytes:eraseOne length:3];
    if (dim) [termView writeBytes:dimOn length:4];
    [termView writeBytes:(const unsigned char *)cstr length:(int)strlen(cstr)];
    if (dim) [termView writeBytes:dimOff length:4];
    [termView writeBytes:crlf length:2];
    if (lineLen > 0) [termView writeBytes:(const unsigned char *)lineBuf length:lineLen];
}

- (void)appendLine:(NSString *)text { [self writeFormattedLine:text dim:NO]; }
- (void)appendSystemLine:(NSString *)text { [self writeFormattedLine:text dim:YES]; }

/* ---------------------------------------------------------------- */
/* TerminalView delegate: local line editing (see the .h for why)   */

- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned char c = bytes[i];
        if (c == '\r' || c == '\n') {
            static const unsigned char crlf[2] = { '\r', '\n' };
            NSString *submitted;
            lineBuf[lineLen] = '\0';
            [termView writeBytes:crlf length:2];
            submitted = ui_string_from_utf8(lineBuf);
            lineLen = 0;
            if ([submitted length] > 0 && [owner respondsToSelector:@selector(channelSession:didSubmitLine:)])
                [owner channelSession:self didSubmitLine:submitted];
        } else if (c == 0x08 || c == 0x7f) {
            if (lineLen > 0) {
                static const unsigned char erase[3] = { 0x08, ' ', 0x08 };
                lineLen--;
                [termView writeBytes:erase length:3];
            }
        } else if (c >= 0x20 && lineLen < (int)sizeof(lineBuf) - 1) {
            lineBuf[lineLen++] = (char)c;
            [termView writeBytes:&c length:1];
        }
        /* other control bytes (escape sequences from special keys, etc.) are dropped for now --
         * no in-line cursor movement or history recall yet, see README for what's not built. */
    }
}

- (void)terminalView:(id)tv resizedToCols:(int)cols rows:(int)rows
{
    /* No pty on the other end to inform -- nothing to do. */
}

/* ---------------------------------------------------------------- */
/* window delegate                                                  */

- (void)windowWillClose:(NSNotification *)notification
{
    [self shutdown];
    if ([owner respondsToSelector:@selector(channelSessionDidEnd:)])
        [owner channelSessionDidEnd:self];
}

- (void)shutdown
{
}

@end
