#import "IRCChannelSession.h"
#import "UIHelpers.h"

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface IRCChannelSession (Private)
- (void)buildWindow;
- (void)writeFormattedLine:(NSString *)text dim:(BOOL)dim;
- (void)replaceLineWithBytes:(const unsigned char *)bytes length:(int)n;
- (void)recallHistory:(int)direction;
- (void)handleTabComplete;
- (int)indexOfMemberCI:(NSString *)nick;
@end

/* A small fixed palette (ANSI red/green/yellow/blue/magenta/cyan -- avoiding black/white, which
 * would blend into this terminal's default black-on-white rendering), picked per nick by a cheap
 * hash so the same nick reads as the same color for the life of the window. */
static int nick_color_code(NSString *nick)
{
    static const int palette[] = { 31, 32, 33, 34, 35, 36 };
    unsigned hash = 0;
    unsigned i, n = [nick length];
    for (i = 0; i < n; i++) hash = hash * 31 + [nick characterAtIndex:i];
    return palette[hash % 6];
}

@implementation IRCChannelSession

- (id)initWithOwner:(id)anOwner target:(NSString *)aTarget kind:(int)aKind
{
    self = [super init];
    if (!self) return nil;
    owner = anOwner;
    target = [aTarget retain];
    kind = aKind;
    historyPos = -1;
    return self;
}

- (void)dealloc
{
    [self shutdown];
    [target release];
    [window release]; [termView release]; [scroller release]; [memberTable release];
    [members release]; [history release];
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
    float memberWidth = (kind == IRC_TARGET_CHANNEL) ? 140.0 : 0.0;
    NSRect content;
    NSView *container;
    NSRect scr = [[NSScreen mainScreen] frame];

    termView = [[TerminalView alloc] initWithFrame:NSMakeRect(0, 0, 100, 100)];
    [termView setUTF8:YES];             /* IRC message text: usually UTF-8, see UIHelpers.h */
    cs = [termView contentSizeForCols:80 rows:24];
    content = NSMakeRect(0, 0, cs.width + sw + memberWidth, cs.height);

    window = [[NSWindow alloc] initWithContentRect:content
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(200 + memberWidth, 100)];
    if ([window respondsToSelector:@selector(setResizeIncrements:)])
        [window setResizeIncrements:NSMakeSize(1, 1)];

    container = [[NSView alloc] initWithFrame:content];
    [termView setFrame:NSMakeRect(0, 0, cs.width, cs.height)];
    [termView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    scroller = [[NSScroller alloc] initWithFrame:NSMakeRect(cs.width, 0, sw, cs.height)];
    [scroller setAutoresizingMask:(NSViewHeightSizable | NSViewMinXMargin)];
    [container addSubview:termView];
    [container addSubview:scroller];

    if (kind == IRC_TARGET_CHANNEL) {
        NSScrollView *memberScroll = [[[NSScrollView alloc]
            initWithFrame:NSMakeRect(cs.width + sw, 0, memberWidth, cs.height)] autorelease];
        NSTableColumn *col = [[[NSTableColumn alloc] initWithIdentifier:@"nick"] autorelease];
        [[col headerCell] setStringValue:@"Members"];
        [col setWidth:memberWidth - 4.0];
        [col setEditable:NO];
        members = [[NSMutableArray alloc] init];
        memberTable = [[NSTableView alloc] initWithFrame:NSMakeRect(0, 0, memberWidth, cs.height)];
        [memberTable addTableColumn:col];
        [memberTable setDataSource:(id)self];
        [memberTable setAllowsMultipleSelection:NO];
        [memberScroll setHasVerticalScroller:YES];
        [memberScroll setDocumentView:memberTable];
        [memberScroll setAutoresizingMask:(NSViewHeightSizable | NSViewMinXMargin)];
        [container addSubview:memberScroll];
    }

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
/* member list (channel windows only)                               */

- (int)indexOfMemberCI:(NSString *)nick
{
    int i, count = members ? (int)[members count] : 0;
    for (i = 0; i < count; i++)
        if ([[members objectAtIndex:i] caseInsensitiveCompare:nick] == NSOrderedSame) return i;
    return -1;
}

- (void)setMembers:(NSArray *)names
{
    if (!members) return;
    [members setArray:[names sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)]];
    [memberTable reloadData];
}

- (void)addMember:(NSString *)nick
{
    int i, count;
    if (!members || [self indexOfMemberCI:nick] >= 0) return;
    count = (int)[members count];
    for (i = 0; i < count; i++)
        if ([nick caseInsensitiveCompare:[members objectAtIndex:i]] == NSOrderedAscending) break;
    [members insertObject:nick atIndex:i];
    [memberTable reloadData];
}

- (void)removeMember:(NSString *)nick
{
    int i = [self indexOfMemberCI:nick];
    if (i < 0) return;
    [members removeObjectAtIndex:i];
    [memberTable reloadData];
}

- (void)renameMemberFrom:(NSString *)oldNick to:(NSString *)newNick
{
    if ([self indexOfMemberCI:oldNick] < 0) return;
    [self removeMember:oldNick];
    [self addMember:newNick];
}

- (NSArray *)members { return members; }

- (int)numberOfRowsInTableView:(NSTableView *)tv { return members ? (int)[members count] : 0; }

- (id)tableView:(NSTableView *)tv objectValueForTableColumn:(NSTableColumn *)col row:(int)row
{
    return [members objectAtIndex:row];
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

/* `style` picks the wrapper ("<nick> text", "* nick text", or "-nick- text"); the nick itself is
 * colored (a fixed hash-based color per nick, or always bold for the local user's own messages)
 * so different speakers are visually distinguishable at a glance. */
- (void)appendMessage:(NSString *)text fromNick:(NSString *)nick style:(int)style isOwn:(BOOL)isOwn
{
    NSString *ts = ui_timestamp();
    NSString *colorOn = [NSString stringWithFormat:@"\033[%dm", isOwn ? 1 : nick_color_code(nick)];
    NSString *composed;
    switch (style) {
    case IRC_LINE_ACTION:
        composed = [NSString stringWithFormat:@"[%@] * %@%@\033[0m %@", ts, colorOn, nick, text];
        break;
    case IRC_LINE_NOTICE:
        composed = [NSString stringWithFormat:@"[%@] -%@%@\033[0m- %@", ts, colorOn, nick, text];
        break;
    default:
        composed = [NSString stringWithFormat:@"[%@] <%@%@\033[0m> %@", ts, colorOn, nick, text];
        break;
    }
    [self writeFormattedLine:composed dim:NO];
}

- (void)appendSystemLine:(NSString *)text
{
    [self writeFormattedLine:[NSString stringWithFormat:@"[%@] %@", ui_timestamp(), text] dim:YES];
}

/* ---------------------------------------------------------------- */
/* TerminalView delegate: local line editing (see the .h for why)   */

- (void)replaceLineWithBytes:(const unsigned char *)bytes length:(int)n
{
    static const unsigned char eraseOne[3] = { 0x08, ' ', 0x08 };
    int i;
    for (i = 0; i < lineLen; i++) [termView writeBytes:eraseOne length:3];
    if (n > (int)sizeof(lineBuf) - 1) n = sizeof(lineBuf) - 1;
    memcpy(lineBuf, bytes, (size_t)n);
    lineLen = n;
    if (lineLen > 0) [termView writeBytes:(const unsigned char *)lineBuf length:lineLen];
}

/* direction: -1 = older (Up), +1 = newer (Down). The in-progress line is stashed (as raw bytes,
 * not round-tripped through NSString) the first time the user arrows up, and restored verbatim if
 * they arrow back down past the newest history entry. */
- (void)recallHistory:(int)direction
{
    int count = history ? (int)[history count] : 0;
    NSString *entry = nil;

    if (direction < 0) {
        if (count == 0) return;
        if (historyPos == -1) {
            savedLineLen = lineLen;
            memcpy(savedLine, lineBuf, (size_t)lineLen);
            historyPos = count - 1;
        } else if (historyPos > 0) {
            historyPos--;
        } else {
            return;
        }
        entry = [history objectAtIndex:historyPos];
    } else {
        if (historyPos == -1) return;
        if (historyPos < count - 1) {
            historyPos++;
            entry = [history objectAtIndex:historyPos];
        } else {
            historyPos = -1;
        }
    }

    if (entry) {
        const char *bytes = UI_CPATH(entry);
        [self replaceLineWithBytes:(const unsigned char *)bytes length:(int)strlen(bytes)];
    } else {
        [self replaceLineWithBytes:(const unsigned char *)savedLine length:savedLineLen];
    }
}

/* Completes the word under the cursor (the buffer's own append-only "cursor", i.e. its end --
 * there is no in-line cursor movement yet) against the channel's member list. Only acts on a
 * single unambiguous match; multiple or no matches do nothing. A completion at the very start of
 * the line (addressing someone) gets ": " after it, matching the classic IRC-client convention;
 * anywhere else just gets a space. */
- (void)handleTabComplete
{
    int start, i, matchCount = 0;
    NSString *word, *match = nil;
    const char *suffix; int suffixLen;
    const char *sep; int sepLen;

    if (kind != IRC_TARGET_CHANNEL || !members || [members count] == 0) return;
    start = lineLen;
    while (start > 0 && lineBuf[start - 1] != ' ') start--;
    if (start == lineLen) return;
    lineBuf[lineLen] = '\0';                              /* safe: lineLen is always < sizeof(lineBuf)-1 */
    word = ui_string_from_utf8(lineBuf + start);
    if ([word length] == 0) return;

    for (i = 0; i < (int)[members count]; i++) {
        NSString *m = [members objectAtIndex:i];
        if ([m length] >= [word length] &&
            [[m substringToIndex:[word length]] caseInsensitiveCompare:word] == NSOrderedSame) {
            match = m;
            matchCount++;
        }
    }
    if (matchCount != 1) return;

    suffix = UI_CPATH([match substringFromIndex:[word length]]);
    suffixLen = (int)strlen(suffix);
    for (i = 0; i < suffixLen && lineLen < (int)sizeof(lineBuf) - 1; i++) {
        lineBuf[lineLen++] = suffix[i];
        [termView writeBytes:(const unsigned char *)&suffix[i] length:1];
    }
    sep = (start == 0) ? ": " : " ";
    sepLen = (int)strlen(sep);
    if (lineLen + sepLen < (int)sizeof(lineBuf) - 1) {
        memcpy(lineBuf + lineLen, sep, (size_t)sepLen);
        lineLen += sepLen;
        [termView writeBytes:(const unsigned char *)sep length:sepLen];
    }
}

- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n
{
    int i;

    if (n == 3 && bytes[0] == 0x1b && bytes[1] == '[' && (bytes[2] == 'A' || bytes[2] == 'B')) {
        [self recallHistory:(bytes[2] == 'A') ? -1 : 1];
        return;
    }

    for (i = 0; i < n; i++) {
        unsigned char c = bytes[i];
        if (c == '\r' || c == '\n') {
            static const unsigned char crlf[2] = { '\r', '\n' };
            NSString *submitted;
            lineBuf[lineLen] = '\0';
            [termView writeBytes:crlf length:2];
            submitted = ui_string_from_utf8(lineBuf);
            lineLen = 0;
            historyPos = -1;
            if ([submitted length] > 0) {
                if (!history) history = [[NSMutableArray alloc] init];
                [history addObject:submitted];
                if ([owner respondsToSelector:@selector(channelSession:didSubmitLine:)])
                    [owner channelSession:self didSubmitLine:submitted];
            }
        } else if (c == 0x08 || c == 0x7f) {
            if (lineLen > 0) {
                static const unsigned char erase[3] = { 0x08, ' ', 0x08 };
                lineLen--;
                [termView writeBytes:erase length:3];
            }
        } else if (c == 0x09) {
            [self handleTabComplete];
        } else if (c >= 0x20 && lineLen < (int)sizeof(lineBuf) - 1) {
            lineBuf[lineLen++] = (char)c;
            [termView writeBytes:&c length:1];
        }
        /* other control bytes (e.g. left/right-arrow escape sequences) are dropped for now -- no
         * in-line cursor movement yet, see README for what's not built. */
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
