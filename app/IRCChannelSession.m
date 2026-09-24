#import "IRCChannelSession.h"
#import "UIHelpers.h"

#define INPUT_HEIGHT 24.0

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface IRCChannelSession (Private)
- (void)buildWindow;
- (void)writeFormattedLine:(NSString *)text dim:(BOOL)dim;
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
    [members release]; [inputField release]; [history release]; [savedDraft release];
    [super dealloc];
}

- (NSString *)target { return target; }
- (int)kind { return kind; }
- (NSWindow *)window { return window; }

/* ---------------------------------------------------------------- */
/* window (mirrors PTYSession's buildWindow closely)                */

/* Message log + optional member list occupy everything above INPUT_HEIGHT; the input field is a
 * full-width strip pinned to the bottom (NSViewMaxYMargin: the flexible gap is ABOVE it, so it
 * stays put as the window resizes), under the member list too, not beside it. */
- (void)buildWindow
{
    static float offset = 0.0;
    NSSize cs;
    float sw = [NSScroller scrollerWidth];
    float memberWidth = (kind == IRC_TARGET_CHANNEL) ? 140.0 : 0.0;
    float totalWidth, totalHeight;
    NSRect content;
    NSView *container;
    NSRect scr = [[NSScreen mainScreen] frame];

    termView = [[TerminalView alloc] initWithFrame:NSMakeRect(0, 0, 100, 100)];
    [termView setUTF8:YES];             /* IRC message text: usually UTF-8, see UIHelpers.h */
    cs = [termView contentSizeForCols:80 rows:24];
    totalWidth = cs.width + sw + memberWidth;
    totalHeight = cs.height + INPUT_HEIGHT;
    content = NSMakeRect(0, 0, totalWidth, totalHeight);

    window = [[NSWindow alloc] initWithContentRect:content
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(200 + memberWidth, 100 + INPUT_HEIGHT)];
    if ([window respondsToSelector:@selector(setResizeIncrements:)])
        [window setResizeIncrements:NSMakeSize(1, 1)];

    /* Scrollbar on the left, not the right -- genuine OPENSTEP/NeXTSTEP AppKit's own native
     * default for NSScrollView's vertical scroller (NSMinXEdge; it only moves to the right under
     * the NSMacintoshInterfaceStyle/NSWindows95InterfaceStyle compatibility styles, neither of
     * which this app requests). This view's scroller is a plain NSScroller positioned by hand
     * rather than an NSScrollView, so it does not inherit that platform default automatically --
     * placed on the left explicitly here to match it. (The member list's own scrollbar, further
     * right, is a real NSScrollView and already gets this for free.) */
    container = [[NSView alloc] initWithFrame:content];
    [termView setFrame:NSMakeRect(sw, INPUT_HEIGHT, cs.width, cs.height)];
    [termView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    scroller = [[NSScroller alloc] initWithFrame:NSMakeRect(0, INPUT_HEIGHT, sw, cs.height)];
    [scroller setAutoresizingMask:(NSViewHeightSizable | NSViewMaxXMargin)];
    [container addSubview:termView];
    [container addSubview:scroller];

    if (kind == IRC_TARGET_CHANNEL) {
        NSScrollView *memberScroll = [[[NSScrollView alloc]
            initWithFrame:NSMakeRect(cs.width + sw, INPUT_HEIGHT, memberWidth, cs.height)] autorelease];
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

    inputField = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, totalWidth, INPUT_HEIGHT)];
    [inputField setAutoresizingMask:(NSViewWidthSizable | NSViewMaxYMargin)];
    [inputField setTarget:self];
    [inputField setAction:@selector(inputSubmitted:)];
    [inputField setDelegate:self];
    [container addSubview:inputField];

    [window setContentView:container];
    [container release];

    [termView setDelegate:self];
    [termView setScroller:scroller];
    [window setTitle:(kind == IRC_TARGET_STATUS ? @"Server" : target)];
    [window setFrameTopLeftPoint:NSMakePoint(scr.origin.x + 60 + offset, NSMaxY(scr) - 40 - offset)];
    offset += 24.0;
    if (offset > 240.0) offset = 0.0;
    [window makeKeyAndOrderFront:nil];
    [window makeFirstResponder:inputField];
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

/* Input lives in its own field now, never in termView itself, so there is no in-progress typed
 * line to protect from corruption here anymore (contrast StepTTY's PTYSession, or this class's own
 * previous revision, where typing and display shared one view). */
- (void)writeFormattedLine:(NSString *)text dim:(BOOL)dim
{
    static const unsigned char crlf[2] = { '\r', '\n' };
    static const unsigned char dimOn[4]  = { 0x1b, '[', '2', 'm' };
    static const unsigned char dimOff[4] = { 0x1b, '[', '0', 'm' };
    const char *cstr = UI_CPATH(text);
    if (dim) [termView writeBytes:dimOn length:4];
    [termView writeBytes:(const unsigned char *)cstr length:(int)strlen(cstr)];
    if (dim) [termView writeBytes:dimOff length:4];
    [termView writeBytes:crlf length:2];
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
/* the input field                                                   */

- (void)inputSubmitted:(id)sender
{
    NSString *text = ui_trim([inputField stringValue]);
    [inputField setStringValue:@""];
    historyPos = -1;
    /* [V] Reported on real OPENSTEP 4.2 hardware: after Return submits a line, the field loses
     * focus and needs an extra click before the next message can be typed. Reclaiming first
     * responder explicitly is the standard fix for this on classic (pre-Mac-OS-X) AppKit, where
     * ending a field editor's session on Return does not restore focus to the field on its own
     * the way modern Cocoa does -- confirmed not reproducible host-side (a real synthetic Return
     * keypress here never loses currentEditor status in the first place), so this can only be
     * confirmed fixed on real hardware, not by an automated test. */
    [window makeFirstResponder:inputField];
    if ([text length] == 0) return;
    if (!history) history = [[NSMutableArray alloc] init];
    [history addObject:text];
    if ([owner respondsToSelector:@selector(channelSession:didSubmitLine:)])
        [owner channelSession:self didSubmitLine:text];
}

/* direction: -1 = older (Up), +1 = newer (Down). The in-progress draft is stashed the first time
 * the user arrows up, and restored verbatim if they arrow back down past the newest entry. */
- (void)recallHistory:(int)direction
{
    int count = history ? (int)[history count] : 0;

    if (direction < 0) {
        if (count == 0) return;
        if (historyPos == -1) {
            [savedDraft release];
            savedDraft = [[inputField stringValue] retain];
            historyPos = count - 1;
        } else if (historyPos > 0) {
            historyPos--;
        } else {
            return;
        }
        [inputField setStringValue:[history objectAtIndex:historyPos]];
    } else {
        if (historyPos == -1) return;
        if (historyPos < count - 1) {
            historyPos++;
            [inputField setStringValue:[history objectAtIndex:historyPos]];
        } else {
            historyPos = -1;
            [inputField setStringValue:(savedDraft ? savedDraft : @"")];
        }
    }
}

/* Completes the word under the cursor -- the last space-separated word in the field, since
 * NSTextField doesn't expose the field editor's insertion point through this delegate hook --
 * against the channel's member list. Only acts on a single unambiguous match. A completion at the
 * very start of the field (addressing someone) gets ": " after it, the classic IRC-client
 * convention; anywhere else just gets a space. */
- (void)handleTabComplete
{
    NSString *text, *word, *match = nil;
    NSRange lastSpace;
    int start, i, matchCount = 0;

    if (kind != IRC_TARGET_CHANNEL || !members || [members count] == 0) return;
    text = [inputField stringValue];
    lastSpace = [text rangeOfString:@" " options:NSBackwardsSearch];
    start = (lastSpace.location == NSNotFound) ? 0 : (int)(lastSpace.location + 1);
    word = [text substringFromIndex:start];
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

    [inputField setStringValue:[[[text substringToIndex:start] stringByAppendingString:match]
                                  stringByAppendingString:(start == 0) ? @": " : @" "]];
}

/* [V] The NSControl delegate hook for intercepting field-editor commands (Tab/Up/Down) while
 * editing continues, rather than waiting for editing to end -- standard OpenStep API (the "Text
 * System"'s doCommandBySelector: dispatch predates Mac OS X), but not yet exercised by any of
 * these sibling projects, so not yet confirmed present on real OPENSTEP 4.2 specifically. If it
 * turns out missing there, the graceful fallback is simply that Tab/Up/Down stop doing their
 * special thing and fall back to NSTextField's own default handling -- Return/submission (a plain
 * target-action, definitely safe) is unaffected either way. */
- (BOOL)control:(NSControl *)control textView:(NSTextView *)textView doCommandBySelector:(SEL)commandSelector
{
    if (commandSelector == @selector(insertTab:)) { [self handleTabComplete]; return YES; }
    if (commandSelector == @selector(moveUp:)) { [self recallHistory:-1]; return YES; }
    if (commandSelector == @selector(moveDown:)) { [self recallHistory:1]; return YES; }
    return NO;
}

/* ---------------------------------------------------------------- */
/* TerminalView delegate                                             */

- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n
{
    /* The message log is read-only now -- typing happens in inputField. Nothing to forward. */
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
