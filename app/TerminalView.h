#import "Compat.h"
#include "vt.h"

/* Informal protocol implemented by whoever owns the terminal (IRCChannelSession). */
@interface NSObject (TerminalViewDelegate)
- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n;
- (void)terminalView:(id)tv resizedToCols:(int)cols rows:(int)rows;
@end

@interface TerminalView : NSView
{
    vt        *term;
    id         delegate;
    NSScroller *scroller;
    NSFont    *font;
    float      cellW, cellH, baseline;
    int        cols, rows;
    int        scrollBack;                 /* lines back from the live screen; 0 = live */
    int        selActive;
    int        selAnchorLine, selAnchorCol, selEndLine, selEndCol;
    int        lastCx, lastCy, lastSb;
    /* Output is taken in as it arrives but handed to AppKit for redrawing at most maxFPS times a second (a flood of
     * output then costs one redraw of what changed, not one per read); the screen is redrawn at once if it has been
     * quiet for longer than that, so a typed character's echo never waits. */
    NSTimeInterval lastFlush;
    NSTimeInterval minFlushInterval;           /* 0: every write redraws */
    BOOL       pendingFlush;                   /* the terminal changed since the last flush */
    NSTimer   *flushTimer;                     /* a deferred flush is due when it fires (not retained: it is the run loop's) */
    int        flushCount;                     /* flushes so far, and what the last one asked AppKit to redraw: for the tests */
    float      lastFlushArea;
    BOOL       confirmPaste;                   /* ask before pasting more than one line */
    int        pasteAnswer;                    /* tests: -1 ask for real, 0 refuse, 1 accept */
    int        deleteSendsBackspace;       /* 1: Delete key sends ^H, 0: sends DEL */
    int        altSendsEscape;
    /* OPENSTEP delivers an arrow key as two separate keyDown events -- a lone, unmodified ESC, then
     * a lone letter (A/B/C/D for up/down/right/left: the old VT52 cursor codes, no CSI bracket) --
     * rather than one event carrying a KEYCH_UP-style codepoint. A lone ESC is held for a short time
     * to see whether one of those letters follows, the same way terminals/readline disambiguate a
     * bare Escape keypress from the start of a multi-byte special-key sequence. */
    BOOL        escPending;
    NSTimer    *escTimer;

    /* Mouse reporting (xterm protocol; see term/vt.h's vt_encode_mouse).  Whether the gesture that
     * began at the last mouseDown/rightMouseDown is being sent to the host rather than treated as
     * local text selection is decided once, at that mouseDown, and held for the whole gesture. */
    BOOL        mouseReportingActive;
    int         mouseReportButton;                    /* which button, for this gesture's drag/up events */
    int         mouseLastReportLine, mouseLastReportCol;  /* last cell a motion report was sent for */
    NSColor   *defaultFg, *defaultBg;
    NSColor   *palette[256];
}
- (id)initWithFrame:(NSRect)frame;
- (void)setDelegate:(id)anObject;
- (void)setScroller:(NSScroller *)aScroller;
- (vt *)terminal;
- (int)cols;
- (int)rows;
- (NSSize)contentSizeForCols:(int)c rows:(int)r;
- (void)writeBytes:(const unsigned char *)bytes length:(int)n;
- (void)flushDisplayIfDue;                 /* call every tick: redraws what changed once the frame interval has passed */
- (void)flushDisplay;                      /* ... or right now */
- (void)setMaxFPS:(float)fps;              /* 0 or less: no cap */
- (float)maxFPS;
- (int)flushCount;
- (float)lastFlushArea;                    /* points^2 of the last flush's redraw requests, for the tests */
- (void)setConfirmsMultilinePaste:(BOOL)flag;
- (void)setPasteAnswer:(int)answer;        /* tests: -1 ask for real, 0 refuse, 1 accept */
- (void)fitToFrame;                        /* recompute cols/rows after the view was resized */
- (void)scrollerMoved:(id)sender;
- (void)setUTF8:(BOOL)flag;
- (void)copy:(id)sender;
- (void)paste:(id)sender;
- (void)selectAll:(id)sender;
- (void)clearScrollback:(id)sender;
- (NSString *)selectedText;
@end
