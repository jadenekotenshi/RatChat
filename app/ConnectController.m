#import "ConnectController.h"
#import "UIHelpers.h"

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface ConnectController (Private)
- (void)buildPanel;
@end

@implementation ConnectController

- (id)initWithOwner:(id)anOwner
{
    self = [super init];
    if (!self) return nil;
    owner = anOwner;
    return self;
}

- (void)dealloc
{
    [panel release];
    [super dealloc];
}

- (void)buildPanel
{
    NSView *c;
    NSButton *connectBtn, *cancelBtn;
    /* Column plan: labels 14..94, fields 100..306.  Every row is 34 high. */

    panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 420, 246)
                                       styleMask:(NSTitledWindowMask | NSClosableWindowMask)
                                         backing:NSBackingStoreBuffered
                                           defer:NO];
    [panel setTitle:@"Connect to Server"];
    [panel setReleasedWhenClosed:NO];
    [panel setHidesOnDeactivate:NO];
    c = [panel contentView];

    [c addSubview:ui_label(@"Server:", NSMakeRect(14, 208, 80, 20))];
    hostField = ui_field(NSMakeRect(100, 206, 196, 22));
    [c addSubview:hostField];
    [c addSubview:ui_label(@"Port:", NSMakeRect(304, 208, 36, 20))];
    portField = ui_field(NSMakeRect(342, 206, 64, 22));
    [portField setStringValue:@"6667"];
    [c addSubview:portField];

    [c addSubview:ui_label(@"Nickname:", NSMakeRect(14, 174, 80, 20))];
    nickField = ui_field(NSMakeRect(100, 172, 306, 22));
    [c addSubview:nickField];

    [c addSubview:ui_label(@"Username:", NSMakeRect(14, 140, 80, 20))];
    userField = ui_field(NSMakeRect(100, 138, 306, 22));
    [userField setStringValue:NSUserName()];
    [c addSubview:userField];

    [c addSubview:ui_label(@"Real name:", NSMakeRect(14, 106, 80, 20))];
    realNameField = ui_field(NSMakeRect(100, 104, 306, 22));
    [realNameField setStringValue:NSUserName()];
    [c addSubview:realNameField];

    connectBtn = [[[NSButton alloc] initWithFrame:NSMakeRect(328, 16, 78, 30)] autorelease];
    [connectBtn setTitle:@"Connect"];
    [connectBtn setTarget:self];
    [connectBtn setAction:@selector(connect:)];
    [connectBtn setKeyEquivalent:@"\r"];
    [c addSubview:connectBtn];
    cancelBtn = [[[NSButton alloc] initWithFrame:NSMakeRect(242, 16, 78, 30)] autorelease];
    [cancelBtn setTitle:@"Cancel"];
    [cancelBtn setTarget:self];
    [cancelBtn setAction:@selector(cancel:)];
    [c addSubview:cancelBtn];

    [hostField setNextKeyView:portField];
    [portField setNextKeyView:nickField];
    [nickField setNextKeyView:userField];
    [userField setNextKeyView:realNameField];
    [realNameField setNextKeyView:hostField];
    [panel setInitialFirstResponder:hostField];
    [panel center];
}

- (void)showPanel
{
    if (!panel) [self buildPanel];
    [panel makeKeyAndOrderFront:nil];
    [panel makeFirstResponder:hostField];
}

- (void)cancel:(id)sender { [panel orderOut:nil]; }

- (void)connect:(id)sender
{
    NSString *h = ui_trim([hostField stringValue]);
    NSString *nk = ui_trim([nickField stringValue]);
    NSString *u = ui_trim([userField stringValue]);
    NSString *r = ui_trim([realNameField stringValue]);
    int p = [[portField stringValue] intValue];

    if ([h length] == 0 || [nk length] == 0) {
        NSRunAlertPanel(@"Missing information", @"Enter a server and a nickname.", @"OK", nil, nil);
        return;
    }
    if (p < 1 || p > 65535) {
        NSRunAlertPanel(@"Bad port", @"The port must be a number from 1 to 65535.", @"OK", nil, nil);
        return;
    }
    if ([u length] == 0) u = nk;
    if ([r length] == 0) r = nk;

    [panel orderOut:nil];
    if ([owner respondsToSelector:@selector(connectController:didRequestHost:port:nick:user:realName:)])
        [owner connectController:self didRequestHost:h port:p nick:nk user:u realName:r];
}

@end
