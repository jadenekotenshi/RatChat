#import "Compat.h"

/* A small connect panel -- server/port/nick/username/real name -- mirroring StepSSH's own
 * ConnectController in shape but trimmed to what an IRC connection actually needs (no key auth,
 * no host-key verification, no saved-profiles list yet). */
@interface ConnectController : NSObject
{
    id       owner;
    NSPanel *panel;
    NSTextField *hostField, *portField, *nickField, *userField, *realNameField;
}
- (id)initWithOwner:(id)anOwner;
- (void)showPanel;
@end

@interface NSObject (ConnectControllerOwner)
- (void)connectController:(ConnectController *)cc didRequestHost:(NSString *)host port:(int)port
                      nick:(NSString *)nick user:(NSString *)user realName:(NSString *)realName;
@end
