#import "Compat.h"
#include <stdarg.h>

/* Small control factories shared by the hand-built panels.  All return autoreleased objects. */
NSTextField *ui_label(NSString *text, NSRect frame);
NSTextField *ui_wrapping_label(NSString *text, NSRect frame, BOOL selectable);
NSTextField *ui_field(NSRect frame);
NSButton    *ui_switch(NSString *title, NSRect frame);
NSButton    *ui_button(NSString *title, NSRect frame, id target, SEL action);
NSString    *ui_trim(NSString *s);          /* OpenStep has no NSString trimming method, so this is hand-written */

/* Incoming IRC message bytes are usually UTF-8, though not guaranteed by the protocol.  NSString +stringWithCString: would read them as NeXTSTEP text,
 * so decode by hand (invalid bytes fall back to Latin-1) and encode with NUL termination. */
NSString *ui_string_from_utf8(const char *bytes);
NSData   *ui_utf8_cstring(NSString *s);              /* bytes of s in UTF-8 plus a trailing NUL */
#define UI_CPATH(s) ((const char *)[ui_utf8_cstring(s) bytes])

/* [V] NSCalendarDate is standard OpenStep API (predates NSDateFormatter), but unlike NSDate/NSTimer
 * (already relied on throughout PTYSession/SSHSession's own poll loops, confirmed on real
 * hardware) it has not been exercised anywhere in these sibling projects before now -- confirm
 * this actually works the first time RatChat runs on real OPENSTEP hardware. */
NSString *ui_timestamp(void);                        /* "HH:MM", local time, for a chat line */

/* Startup diagnostics.  If the file ~/.RatChat.trace exists (create it with `touch`), SSTrace()
 * appends printf-style lines to it; otherwise it does nothing.  Workspace discards a launched
 * application's stderr, so this is how to see how far a launch from Workspace got. */
void SSTrace(const char *fmt, ...);
void SSTraceV(NSString *path, const char *fmt, va_list ap);   /* same, for any path (used by the tests) */
#define SSCS(s) ((s) != nil ? [(s) cString] : "(nil)")      /* an NSString as a C string, nil-safe */
