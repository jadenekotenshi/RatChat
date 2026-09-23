/*
 * Compat.h -- the only place that knows about differences between OPENSTEP 4.2
 * and the modern SDK used on the development Mac to syntax-check these sources.
 *
 * VERIFY ON OPENSTEP (first build): the two items marked [V].
 */
#ifndef COMPAT_H
#define COMPAT_H

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

#ifdef OPENSTEP
/* [V] PostScript operator wrappers.  If this header is not found, try
 * <dpsclient/psops.h> (NEXTSTEP 3.x location). */
#import <AppKit/psops.h>
#else
/* Development host only: stubs so `make check-objc` can syntax-check on macOS. Never linked. */
extern void PSmoveto(float x, float y);
extern void PSshow(const char *s);
/* Exists in OpenStep's NSFont (removed from modern Cocoa); declared so the host syntax check passes. */
@interface NSFont (OpenStepHostStub)
- (float)widthOfString:(NSString *)string;
@end
#endif

/* [V] Characters delivered by -[NSEvent characters] for function keys: the
 * Unicode private-use codes NSEvent.h calls NSUpArrowFunctionKey etc.  Named
 * differently here so they cannot collide with the system header. */
#define KEYCH_UP        0xF700
#define KEYCH_DOWN      0xF701
#define KEYCH_LEFT      0xF702
#define KEYCH_RIGHT     0xF703
#define KEYCH_F1        0xF704          /* F1..F12 = 0xF704..0xF70F */
#define KEYCH_INSERT    0xF727
#define KEYCH_DELETE    0xF728          /* forward delete */
#define KEYCH_HOME      0xF729
#define KEYCH_END       0xF72B
#define KEYCH_PGUP      0xF72C
#define KEYCH_PGDN      0xF72D

#define BACKTAB_CHAR    0x19            /* Shift-Tab */

/* [V] The return type of -draggingEntered:/-draggingUpdated: (SFTPBrowser.m's SFTPTableView).  This
 * OPENSTEP install rejects the type name NSDragOperation outright ("undefined type") even though the
 * NSDragOperationNone/Copy constants -- plain integers, not typedef'd -- compile fine; apparently no
 * typedef of that name exists here.  unsigned int is what the type is defined to be on a 32-bit
 * target regardless of what (if anything) that name resolves to, so it is ABI-compatible either way;
 * the dev host still returns the real NSDragOperation, to avoid an actual width mismatch against the
 * 64-bit modern SDK's own declaration of the same informal protocol method. */
#ifdef OPENSTEP
typedef unsigned int SSDragOp;
#else
typedef NSDragOperation SSDragOp;
#endif

/* Dev-host builds use a newer SDK where a few selectors changed type; nothing to do. */

#endif
