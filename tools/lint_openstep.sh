#!/bin/sh
# Reject language features and APIs that did not exist on OPENSTEP 4.2
# (gcc 2.7.2 + the 1996 OpenStep Foundation/AppKit).  Run: make lint
cd "$(dirname "$0")/.." || exit 2
status=0
check() {   # description, extended-regex, files...
    desc=$1; re=$2; shift 2
    hits=$(grep -nE "$re" "$@" 2>/dev/null | grep -v '^[^:]*:[0-9]*:[[:space:]]*/\?\*' | grep -v '^[^:]*:[0-9]*:[[:space:]]*//')
    if [ -n "$hits" ]; then echo "LINT: $desc"; echo "$hits" | sed 's/^/    /'; status=1; fi
}
OBJC="app/*.m app/*.h"
CSRC="core/*.c core/*.h term/*.c term/*.h"

# --- language ---
check "// comments (gcc 2.7.2 -ansi rejects them in C)"     '(^|[^:"])//[^"]*$'                   $CSRC
check "@property/@synthesize/@autoreleasepool"              '@(property|synthesize|autoreleasepool|try|catch|finally)' $OBJC
check "blocks"                                              '\^[[:space:]]*\{|\^[[:space:]]*\([^)]*\)[[:space:]]*\{' $OBJC
check "dot syntax on objects / literals"                    '@\[|@\{|@[0-9(]'                     $OBJC
check "fast enumeration"                                    'for[[:space:]]*\([^;)]*[[:space:]]in[[:space:]]' $OBJC
check "modern integer types (NSInteger/CGFloat/...)"        '\b(NSInteger|NSUInteger|CGFloat|CGRect|CGPoint|instancetype|nullable|__weak|__strong)\b' $OBJC
check "stdint / stdbool / inline / restrict"                '#include[[:space:]]*<(stdint|stdbool|inttypes)\.h>|\binline\b|\brestrict\b' $CSRC
check "declaration in for-init (C99)"                       'for[[:space:]]*\((int|unsigned|size_t|u8|u32)[[:space:]]+[a-z_]+[[:space:]]*=' core/*.c term/*.c
check "snprintf/vsnprintf (not guaranteed on 4.2)"          '\bv?snprintf\b'                      core/*.c term/*.c app/*.m

# --- APIs added after OpenStep 4.2 ---
check "NSString drawing (drawAtPoint:withAttributes:) -- use PSshow"   'drawAtPoint|drawInRect:.*withAttributes|sizeWithAttributes' $OBJC
check "NSString UTF8String (use dataUsingEncoding:)"         '\bUTF8String\b|stringWithUTF8String'  $OBJC
check "NSStream / NSURL session / GCD / performSelectorOnMainThread" 'NSStream|NSURLSession|dispatch_|performSelectorOnMainThread|NSOperation' $OBJC
check "NSSecureTextField (use SecretField)"                 'NSSecureTextField'                    $OBJC
check "stringByTrimmingCharactersInSet"                     'stringByTrimmingCharactersInSet'      $OBJC
check "NSAlert class / sheets"                              '\bNSAlert\b|beginSheet|NSSavePanel.*Sheet' $OBJC
check "NSApplicationMain"                                   'NSApplicationMain'                    $OBJC
check "-addObjectsFromArray shorthands / NSArray subscripting" '\[[a-zA-Z_]+ (objectAtIndexedSubscript|containsString|hasPrefix:)' $OBJC
check "NSLog with %ld/%lu (LP64 formats)"                   '%l[du]'                               $OBJC

check "floor/ceil/strdup in app code (implicit decl. is silently wrong for double-returning libm; strdup is not ANSI)" '\b(floor|ceil|strdup)[[:space:]]*\(' app/*.m

# --- shell in the OPENSTEP makefile: stock NeXT/BSD userland, no GNU/POSIX-2001 extras ---
check "mkdir -p / cp -r / install -D in Makefile.openstep (OPENSTEP mkdir has no -p)" \
      '(^|[[:space:]@;&|])(mkdir[[:space:]]+-p|install[[:space:]]+-D|cp[[:space:]]+-a)\b' Makefile.openstep

# --- every source file must be listed in the hand-written OPENSTEP object list ---
for f in core/*.c term/*.c app/*.m; do
    o=$(echo "$f" | sed 's/\.[cm]$/.o/')
    grep -q "$o" Makefile.openstep || { echo "LINT: $f is not listed in Makefile.openstep (it would fail to link)"; status=1; }
done

# --- the application icon: Workspace reads it from a __ICON segment linked into the executable ---
if [ ! -f app/RatChat.iconheader ] || [ ! -f app/RatChat.tiff ]; then
    echo "LINT: app/RatChat.iconheader and app/RatChat.tiff are both required (Workspace icon)"; status=1
elif ! awk -F'\t' 'NF != 4 || ($1 != "F" && $1 != "S") { bad = 1 } END { exit bad }' app/RatChat.iconheader; then
    echo "LINT: app/RatChat.iconheader lines must be 4 TAB-separated fields starting F or S"; status=1
fi
grep -q "__ICON" Makefile.openstep || { echo "LINT: Makefile.openstep does not link the __ICON segment"; status=1; }

# --- static tables of Objective-C string constants (old gcc may reject them) ---
if command -v python3 >/dev/null 2>&1; then
    python3 tools/check_static_init.py >/dev/null || { python3 tools/check_static_init.py; status=1; }
fi

# --- Objective-C methods used before gcc 2.7.2 can know about them ---
if command -v python3 >/dev/null 2>&1; then
    python3 tools/check_method_order.py >/dev/null || { python3 tools/check_method_order.py; status=1; }
fi

# --- string literals split across lines via implicit adjacent-literal concatenation ---
if command -v python3 >/dev/null 2>&1; then
    python3 tools/check_string_concat.py >/dev/null || { python3 tools/check_string_concat.py; status=1; }
fi

if [ $status -eq 0 ]; then echo "lint: clean"; fi
exit $status
