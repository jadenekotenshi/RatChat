#!/usr/bin/env python3
"""Find Objective-C methods called before gcc 2.7.2 can know about them.

gcc 2.7.2 only knows a method if it is declared in an @interface (or category)
or *defined earlier* in the file; modern clang looks ahead, so a host build never
notices.  The symptom on OPENSTEP is "Foo does not respond to bar".

Flags:  [self bar ...]  inside @implementation Foo  where bar is defined in Foo's
        implementation AFTER the call and is not declared for Foo anywhere.
Exit status 1 if anything is found.
"""
import glob, re, sys

METHOD_DECL = re.compile(r'^\s*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)')
files = sorted(glob.glob("app/*.h") + glob.glob("app/*.m"))
declared = {}                                   # class -> set of first keywords

def strip(src):                                 # blank out comments and strings, keep line numbers
    def blank(m): return re.sub(r'[^\n]', ' ', m.group(0))
    src = re.sub(r'/\*.*?\*/', blank, src, flags=re.S)
    src = re.sub(r'//[^\n]*', blank, src)
    return re.sub(r'@?"(?:\\.|[^"\\\n])*"', blank, src)

texts = {f: strip(open(f).read()) for f in files}

for f, text in texts.items():                   # 1. declarations (@interface / categories)
    for m in re.finditer(r'@interface\s+(\w+)[^\n]*\n(.*?)^@end', text, flags=re.S | re.M):
        cls, body = m.group(1), m.group(2)
        for line in body.split("\n"):
            d = METHOD_DECL.match(line)
            if d and line.rstrip().endswith(";"):
                declared.setdefault(cls, set()).add(d.group(1))

problems = []
for f in [f for f in files if f.endswith(".m")]:
    text = texts[f]
    for m in re.finditer(r'@implementation\s+(\w+)[^\n]*\n(.*?)^@end', text, flags=re.S | re.M):
        cls, body = m.group(1), m.group(2)
        base = text[:m.start(2)].count("\n") + 1
        defs = {}                               # keyword -> first definition line
        for i, line in enumerate(body.split("\n")):
            d = METHOD_DECL.match(line)
            if d and not line.rstrip().endswith(";"):
                defs.setdefault(d.group(1), base + i)
        for i, line in enumerate(body.split("\n")):
            for c in re.finditer(r'\[\s*self\s+([A-Za-z_]\w*)', line):
                kw = c.group(1)
                ln = base + i
                if kw in defs and defs[kw] > ln and kw not in declared.get(cls, set()):
                    problems.append("%s:%d: [%s %s ...] is called before it is defined (line %d) and never declared"
                                    % (f, ln, "self", kw, defs[kw]))
for p in problems: print("METHOD-ORDER: " + p)
if not problems: print("method order: clean")
sys.exit(1 if problems else 0)
