#!/usr/bin/env python3
"""Flag `static` variables whose initializer contains an Objective-C string constant (@"...").
gcc 2.7.2 may not accept those as compile-time constants; initialise such tables at run time.
Follows braces across lines, so struct-typed and multi-line declarations are seen."""
import glob, re, sys

def clean(src):
    src = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), src, flags=re.S)
    src = re.sub(r'//[^\n]*', '', src)
    src = re.sub(r'@"(?:\\.|[^"\\\n])*"', '@"S"', src)          # keep the marker, drop the contents
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '"S"', src)

bad = []
for path in sorted(glob.glob("app/*.m")):
    text = clean(open(path).read())
    for m in re.finditer(r'\bstatic\b', text):
        i, depth, eq = m.end(), 0, None
        while i < len(text):
            c = text[i]
            if c in "({[": 
                if c == "{" and depth == 0 and text[:i].rstrip().endswith(")"):
                    break                                    # a function body: not a variable
                depth += 1
            elif c in ")}]": depth -= 1
            elif c == "=" and depth == 0 and eq is None and text[i + 1] != "=": eq = i
            elif c == ";" and depth == 0:
                if eq is not None and '@"' in text[eq:i]:
                    bad.append("%s:%d: static initializer contains an @\"...\" constant" % (path, text[:m.start()].count("\n") + 1))
                break
            i += 1
for b in bad: print("STATIC-INIT: " + b)
if not bad: print("static initializers: clean")
sys.exit(1 if bad else 0)
