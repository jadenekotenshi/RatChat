#!/usr/bin/env python3
"""Flag a string literal split across two lines relying on implicit adjacent-literal
concatenation, e.g.:

    [label setStringValue:@"first half "
                            "second half"];

Real OPENSTEP 4.2's gcc 2.7.2 does not reliably concatenate an @"..." NSString literal with a
following plain "..." literal this way (found the hard way: "syntax error" pointing at the tail
of the second literal, on real hardware only -- the dev Mac's modern clang accepts it silently).
Keep the whole literal on one line instead (see AppController.m's entropy-panel label, or
StepSSH's own precedent for the same string).
"""
import glob, re, sys

def clean(src):
    src = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), src, flags=re.S)
    return re.sub(r'//[^\n]*', '', src)

CONT_END = re.compile(r'"\s*$')                 # line's last non-space char is a string's closing "
CONT_START = re.compile(r'^\s*@?"')              # next line starts with an (optional @) string

bad = []
for path in sorted(glob.glob("app/*.m") + glob.glob("app/*.h")):
    lines = clean(open(path).read()).split("\n")
    for i in range(len(lines) - 1):
        if CONT_END.search(lines[i]) and CONT_START.match(lines[i + 1]):
            bad.append("%s:%d: string literal appears to continue on line %d via implicit concatenation"
                       % (path, i + 1, i + 2))
for b in bad: print("STRING-CONCAT: " + b)
if not bad: print("string literal continuations: clean")
sys.exit(1 if bad else 0)
