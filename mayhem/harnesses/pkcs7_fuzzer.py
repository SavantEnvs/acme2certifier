#!/usr/bin/env python3
"""Mayhem entry for upstream's OSS-Fuzz harness fuzz/pkcs7_fuzzer.py, run unchanged.

The upstream file is exec'd in-process (not runpy, which would rewrite sys.argv[0]) so atheris's
-fork=N mode re-execs THIS executable file rather than the non-executable upstream one.
"""
import os
import sys

import atheris  # noqa: F401  (the harness imports and instruments it; named here for the gates)

_HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "fuzz", "pkcs7_fuzzer.py")
_HARNESS = os.path.normpath(_HARNESS)

if __name__ == "__main__":
    with open(_HARNESS, encoding="utf-8") as fh:
        code = compile(fh.read(), _HARNESS, "exec")
    exec(code, {"__name__": "__main__", "__file__": _HARNESS, "__builtins__": __builtins__})
