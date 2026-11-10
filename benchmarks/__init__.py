"""Sentinel evaluation harness.

The reports in this package draw tables with box-drawing characters, which
the default Windows console codepage (cp1252) cannot encode. Reconfiguring
here covers every entry point in the package.
"""

import sys

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")
