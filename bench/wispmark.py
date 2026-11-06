#!/usr/bin/env python3
"""30.03 WispMark-style benchmark (= `bench/wst wispmark`).
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import wispmark
wispmark.main(sys.argv[1:])
