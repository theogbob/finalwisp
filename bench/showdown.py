#!/usr/bin/env python3
"""30.02 visual head-to-head (= `bench/wst showdown`).
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import showdown
showdown.main(sys.argv[1:])
