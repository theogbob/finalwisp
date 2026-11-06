#!/usr/bin/env python3
"""60.01 Phase B regression harness (= `bench/wst regress`); see `bench/wst regress --help`.
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import regress
regress.main(sys.argv[1:])
