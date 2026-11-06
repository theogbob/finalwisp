#!/usr/bin/env python3
"""20.26 potato curve, one pass (= `bench/wst potato`).
usage: potato_curve.py WBENCH OUT BIN_NAME=PATH ...  (env CPU, PEERS_CPU)
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import potato
potato.legacy_curve(sys.argv[1:])
