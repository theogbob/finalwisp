#!/usr/bin/env python3
"""Server x case matrix (= `bench/wst matrix`).
usage: run_matrix.py CONFIG.json [--only NAME ...] [--out-dir DIR] [--reps N]
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import matrix
matrix.main(sys.argv[1:])
