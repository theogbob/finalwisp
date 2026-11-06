#!/usr/bin/env python3
"""60.01 gate runner (= `bench/wst compat --bin BIN --base-port 8110`).
usage: gates.py BIN OUTDIR   (ports 8110-8189; exit 1 on any failure)
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if len(sys.argv) != 3:
    sys.exit("usage: gates.py BIN OUTDIR")
from wispsuite import compat
master = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench/results/b1/fw-master2")
compat.main(["--bin", sys.argv[1], "--out", sys.argv[2], "--base-port", "8110"]
            + (["--membudget-master", master] if os.access(master, os.X_OK) else []))
