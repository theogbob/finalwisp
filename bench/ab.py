#!/usr/bin/env python3
"""30.09 rotated interleaved A/B (= `bench/wst ab`).
usage: ab.py VARIANTS.json REPS --test T --conns C --streams S [wbench run args...]  (env: RAW LINK WBENCH PORT TPORT TMODE DUR WARMUP
AB_TLS FW_AB_ROTATE SRV_PREFIX CLI_PREFIX SRV_HOST SRV_BIND; see `bench/wst ab --help`)
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import ab
ab.main(sys.argv[1:])
