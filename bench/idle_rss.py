#!/usr/bin/env python3
"""30.06 idle RSS probe (one probe against a running server; `bench/wst idle` runs whole comparisons).
Usage: idle_rss.py WS_PORT ECHO_PORT SERVER_PID N [size] [settle]
Thin wrapper (30.10): the code lives in bench/wispsuite/. Same command line as before."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import idle
idle.probe_main(sys.argv[1:])
