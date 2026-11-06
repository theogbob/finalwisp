"""wst: the wisp test suite (30.10). usage: wst <command> [args]   (wst <command> --help for details)

  compat    functional gates: --bin FINALWISP (exit 1 on any failure) or --server ANY (report mode)
  ab        rotated interleaved A/B of server variants (wbench)
  regress   Phase B gate: new build vs base (lo/tls/idle/link/potato), exact paired Wilcoxon, one table
  matrix    servers x cases from a matrix JSON (+ --reps medians)
  showdown  live visual head-to-head of Wisp servers
  wispmark  WispMark-compatible grid with the real clients (wisp-js, wisp-mux)
  potato    survival + throughput under MemoryMax scopes (16-128 MiB)
  link      root: netns rate/delay link up/down, A/B over it
  idle      KiB per idle connection
  browser   real-user simulator: headless Chromium + Scramjet over Wisp (quick subset; --full = all)
"""
import os, sys

COMMANDS = {"compat": "compat", "ab": "ab", "regress": "regress", "matrix": "matrix", "showdown": "showdown",
            "wispmark": "wispmark", "potato": "potato", "link": "link", "idle": "idle", "browser": "browser"}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0 if argv else 2)
    cmd = argv[0]
    if cmd not in COMMANDS:
        sys.exit(f"wst: unknown command '{cmd}'\n{__doc__}")
    # Every command starts servers, wbench clients and targets that inherit this limit; an interactive shell's soft
    # 1024 made 100x10 cases (1000 streams -> 1000 target sockets) fail ~190 streams with 0x03 (gold 2026-10-29).
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    import importlib
    mod = importlib.import_module(f"wispsuite.{COMMANDS[cmd]}")
    mod.main(argv[1:])


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()
