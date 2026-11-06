"""wst browser: real-user simulator (headless Chromium + Scramjet over Wisp; code and setup in bench/browser/README.md).

usage: wst browser [--full] [browser.py options...]
  default (quick, compat mode): transport epoxy only; cases wikipedia, hn, wikipedia-session (scroll/click/back),
           ws-echo (page WebSocket), cloudflare-25MiB (download), busy-user (download + cancel + fetches + page load).
  --full:  every case of the mode x transports epoxy, epoxy-v2, libcurl.
  An explicit --sites or --transport always wins. Timing mode (--mode timing, local mirror) runs its own case list;
  ask for the machine lock first. All other options go to bench/browser/browser.py unchanged (its help follows).
"""
import importlib.util, os, sys

BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(BENCH, "browser", "browser.py")
QUICK_SITES = ["wikipedia", "hn", "wikipedia-session", "ws-echo", "cloudflare-25MiB", "busy-user"]
FULL_TRANSPORTS = ["epoxy", "epoxy-v2", "libcurl"]


def build_argv(argv):
    """Suite defaults -> browser.py argv (pure; tested without running anything)."""
    full = "--full" in argv
    out = [x for x in argv if x != "--full"]
    has = lambda opt: any(x == opt or x.startswith(opt + "=") for x in out)
    mode = "compat"
    for i, x in enumerate(out):
        if x == "--mode" and i + 1 < len(out):
            mode = out[i + 1]
        elif x.startswith("--mode="):
            mode = x.split("=", 1)[1]
    if not has("--transport"):
        for t in (FULL_TRANSPORTS if full else ["epoxy"]):
            out += ["--transport", t]
    if not full and mode == "compat" and not has("--sites"):
        out += ["--sites", ",".join(QUICK_SITES)]
    return out


def load():
    if not os.path.isfile(SIM):
        sys.exit(f"wst browser: {SIM} not found")
    spec = importlib.util.spec_from_file_location("wst_browser_sim", SIM)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv):
    if any(x in ("-h", "--help") for x in argv):
        print(__doc__)
        load().main(["--help"])
        return
    load().main(build_argv(argv))
