"""Build the timing-mode mirror (bench/browser/mirror/, gitignored): saved copies of a few real pages plus
deterministic synthetic pages, served by scenario.mjs from 127.0.0.1 so the Wisp server is the only variable.

  python3 bench/browser/mirror.py [--refresh]

Real pages are fetched once with wget (page + requisites, gentle: --wait 0.2, one page each), then made offline:
<script> elements are removed (page JS would reach the internet and add noise) and every remaining absolute
http(s) or protocol-relative URL in HTML/CSS is pointed at /__blocked/ (an instant 404). Synthetic: "assets200" (200 small images,
10 CSS, 10 JS files ~60 KiB each, deterministic bytes) and "big100" (one 100 MiB file for the download case).
The fetch date is recorded in mirror/MANIFEST.json; compare runs only against the same mirror.
"""
import argparse, datetime as dt, json, os, random, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
M = os.path.join(HERE, "mirror")
REAL = {  # name: (url, extra wget domain list)
    "wikipedia": ("https://en.wikipedia.org/wiki/WebSocket", "en.wikipedia.org,upload.wikimedia.org"),
    "hn": ("https://news.ycombinator.com/", "news.ycombinator.com"),
    "mdn": ("https://developer.mozilla.org/en-US/docs/Web/API/WebSocket", "developer.mozilla.org"),
}
SCRIPT = re.compile(r"<script\b.*?</script\s*>", re.S | re.I)
ABS = re.compile(r"""(?<=["'(=\s])(?:https?:)?//[^\s"'()<>]+""", re.I)  # absolute and protocol-relative


def fetch_real(name, url, domains):
    out = os.path.join(M, name)
    os.makedirs(out, exist_ok=True)
    cmd = ["wget", "-q", "-e", "robots=off", "--wait", "0.2", "-p", "-k", "-E", "-H", "-D", domains, "-nH",
           "--cut-dirs=0", "-P", out, "-U", "Mozilla/5.0 (X11; Linux x86_64) finalwisp-browser-sim mirror", url]
    rc = subprocess.run(cmd).returncode  # wget exits 8 when some requisite 404s; the page itself is checked below
    html = [os.path.join(d, f) for d, _, fs in os.walk(out) for f in fs if f.endswith(".html")]
    if not html:
        sys.exit(f"{name}: wget rc {rc}, no html saved")
    main = max(html, key=os.path.getsize)  # the article itself
    for d, _, fs in os.walk(out):
        for f in fs:
            p = os.path.join(d, f)
            if f.endswith((".html", ".css")) or ".css" in f:
                t = open(p, encoding="utf-8", errors="replace").read()
                if f.endswith(".html"):
                    t = SCRIPT.sub("", t)
                t = ABS.sub("/__blocked/", t)
                open(p, "w", encoding="utf-8").write(t)
    rel = os.path.relpath(main, M)  # kept under its own name: pages link to themselves (prefetch, canonical)
    return {"url": url, "entry": "/" + rel, "files": sum(len(fs) for _, _, fs in os.walk(out)),
            "bytes": sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(out) for f in fs)}


def synth():
    rnd = random.Random(1)
    d = os.path.join(M, "assets200")
    os.makedirs(d, exist_ok=True)
    parts = ["<!doctype html><html><head><meta charset=utf-8><title>assets200</title>"]
    for i in range(10):
        open(os.path.join(d, f"s{i}.css"), "w").write("".join(f".c{i}_{j}{{margin:{j % 7}px;color:#{j:06x}}}\n" for j in range(2000)))
        parts.append(f'<link rel=stylesheet href="s{i}.css">')
    for i in range(10):
        body = "".join(f"function f{i}_{j}(a){{return a*{j}+{i}}}\n" for j in range(1800))
        open(os.path.join(d, f"j{i}.js"), "w").write(body + f"window.__j{i}=f{i}_1(2);\n")
        parts.append(f'<script src="j{i}.js"></script>')
    parts.append("</head><body><h1>assets200</h1>")
    for i in range(200):
        n = rnd.randint(2048, 20480)  # 2-20 KiB "images" (random bytes; the browser fails to decode them, which is fine)
        open(os.path.join(d, f"i{i}.bin"), "wb").write(rnd.randbytes(n))
        parts.append(f'<img src="i{i}.bin" width=16 height=16 alt="">')
    parts.append("<p>" + "lorem ipsum dolor sit amet " * 400 + "</p></body></html>")
    open(os.path.join(d, "index.html"), "w").write("".join(parts))
    big = os.path.join(M, "big100.bin")
    if not os.path.exists(big) or os.path.getsize(big) != 100 << 20:
        with open(big, "wb") as f:
            for _ in range(100):
                f.write(rnd.randbytes(1 << 20))
    return {"entry": "/assets200/index.html", "files": 221}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="re-fetch the real pages")
    a = ap.parse_args(argv)
    os.makedirs(M, exist_ok=True)
    man_path = os.path.join(M, "MANIFEST.json")
    man = json.load(open(man_path)) if os.path.exists(man_path) else {}
    for name, (url, dom) in REAL.items():
        if a.refresh or name not in man:
            man[name] = dict(fetch_real(name, url, dom), fetched=dt.datetime.now().isoformat(timespec="seconds"))
            print(name, man[name])
    man["assets200"] = synth()
    json.dump(man, open(man_path, "w"), indent=1)
    print("mirror ready:", M)


if __name__ == "__main__":
    main()
