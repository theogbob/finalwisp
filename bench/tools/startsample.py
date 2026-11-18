#!/usr/bin/env python3
"""Print the two start samples of the public docs from a finalwisp binary, or check that the docs hold them.

usage: bench/tools/startsample.py [--bin BIN] [--check | --write]

The docs show what `finalwisp` prints at startup on a terminal, twice:
  getting-started.md "First run"     `finalwisp` (no option, no file)
  configuration.md   "Config file"   `finalwisp --config /etc/finalwisp.conf` with the file shown below that sample
Each sample is the fenced block right after an HTML comment that starts with "<!-- sample:".

The script starts BIN for each sample with stderr on a pseudo-terminal (so the lines wrap as on a terminal) and
NO_COLOR=1 (no colour codes), reads the start lines, and stops it with SIGTERM. Every server listens on 127.0.0.1
only: the first on the default port 6001, the second on 6001 and metrics port 9100 (both must be free: the script
refuses otherwise, since another port would add a `command line` row and change the column width). The config file
is written to a /tmp path of the same length as /etc/finalwisp.conf (the value wraps the same) and named
/etc/finalwisp.conf in the output.

  (no flag)  print both samples (comment line + block) as they would stand in the docs
  --check    compare each docs block with the binary's output; the values of this host (threads, memory, open
             files, the TCP buffer line) are masked on both sides. Exit 1 on a difference.
  --write    replace both blocks and their comments in the docs with this binary's output
  --port P   (with --check only) run the servers on P and the metrics on P + 1 instead of 6001 / 9100, for a gate
             that owns a port range. The output then differs only in the URL, a `command line  port P` row, the
             metrics port and the width of the key column; --check compares rows by key and value with those undone
             (the wrap of long values is then not compared: ui.rs unit tests cover it).
BIN defaults to the release build of this tree (server/target/x86_64-unknown-linux-gnu/release/finalwisp).
"""
import argparse, hashlib, os, pty, re, secrets, select, signal, socket, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONF_SHOWN = "/etc/finalwisp.conf"
CONF_TEXT = "preset public\ntrusted-proxy 127.0.0.1\nmax-streams-per-conn 256\nmetrics-listen 9100\n"
SAMPLES = [  # (page, the command shown, arguments, ports that must be free)
    ("docs/getting-started.md", None, [], [6001]),
    ("docs/configuration.md", f"$ finalwisp --config {CONF_SHOWN}", ["--config", "CONF"], [6001, 9100]),
]
HOST_ROWS = ("threads", "memory", "open files", "TCP buffer")  # values that depend on the host


def port_free(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def start_lines(binary, args, ports, port=None):
    """the lines BIN writes to a terminal at startup, up to (not with) its SIGTERM line; port: P and P + 1 for 6001 / 9100"""
    if port:
        ports = [port if p == 6001 else port + 1 for p in ports]
        args = args + ["--port", str(port)]
    for p in ports:
        if not port_free(p):
            sys.exit(f"startsample: port {p} on 127.0.0.1 is in use; the sample needs it free")
    conf = None
    if "CONF" in args:
        while True:  # same length as /etc/finalwisp.conf, created exclusively
            conf = f"/tmp/fw{secrets.token_hex(4)[:7]}.conf"
            assert len(conf) == len(CONF_SHOWN)
            try:
                fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                continue
        os.write(fd, (CONF_TEXT.replace("metrics-listen 9100", f"metrics-listen {port + 1}") if port else CONF_TEXT).encode())
        os.close(fd)
        args = [conf if a == "CONF" else a for a in args]
    master, slave = pty.openpty()
    env = {"PATH": "/usr/bin:/bin", "TERM": "xterm", "NO_COLOR": "1", "HOME": os.environ.get("HOME", "/")}
    p = subprocess.Popen([binary] + args, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave, env=env, start_new_session=True)
    os.close(slave)
    out, t0 = b"", time.time()
    try:
        while time.time() - t0 < 3.0:  # the block comes at once; wait for 0.8 s without output after it
            r, _, _ = select.select([master], [], [], 0.8)
            if not r:
                if out:
                    break
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    finally:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        os.close(master)
        if conf:
            os.unlink(conf)
    text = out.decode().replace("\r\n", "\n")
    if conf:
        text = text.replace(conf, CONF_SHOWN)
    if port:  # undo the other ports (the `command line  port P` row is dropped by rows())
        text = text.replace(f"127.0.0.1:{port}/", "127.0.0.1:6001/").replace(f"metrics-listen {port + 1}", "metrics-listen 9100")
        text = text.replace(f"127.0.0.1:{port + 1}/metrics", "127.0.0.1:9100/metrics")
    lines = [l.rstrip() for l in text.split("\n")]
    lines = [l for l in lines if l]
    cut = next((i for i, l in enumerate(lines) if l.startswith("finalwisp: SIGTERM")), len(lines))
    lines = lines[:cut]
    if not lines or not lines[0].startswith("finalwisp listening on "):
        sys.exit(f"startsample: {binary} {' '.join(args)} did not print the start block:\n" + "\n".join(lines))
    return lines


def version(lines):
    m = next((re.match(r"^\s+version\s+(\S+)$", l) for l in lines if re.match(r"^\s+version\s", l)), None)
    return m.group(1) if m else "?"


def comment(binary, lines, page):
    md5 = hashlib.md5(open(binary, "rb").read()).hexdigest()[:8]
    day = time.strftime("%Y-%m-%d", time.gmtime())
    threads = next((l.split()[-1] for l in lines if re.match(r"^\s+threads\s", l)), "?")
    extra = "; the file stood in /tmp for the run" if page.endswith("configuration.md") else ""
    return (f"<!-- sample: real output of finalwisp {version(lines)} (md5 {md5}) on a terminal ({day}, a {threads}-thread "
            f"machine{extra}); printed by bench/tools/startsample.py -->")


def block(cmd, lines):
    return "```text\n" + (cmd + "\n" if cmd else "") + "\n".join(lines) + "\n```"


SAMPLE_RE = re.compile(r"<!-- sample:[^\n]*-->\n```text\n.*?\n```", re.S)


def doc_block(page):
    text = open(os.path.join(ROOT, page), encoding="utf-8").read()
    found = SAMPLE_RE.findall(text)
    if len(found) != 1:
        sys.exit(f"startsample: {page} has {len(found)} sample blocks (\"<!-- sample:\" + a text fence); expected 1")
    return text, found[0]


def mask(lines):
    out = []
    for l in lines:
        m = re.match(r"^(\s+)(\S+(?: \S+)?)(\s+)(.*)$", l)
        if m and m.group(2) in HOST_ROWS:
            continue  # host rows: their presence (TCP buffer) and values differ per host
        out.append(l)
    return out


def rows(lines, port):
    """the start block as (key, value) rows: continuation lines joined, spacing collapsed, host rows and the
    `command line  port P` row of --port dropped (the key column's width follows the longest key)"""
    out = []
    for l in lines:
        m = re.match(r"^  (\S+(?: \S+)?)\s{2,}(\S.*)$", l)
        if l.startswith("finalwisp"):
            out.append(["", l])
        elif m:
            out.append([m.group(1), m.group(2)])
        elif out:
            out[-1][1] += " " + l.strip()
        else:
            out.append(["", l.strip()])
    out = [(k, re.sub(r"\s+", " ", v)) for k, v in out]
    return [r for r in out if r[0] not in HOST_ROWS and not (port and r == ("command line", f"port {port}"))]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bin", default=os.path.join(ROOT, "server/target/x86_64-unknown-linux-gnu/release/finalwisp"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    ap.add_argument("--port", type=int, default=None, help="with --check: servers on PORT, metrics on PORT + 1")
    a = ap.parse_args()
    if a.port and not a.check:
        sys.exit("startsample: --port is for --check only (the docs show port 6001 and metrics 9100)")
    if a.port and not 1024 <= a.port < 32767:
        sys.exit("startsample: --port must be in 1024 .. 32766")
    if not os.access(a.bin, os.X_OK):
        sys.exit(f"startsample: no binary {a.bin}")
    bad = 0
    for page, cmd, args, ports in SAMPLES:
        lines = start_lines(a.bin, args, ports, a.port)
        new = comment(a.bin, lines, page) + "\n" + block(cmd, lines)
        if a.check:
            _, old = doc_block(page)
            old_lines = old.split("\n")[2:-1]
            if cmd:
                if not old_lines or old_lines[0] != cmd:
                    print(f"{page}: the block does not start with {cmd!r}")
                    bad += 1
                    continue
                old_lines = old_lines[1:]
            same = rows(old_lines, None) == rows(lines, a.port) if a.port else mask(old_lines) == mask(lines)
            if same:
                print(f"{page}: OK ({len(lines)} lines, version {version(lines)})")
            else:
                bad += 1
                print(f"{page}: DIFFERENT (host rows masked)\n--- docs\n" + "\n".join(mask(old_lines)) + "\n--- binary\n" + "\n".join(mask(lines)))
        elif a.write:
            text, old = doc_block(page)
            open(os.path.join(ROOT, page), "w", encoding="utf-8").write(text.replace(old, new))
            print(f"{page}: written ({len(lines)} lines)")
        else:
            print(f"== {page}\n{new}\n")
    if a.check:
        print("--check: OK" if not bad else f"--check: BROKEN ({bad} sample(s) differ)")
        sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
