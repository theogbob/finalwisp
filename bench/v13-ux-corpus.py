#!/usr/bin/env python3
"""v13-ux (note 60.60): build the command-line corpus for the unit test cli::tests::corpus_parses_as_before.

Every case is a command line (and maybe a --config file) that real use or a test or the fuzz corpus holds:
  compat   string literals of tests/compat/*.py, bench/wispsuite/compat.py, bench/v13-form-fn.py (runs of literals
           with an option in them; literals with a newline whose first word looks like an option = a config file)
  docs     `finalwisp ...` lines of README*.md, CHANGELOG.md, docs/*.md (code blocks and code spans), the config
           file examples there
  contrib  the systemd unit's ExecStart, the Dockerfile's ENTRYPOINT + CMD and its `docker run` comments,
           contrib/public.conf as a config file
  fuzz     server/fuzz/regress/cli-parse and config-parse, decoded the way the fuzz targets decode them AT THE BASE
           COMMIT (the selector bytes index the flag lists of that commit: --base-cli, --base-fuzz)
Output (stdout or --out): one case per line, `CMD<TAB>FILE`: the words of CMD separated by one space, FILE `-` (no
--config file) or the file's bytes. Bytes outside 0x21..0x7e and `%` are written %XX; a lone `%` is an empty word or
an empty file. Sorted, no duplicates.
The classes (what the parser of the base commit made of each case) are added by the unit test itself, run at the base
commit with FW_CORPUS_WRITE=OUT (see the test's comment)."""
import argparse, ast, io, os, re, shlex, subprocess, sys, tokenize

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ap.add_argument("--base", default="016cc67c", help="the commit whose flag lists decode the fuzz corpus")
ap.add_argument("--fuzz-max", type=int, default=20000, help="skip fuzz cases whose line is longer")
ap.add_argument("--prune", help="a classed corpus (the unit test's FW_CORPUS_WRITE output): drop its `err` cases longer "
                "than --err-max (they repeat the short ones; every `run` and `preset` case stays), write the rest to --out")
ap.add_argument("--err-max", type=int, default=300)
ap.add_argument("--out")
a = ap.parse_args()
R = os.path.abspath(a.repo)
if a.prune:
    keep, dropped = [], 0
    for l in open(a.prune, encoding="utf-8").read().splitlines():
        cmd, file, cls = l.split("\t", 2)
        if cls == "err" and len(cmd) + len(file) > a.err_max: dropped += 1
        else: keep.append(l)
    head = ("# 60.60 corpus of real command lines for cli::tests::corpus_parses_as_before. Made by bench/v13-ux-corpus.py (the\n"
            "# cases) and the unit test at the base commit (the third column; see the test). CMD<TAB>FILE<TAB>CLASS[<TAB>changed fields]\n")
    open(a.out, "w", encoding="utf-8").write(head + "\n".join(keep) + "\n")
    cls = {}
    for l in keep: cls[l.split("\t")[2]] = cls.get(l.split("\t")[2], 0) + 1
    print("v13-ux-corpus: kept %d (%s), dropped %d long err cases" % (len(keep), ", ".join("%s %d" % kv for kv in sorted(cls.items())), dropped), file=sys.stderr)
    sys.exit(0)

def pct(b):
    if isinstance(b, str): b = b.encode()
    if not b: return "%"
    return "".join(chr(c) if 0x21 <= c <= 0x7e and c != 0x25 else "%%%02X" % c for c in b)

cases, stats = set(), {}
def add(kind, words, file=None):
    words = [w for w in words]
    if not words and file is None: return
    line = " ".join(pct(w) for w in words) + "\t" + ("-" if file is None else pct(file))
    if kind.startswith("fuzz") and len(line) > a.fuzz_max:
        stats[kind + " (skipped: long)"] = stats.get(kind + " (skipped: long)", 0) + 1; return
    if line not in cases:
        cases.add(line); stats[kind] = stats.get(kind, 0) + 1

FLAGLIKE = re.compile(r"^[a-z][a-z0-9-]*$")
def confish(s):
    """a string that looks like a config file: several lines, the first word of the first line an option name"""
    first = s.lstrip().split("\n")[0].split(" ")[0].split("\t")[0]
    return "\n" in s and FLAGLIKE.match(first) is not None and len(first) > 2

# ---- compat: runs of string literals
def py_cases(path):
    src = open(path, encoding="utf-8").read()
    run = []
    def flush():
        if any(w.startswith("--") for w in run): add("compat", list(run))
        run.clear()
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, SyntaxError):
        return
    for t in toks:
        if t.type == tokenize.STRING:
            try: v = ast.literal_eval(t.string)
            except (ValueError, SyntaxError): flush(); continue   # an f-string: its value is not known here
            if not isinstance(v, str): flush(); continue
            if confish(v): add("compat-file", ["--config", "f"], v); flush(); continue
            if "\n" in v or len(v) > 200: flush(); continue
            run.append(v)
        elif t.type in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT) or t.string == ",":
            continue
        else:
            flush()
    flush()

for d, names in (("tests/compat", None), ("bench/wispsuite", ["compat.py"]), ("bench", ["v13-form-fn.py"])):
    for n in sorted(names or os.listdir(os.path.join(R, d))):
        if n.endswith(".py") and os.path.isfile(os.path.join(R, d, n)): py_cases(os.path.join(R, d, n))

# ---- docs: finalwisp command lines, config file examples
def cmdline(s, kind):
    s = s.strip()
    s = re.sub(r"^(\$ |sudo |ExecStart=)", "", s)
    m = re.match(r"^(?:\S*/)?finalwisp(?::\S+)?\s+(.*)$", s)
    if not m: return
    try: words = shlex.split(m.group(1), comments=True)
    except ValueError: return
    if not words or any(w in ("...", "|", ">", "&&", ";") or "<" in w for w in words): return
    if not any(w.startswith("-") or w.isdigit() for w in words): return
    add(kind, words)

def md_cases(path):
    text = open(path, encoding="utf-8").read().replace("\\\n", " ")
    for block in re.findall(r"```[a-z]*\n(.*?)```", text, re.S):
        for l in block.split("\n"): cmdline(l, "docs")
        lines = [l for l in block.split("\n") if l.strip() and not l.lstrip().startswith("#")]
        if lines and all(FLAGLIKE.match(l.split()[0]) for l in lines) and not any(l.startswith("finalwisp") for l in lines):
            add("docs-file", ["--config", "f"], block)
    for span in re.findall(r"`([^`\n]+)`", text): cmdline(span, "docs")

for n in sorted(os.listdir(R)):
    if n.endswith(".md"): md_cases(os.path.join(R, n))
for n in sorted(os.listdir(os.path.join(R, "docs"))):
    if n.endswith(".md"): md_cases(os.path.join(R, "docs", n))

# ---- contrib
unit = open(os.path.join(R, "contrib/finalwisp.service")).read()
for l in unit.split("\n"): cmdline(l.lstrip("# "), "contrib")
dock = open(os.path.join(R, "contrib/docker/Dockerfile")).read()
arr = lambda key: [w.strip().strip('"') for w in re.search(r"^%s \[(.*)\]$" % key, dock, re.M).group(1).split(",")]
entry, cmd = arr("ENTRYPOINT"), arr("CMD")
add("contrib", entry[1:] + cmd)
for m in re.finditer(r"docker run .*?finalwisp:\S+((?: +[^\n(]+)?)", dock):
    extra = shlex.split(m.group(1).split(" (")[0]) if m.group(1).strip() else cmd
    add("contrib", entry[1:] + [w for w in extra if w != "\\"])
add("contrib-file", ["--config", "f"], open(os.path.join(R, "contrib/public.conf"), "rb").read())
add("contrib-file", ["--preset", "none", "--config", "f"], open(os.path.join(R, "contrib/public.conf"), "rb").read())

# ---- fuzz: the regress corpora, decoded with the base commit's flag lists
def show(path): return subprocess.run(["git", "-C", R, "show", f"{a.base}:{path}"], capture_output=True, text=True, check=True).stdout
fz = show("server/fuzz/fuzz_targets/cli_parse.rs")
FZ = re.findall(r'^\s+"([^"]*)",', fz[fz.index("const FLAGS"):fz.index("];")], re.M)
cl = show("server/src/cli.rs")
CL = re.findall(r'\("(--[a-z0-9-]+)", (?:true|false)\)', cl[cl.index("pub const FLAGS"):cl.index("];", cl.index("pub const FLAGS"))])
PRESETS = ["public", "none"]
assert len(FZ) == 79 and len(CL) == 69, (len(FZ), len(CL))
lossy = lambda b: b.decode("utf-8", errors="replace")

d = os.path.join(R, "server/fuzz/regress/cli-parse")
for n in sorted(os.listdir(d)):
    data = open(os.path.join(d, n), "rb").read()
    words = [FZ[(t[0] - 1 + 31 * (len(t) - 1)) % len(FZ)] if t and 1 <= t[0] <= 0x1f else lossy(t) for t in data.split(b"\0")]
    add("fuzz-cli", words)
d = os.path.join(R, "server/fuzz/regress/config-parse")
for n in sorted(os.listdir(d)):
    data = open(os.path.join(d, n), "rb").read()
    i = data.find(b"\xff\xfe")
    cmd, file = (data[:i], data[i + 2:]) if i >= 0 else (b"", data)
    words = []
    if cmd:
        for t in cmd.split(b"\0"):
            if t and t[0] == 0x1f: words.append("--config" if len(t) == 1 else "--preset" if len(t) == 2 else PRESETS[len(t) % 2])
            elif t and 1 <= t[0] <= 0x1e: words.append(CL[(t[0] - 1 + 31 * (len(t) - 1)) % len(CL)])
            else: words.append(lossy(t))
    if "--config" not in words: words += ["--config", "F"]
    add("fuzz-config", words, file)

out = "\n".join(sorted(cases)) + "\n"
(open(a.out, "w") if a.out else sys.stdout).write(out)
print("v13-ux-corpus: %d cases: %s" % (len(cases), ", ".join("%s %d" % kv for kv in sorted(stats.items()))), file=sys.stderr)
