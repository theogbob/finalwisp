#!/usr/bin/env python3
"""Check the documentation: links, anchors, the option reference, and (optional) that no old text was lost.

usage: bench/tools/doccheck.py [--pending OPT,...] [--lost REV] [--lost-diff BASE..BRANCH]... [--rewritten FILE]
       bench/tools/doccheck.py --map REV

It reads the files of the tree it is in (the working tree, or an unpacked archive). Exit status 1 on a problem.
--lost and --lost-diff need the git history.

1. Links: every relative Markdown link in the README, docs/*.md, CHANGELOG.md, SECURITY.md and CONTRIBUTING.md names
   a file that exists, and its #anchor is a heading of that file (GitHub's anchor rule). A `docs/NAME.md` or
   `docs/NAME.md#anchor` named in a text file under contrib/ or .github/ is checked the same way.
   README.public.md, where it exists, is read as the README.md that other pages link to.
2. Options: every option of the server (the table cli::OPTIONS in server/src/cli.rs) starts a table row in
   docs/configuration.md. Every `--option` that the README or a docs page names in code style is an option of the
   server, or of another tool on the list OTHER_TOOLS. --pending names options that the docs describe before the code
   has them (a branch that is not merged yet).
3. --lost REV: every heading anchor of the README and docs pages of commit REV (LOST_FILES) still exists in the same
   file, and every sentence of those pages is still in a page, or on the list of rewritten sentences (--rewritten FILE: one sentence per line, as this script prints them; `#` lines are
   comments). --lost-diff BASE..BRANCH adds the docs lines that BRANCH added since BASE.
4. --map REV prints a table: every heading of those pages of REV and where it is now (exit status 1 if one is gone).
"""
import argparse, os, re, subprocess, sys

PAGES = ["README.public.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md"]  # plus docs/*.md
MENTION_DIRS = ["contrib", ".github"]  # text files that name docs pages in comments
LOST_FILES = ["README.public.md", "docs/configuration.md", "docs/deployment.md"]
OPTION_PAGES_SKIP = ("docs/benchmarking.md", "docs/benchmarks.md", "CHANGELOG.md")  # options of the bench tools; history
OTHER_TOOLS = {  # options of other programs that the pages show
    "--ulimit", "--memory", "--stop-timeout", "--add-host", "--rm", "--name", "--scope", "--system", "--now",
    "--strip-components",
}


def root():
    """the repository root: this file is bench/tools/doccheck.py (no git needed, so it also runs in an unpacked archive)"""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def rendered(text):
    """(line number, line) of the lines that Markdown renders as text: not inside a ``` or ~~~ fence, not in a comment"""
    text = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    fence = None
    for n, line in enumerate(text.split("\n"), 1):
        m = re.match(r"^\s*(`{3,}|~{3,})", line)
        if m and fence is None:
            fence = m.group(1)
        elif m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line.strip().strip("`~"):
            fence = None
        elif fence is None:
            yield n, line


def strip_code(line):
    """the line without inline code spans (links inside code are examples, not links)"""
    return re.sub(r"`[^`]*`", "", line)


def slug(title, seen):
    """GitHub's heading anchor: lower case, drop everything but letters, digits, '-', '_' and spaces, spaces to '-'"""
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", title.strip())  # a link in a heading counts by its text
    t = re.sub(r"[^\w\- ]", "", t.replace("`", "").lower()).replace(" ", "-")
    n = seen.get(t, 0)
    seen[t] = n + 1
    return t if n == 0 else f"{t}-{n}"


def anchors(text):
    out, seen = set(), {}
    for _, line in rendered(text):
        m = re.match(r"^#{1,6} +(.*?)\s*$", line)
        if m:
            out.add(slug(m.group(1), seen))
        out.update(re.findall(r'<a id="([\w-]+)"></a>', line))  # the old name of a renamed section
    return out


def links(text):
    """(line number, target) of every Markdown link outside code: [text](target), [text](target "title"), [ref]: target"""
    for n, line in rendered(text):
        plain = strip_code(line)
        for m in re.finditer(r"\]\(\s*<?([^)\s>]+)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)", plain):
            yield n, m.group(1)
        m = re.match(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)", plain)
        if m:
            yield n, m.group(1)


def check_links(top, files, problems):
    cache = {}

    def page(path):  # the text of a repository path as the public tree has it
        real = "README.public.md" if path == "README.md" and os.path.exists(os.path.join(top, "README.public.md")) else path
        if real not in cache:
            full = os.path.join(top, real)
            cache[real] = open(full, encoding="utf-8").read() if os.path.isfile(full) else None
        return cache[real]

    def resolve(src, n, target):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # http:, https:, mailto:
            return
        path, _, frag = target.partition("#")
        here = "README.md" if src == "README.public.md" else src
        dest = os.path.normpath(os.path.join(os.path.dirname(here), path)) if path else here
        if dest.startswith(".."):
            problems.append(f"{src}:{n}: link leaves the repository: {target}")
            return
        if os.path.isdir(os.path.join(top, dest)):
            if frag:
                problems.append(f"{src}:{n}: anchor on a directory: {target}")
            return
        text = page(dest)
        if text is None:
            problems.append(f"{src}:{n}: no such file: {target}")
        elif frag and frag not in anchors(text):
            problems.append(f"{src}:{n}: no heading for the anchor: {target}")

    count = 0
    for f in files:
        for n, target in links(page(f)):
            count += 1
            resolve(f, n, target)
    for d in MENTION_DIRS:
        for base, _, names in os.walk(os.path.join(top, d)):
            for name in names:
                rel = os.path.relpath(os.path.join(base, name), top)
                try:
                    text = open(os.path.join(top, rel), encoding="utf-8").read()
                except UnicodeDecodeError:
                    continue
                for n, line in enumerate(text.split("\n"), 1):
                    for m in re.finditer(r"(?<![\w/.-])(docs/[\w.-]+\.md(?:#[\w-]+)?)", line):
                        count += 1
                        resolve("README.md", n, m.group(1))
                        if problems and problems[-1].startswith(f"README.md:{n}:"):
                            problems[-1] = f"{rel}:{n}:" + problems[-1].split(":", 2)[2]
    return count


def server_options(top):
    """(the options that the parser and a config file take, every option): the rows of cli::OPTIONS in
    server/src/cli.rs, one `o("--name", ...)` per line; a row that ends with `.early()` is handled before the parser"""
    src = open(os.path.join(top, "server/src/cli.rs"), encoding="utf-8").read()
    block = src[src.index("pub const OPTIONS"):]
    block = block[:block.index("\n];")]
    rows = [(m.group(1), line.rstrip().endswith(".early(),")) for line in block.split("\n")
            for m in [re.match(r'\s*o\("(--[a-z0-9-]+)", ', line)] if m]
    if not rows:
        sys.exit("doccheck: no option row found in cli::OPTIONS (server/src/cli.rs): the table's form changed")
    return [name for name, early in rows if not early], {name for name, _ in rows}


def check_options(top, files, pending, problems):
    flags, known = server_options(top)
    ref = open(os.path.join(top, "docs/configuration.md"), encoding="utf-8").read()
    rows = set()
    for _, line in rendered(ref):
        if line.startswith("|"):
            first = line.split("|")[1] if line.count("|") > 1 else ""
            rows |= set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", first))
    for o in sorted(known):
        if o not in rows:
            problems.append(f"docs/configuration.md: no table row starts with the option {o}")
    for o in sorted(pending):
        if o in known:
            problems.append(f"--pending {o}: the server has this option now, drop it from --pending")
        elif o not in rows:
            problems.append(f"docs/configuration.md: no table row starts with the pending option {o}")
    ok = known | set(pending) | OTHER_TOOLS
    for f in files:
        if f in OPTION_PAGES_SKIP:
            continue
        text = open(os.path.join(top, f), encoding="utf-8").read()
        fence = False
        for n, line in enumerate(text.split("\n"), 1):
            if line.lstrip().startswith("```"):
                fence = not fence
                continue
            spans = [line] if fence and "finalwisp" in line else ([] if fence else re.findall(r"`([^`]*)`", line))
            for s in spans:
                for o in re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", s):
                    if o not in ok:
                        problems.append(f"{f}:{n}: {o} is not an option of the server")
    return len(flags), len(known)


def norm(text):
    text = re.sub(r"\]\([^)\s]*\)", "]", text)  # a link counts by its text: its target may move
    text = text.replace("\\|", "\x00").replace("|", " ").replace("\x00", "\\|")
    text = re.sub(r"(?m)^\s*(?:[-*]|\d+\.)\s+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def units(text):
    """the sentences, code lines, table cells and headings of a page, normalized"""
    out, para, fence = [], [], False

    def flush():
        if para:
            joined = norm("\n".join(para))
            out.extend(s for s in re.split(r"(?<=[.?!:;])\s+(?=[A-Z`\[*(\"'0-9])", joined) if s)
            para.clear()

    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            flush()
            fence = not fence
            continue
        if fence:
            if line.strip():
                out.append(norm(line))
        elif not line.strip():
            flush()
        elif re.match(r"^#{1,6} ", line):
            flush()
            out.append(norm(line.lstrip("# ")))
        elif re.fullmatch(r"\*\*[^*]+\.\*\*", line.strip()):  # a bold line is a small heading: it counts as one
            flush()
            out.append(norm(line.strip()[2:-3]))
        elif line.startswith("|"):
            flush()
            for cell in re.split(r"(?<!\\)\|", line)[1:-1]:
                m = re.fullmatch(r"\s*`(--[a-z0-9-]+) ([^`]+)`\s*", cell)
                if m:  # an option cell `--opt VALUE` counts as the option and its value (they may be two columns)
                    out.extend([f"`{m.group(1)}`", norm(f"`{m.group(2)}`")])
                elif cell.strip() and not re.fullmatch(r"\s*:?-+:?\s*", cell):
                    para.append(cell)
                    flush()
        else:
            if re.match(r"^\s*(?:[-*]|\d+\.)\s+", line):
                flush()
            para.append(line)
    flush()
    return [u for u in out if len(u) > 3]


def check_lost(top, files, rev, diffs, rewritten, problems):
    corpus = " \n ".join(norm(open(os.path.join(top, f), encoding="utf-8").read()) for f in files)
    allowed = set()
    if rewritten:
        for line in open(rewritten, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                allowed.add(norm(line))
    old = []  # (where, unit)
    if rev:
        for f in LOST_FILES:
            r = subprocess.run(["git", "-C", top, "show", f"{rev}:{f}"], capture_output=True, text=True)
            if r.returncode == 0:
                old.extend((f"{rev}:{f}", u) for u in units(r.stdout))
                now = anchors(open(os.path.join(top, f), encoding="utf-8").read())
                for a in sorted(anchors(r.stdout) - now):  # an old deep link must still land in the same file
                    problems.append(f"{f}: the anchor #{a} of {rev} is gone")
    for d in diffs:
        r = subprocess.run(["git", "-C", top, "diff", "-U0", d, "--", "README.public.md", "docs/configuration.md",
                            "docs/deployment.md"], capture_output=True, text=True, check=True)
        added = "\n".join(ln[1:] for ln in r.stdout.split("\n") if ln.startswith("+") and not ln.startswith("+++"))
        old.extend((d, u) for u in units(added))
    used, lost = set(), 0
    for where, u in old:
        if u in corpus:
            continue
        if u in allowed:
            used.add(u)
            continue
        lost += 1
        problems.append(f"lost ({where}): {u}")
    for u in sorted(allowed - used):
        problems.append(f"rewritten list: this sentence is in the pages again, or was never in the old ones: {u}")
    return len(old), lost


def heading_map(top, rev):
    """one table row per heading of the pages of REV: where that heading is now"""
    rows = []
    for f in LOST_FILES:
        r = subprocess.run(["git", "-C", top, "show", f"{rev}:{f}"], capture_output=True, text=True)
        if r.returncode != 0:
            continue
        now = list(rendered(open(os.path.join(top, f), encoding="utf-8").read()))
        heads, seen = {}, {}  # anchor -> index into `now`
        for i, (_, line) in enumerate(now):
            m = re.match(r"^#{1,6} +(.*?)\s*$", line)
            if m:
                heads[slug(m.group(1), seen)] = i
            for a in re.findall(r'<a id="([\w-]+)"></a>', line):
                heads[a] = i
        seen_old = {}
        for _, line in rendered(r.stdout):
            m = re.match(r"^(#{1,6}) +(.*?)\s*$", line)
            if not m:
                continue
            a = slug(m.group(2), seen_old)
            where = "GONE"
            if a in heads:
                i = heads[a]
                if now[i][1].startswith("<a id="):  # the old name stands above the renamed heading
                    j = next(k for k in range(i, len(now)) if now[k][1].startswith("#"))
                    where = f"{f}#{slug(now[j][1].lstrip('# '), {})} (renamed; the old anchor still works)"
                else:
                    body = next((ln for _, ln in now[i + 1:] if ln.strip()), "")
                    mv = re.match(r"^Moved to \[[^\]]*\]\(([^)]+)\)", body)
                    where = os.path.normpath(os.path.join(os.path.dirname(f), mv.group(1))) if mv else f"{f}#{a}"
            rows.append(f"| {f} | {'#' * len(m.group(1))} {m.group(2)} | {where} |")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--map", metavar="REV", help="print where every heading of the pages of REV is now, and exit")
    ap.add_argument("--pending", default="", help="options that the docs describe and the code does not have yet")
    ap.add_argument("--lost", metavar="REV", help="check that the text of the pages of REV is still there")
    ap.add_argument("--lost-diff", metavar="BASE..BRANCH", action="append", default=[])
    ap.add_argument("--rewritten", metavar="FILE", help="sentences that were rewritten on purpose")
    a = ap.parse_args()
    top = root()
    if a.map:
        rows = heading_map(top, a.map)
        print("| old page | old heading | where it is now |\n|---|---|---|\n" + "\n".join(rows))
        sys.exit(1 if any(r.endswith("| GONE |") for r in rows) else 0)
    files = [p for p in PAGES if os.path.isfile(os.path.join(top, p))]
    if "README.public.md" not in files:  # the public tree: the README is README.md
        files.insert(0, "README.md")
    files += sorted("docs/" + n for n in os.listdir(os.path.join(top, "docs")) if n.endswith(".md"))
    for d in MENTION_DIRS:
        for base, _, names in os.walk(os.path.join(top, d)):
            files += sorted(os.path.relpath(os.path.join(base, n), top) for n in names if n.endswith(".md"))
    problems = []
    n_links = check_links(top, files, problems)
    pending = [o for o in a.pending.split(",") if o]
    n_flags, n_known = check_options(top, files, pending, problems)
    print(f"doccheck: {len(files)} pages, {n_links} relative links and page names, {n_flags} options in FLAGS"
          f" ({n_known} with the ones handled before the parser), {len(pending)} pending")
    if a.lost or a.lost_diff:
        n_old, n_lost = check_lost(top, files, a.lost, a.lost_diff, a.rewritten, problems)
        print(f"doccheck: {n_old} old sentences, code lines and table cells; {n_lost} not found")
    for p in problems:
        print("  " + p)
    if problems:
        sys.exit(f"doccheck: {len(problems)} problem(s)")
    print("doccheck: OK")


if __name__ == "__main__":
    main()
