#!/usr/bin/env python3
"""Per-function normalized disassembly compare of two binaries: evidence that a refactor left the code unchanged.

Usage: bench/tools/disasm_norm.py A B [--fold PREFIX ...] [--show N]
  A, B      two builds of the same toolchain and flags (e.g. bench/release.sh of the old and the new commit)
  --fold    module prefix whose direct submodules are folded into it, for moves between modules:
            `--fold finalwisp::worker` maps finalwisp::worker::<sub>::X to finalwisp::worker::X (repeatable)
  --show N  print a unified diff of the first N differing functions (default 0)
Exit: 0 every function body identical after normalization, 1 something differs, 2 usage or objdump error.

Normalization (objdump -d -z --no-show-raw-insn -C, split per symbol):
- addresses and rip-relative displacements are dropped; for rip-relative references into data sections (not CODE
  sections: those keep name and offset like call / jump targets) also the +offset and
  local data names (anon.*, .L*, str.*, alloc_*, GCC_except*: -> <data>), because string and panic-location data
  move when line numbers or file names change. Call / jump targets keep their full name and offset;
- trailing padding (nop forms, int3) is dropped; functions with the same name are compared as a sorted list;
- --fold collisions (two different original names folding to one) are reported and fail the compare.
What it does not prove: raw instruction bytes are not compared (two encodings with the same disassembly match),
and data sections (.rodata, .data.rel.ro) differ by design when lines move; compare those separately if they matter. Its first use: the 60.16 #10 worker.rs split (3276 functions identical to base-4-rc1,
default and NOFEAT builds; a sanity run default vs NOFEAT reports 573 differing functions); later the 60.18 #11 removal
of the NOFEAT path (default build identical to base-4).
"""
import argparse
import os
import collections
import difflib
import re
import subprocess
import sys

PAD = re.compile(r'^(int3|((data16|cs) )*(nop[wl]?( .*)?|xchg %ax,%ax))$')
LOCAL = re.compile(r'(anon\.|\.L|GCC_except|_GLOBAL|str\.|alloc_)')


def make_fold(prefixes):
    pats = [re.compile(re.escape(p) + r'::[a-z_][a-z0-9_]*::') for p in prefixes]

    def fold(name):
        for p, pat in zip(prefixes, pats):
            name = pat.sub(p + '::', name)
        return name

    return fold


def code_ranges(path):
    """[(start, end)] of the executable sections (objdump -h flag CODE)"""
    out = subprocess.run(['objdump', '-h', '-w', '--', path], capture_output=True, text=True, check=True).stdout
    rs = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 7 and f[0].isdigit() and 'CODE' in line:
            rs.append((int(f[3], 16), int(f[3], 16) + int(f[2], 16)))
    return rs


def funcs(path, fold):
    path = os.path.abspath(path)  # (a leading "@" would be a GNU response file even after "--")
    try:
        code = code_ranges(path)
        out = subprocess.run(['objdump', '-d', '-z', '--no-show-raw-insn', '-C', '--', path], capture_output=True, text=True,
                             check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        print(f'disasm_norm: objdump failed on {path}: {e}', file=sys.stderr)
        sys.exit(2)
    fs = collections.defaultdict(list)
    origin = collections.defaultdict(set)  # folded name -> original names (collision check)
    cur, body = None, []

    def done():
        while body and PAD.match(body[-1]):
            body.pop()
        if cur is not None:
            fs[cur].append('\n'.join(body))

    def sym(m):
        s = fold(m.group(3))
        addr = int(m.group(2), 16)
        if not m.group(1) or any(lo <= addr < hi for lo, hi in code):  # call / jump target, or a rip reference into
            return ('# ' if m.group(1) else '') + '<' + s + '>'  # code (lea of a handler): keep name and offset
        s = re.sub(r'\+0x[0-9a-f]+$', '', s)  # "# addr <sym+off>": rip-relative data, its offset moves with data sizes
        return '# ' + ('<data>' if LOCAL.match(s) else '<' + s + '>')

    for line in out.splitlines():
        m = re.match(r'^[0-9a-f]+ <(.*)>:$', line)
        if m:
            done()
            cur, body = fold(m.group(1)), []
            origin[cur].add(m.group(1))
            continue
        m = re.match(r'^\s+[0-9a-f]+:\t(.*)$', line)
        if m and cur is not None:
            ins = re.sub(r'-?0x[0-9a-f]+\(%rip\)', 'X(%rip)', m.group(1))
            ins = re.sub(r'(#\s*)?\b([0-9a-f]+) <(.*)>$', sym, ins)  # the annotation ends the line (nested <>)
            ins = re.sub(r'#\s*[0-9a-f]+$', '#', ins)
            body.append(re.sub(r'\s+', ' ', ins).strip())
    done()
    if not fs:
        print(f'disasm_norm: no functions disassembled in {path}', file=sys.stderr)
        sys.exit(2)
    return {k: sorted(v) for k, v in fs.items()}, {k: v for k, v in origin.items() if len(v) > 1}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('a')
    ap.add_argument('b')
    ap.add_argument('--fold', action='append', default=[])
    ap.add_argument('--show', type=int, default=0)
    o = ap.parse_args()
    fold = make_fold(o.fold)
    (a, ca), (b, cb) = funcs(o.a, fold), funcs(o.b, fold)
    # names that only --fold made equal (two different items) would hide a changed call between them: fail
    coll = sorted(set(ca) | set(cb))
    only_a, only_b = sorted(set(a) - set(b)), sorted(set(b) - set(a))
    diff = [k for k in sorted(set(a) & set(b)) if a[k] != b[k]]
    ninsn = sum(len(x.splitlines()) for v in a.values() for x in v)
    print(f'functions A {len(a)} B {len(b)}; instructions A {ninsn}; only in A {len(only_a)}; only in B {len(only_b)}; '
          f'bodies differ {len(diff)}')
    for k in only_a[:20]:
        print('  only A:', k)
    for k in only_b[:20]:
        print('  only B:', k)
    for k in diff[:20]:
        print('  differs:', k)
    for k in coll[:20]:
        print('  fold collision:', k, sorted(ca.get(k, set()) | cb.get(k, set()))[:4])
    if coll:
        print(f'fold collisions {len(coll)}: --fold made different items equal; the compare is not valid')
    for k in diff[:o.show]:
        print(f'--- {k}')
        sys.stdout.writelines(l + '\n' for l in difflib.unified_diff(
            '\n=====\n'.join(a[k]).splitlines(), '\n=====\n'.join(b[k]).splitlines(), 'A', 'B', lineterm='', n=2))
    return 0 if not (only_a or only_b or diff or coll) else 1


if __name__ == '__main__':
    sys.exit(main())
