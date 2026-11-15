#!/usr/bin/env python3
"""60.73 tables from the raw files of fu-abuse (an internal note (not published), not in the repository).
usage: bench/fu-abuse-tables.py RAW [--check NOTE]
RAW/wnd/rcvB-rateR.txt: the output of RAW/wnd/wnd.py B R 1448 90 (B = SO_RCVBUF of the client, 0 = the kernel's
default; R = bytes per second the client reads from 2 s on). Each line after the first: a change of the server
socket's tcpi_bytes_acked ("T taken=N acked=N step=N").
--check NOTE: every table line printed here must be a line of NOTE (exit 1 and the missing lines otherwise)."""
import glob, os, re, sys

START = 2.0  # the client reads from 2 s on (wnd.py)
RUN = 90.0  # every run: 90 s


def wnd_rows(raw):
    rows = []
    for f in sorted(glob.glob(os.path.join(raw, "wnd", "rcv*-rate*.txt"))):
        m = re.match(r"rcv(\d+)-rate(\d+)\.txt$", os.path.basename(f))
        if not m:
            continue
        set_, rate = int(m.group(1)), int(m.group(2))
        text = open(f).read().splitlines()
        buf = next((int(l.split()[1]) for l in text if l.startswith("rcvbuf ")), None)
        ev = [(float(a), int(b)) for a, b in re.findall(r"^\s*([\d.]+) taken=\d+ acked=(\d+)", "\n".join(text), re.M)]
        after = [t for t, _ in ev if t >= START]
        times = [START] + after
        gaps = [b - a for a, b in zip(times, times[1:])]
        tail = RUN - times[-1]  # (no change from the last one to the end of the run: a lower bound of that gap)
        longest = f"{max(gaps):.1f}" if gaps and max(gaps) >= tail else f">= {tail:.1f}"
        last = ev[-1][0] if ev else 0.0
        rows.append(
            f"| {'default' if set_ == 0 else set_} | {buf} | {rate} | {len(after)} | {longest} | "
            f"{after[0] - START if after else float('nan'):.1f} | {last:.1f} |"
        )
    return rows


BIG_RUN = 600.0  # wnd2.py runs: 600 s


def big_rows(raw):
    """RAW/wnd-big/rcvB-rateR-fastF.txt: wnd2.py B R 1448 600 F (v1.3.2 review: large buffers; F s of reading at full
    speed first). The gap counts from F + 2 s (the buffer full) to the end of the run."""
    rows = []
    for f in sorted(glob.glob(os.path.join(raw, "wnd-big", "rcv*-rate*-fast*.txt"))):
        m = re.match(r"rcv(\d+)-rate(\d+)-fast(\d+)\.txt$", os.path.basename(f))
        if not m:
            continue
        set_, rate, fast = (int(x) for x in m.groups())
        text = open(f).read()
        ev = [float(t) for t in re.findall(r"^\s*([\d.]+) taken=\d+ acked=\d+", text, re.M)]
        end = float(re.search(r"^end ([\d.]+)", text, re.M).group(1))
        times = [fast + 2.0] + [t for t in ev if t >= fast + 2.0]
        gaps = [b - a for a, b in zip(times, times[1:])]
        tail = end - times[-1]
        longest = f"{max(gaps):.1f}" if gaps and max(gaps) >= tail else f">= {tail:.1f}"
        bufs = re.findall(r"rcvbuf=(\d+)", text)
        wnd = [int(x) for x in re.findall(r" wnd=(\d+) rcvbuf", text)]
        rows.append(
            f"| {'autotuned' if set_ == 0 else set_} | {bufs[-1] if bufs else ''} | {fast} | {rate} | {max(wnd) if wnd else ''} | "
            f"{len(times) - 1} | {longest} |"
        )
    return rows


def main():
    raw = sys.argv[1]
    out = ["| SO_RCVBUF set | SO_RCVBUF the kernel reports | bytes read per s | acked changes after 2 s | longest time without a change, s (>=: until the end of the 90-s run) | first change after the reads began, s | last change at, s |",
           "|---|---|---|---|---|---|---|"]
    out += wnd_rows(raw)
    if os.path.isdir(os.path.join(raw, "wnd-big")):
        out += ["", "| SO_RCVBUF set | SO_RCVBUF the kernel reports at the end | s read at full speed first | bytes read per s after it | largest window seen, bytes | acked changes | longest time without a change, s (>=: until the end of the 600-s run) |",
                "|---|---|---|---|---|---|---|"]
        out += big_rows(raw)
    print("\n".join(out))
    if "--check" in sys.argv:
        note = open(sys.argv[sys.argv.index("--check") + 1]).read().splitlines()
        miss = [l for l in out if l and l not in note]
        for l in miss:
            print("MISSING " + l, file=sys.stderr)
        sys.exit(1 if miss else 0)


main()
