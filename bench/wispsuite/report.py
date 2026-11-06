"""Result files (30.10): one JSON shape for every command, {"schema": "wispsuite/1", "kind", "meta", ...}.
meta = when/where/what: time, host, kernel, cpu, nproc, load, git rev of the repo, argv, md5 of the binaries."""
import datetime as dt, hashlib, json, os, platform, subprocess, sys

SCHEMA = "wispsuite/1"
BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def md5(path):
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def cpu_model():
    try:
        return next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    except OSError:
        return "?"


def git_rev():
    return git_rev_of(BENCH)


def git_rev_of(path):
    try:
        r = subprocess.run(["git", "-C", path, "describe", "--always", "--dirty", "--tags"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def power_state():
    """Host power state (laptops change speed with it): power-profiles-daemon profile, cpufreq policy0 EPP and
    governor, AC online (any power_supply of type Mains; None if the host has none), battery status. None = unknown."""
    profile = None
    try:
        r = subprocess.run(["powerprofilesctl", "get"], capture_output=True, text=True, timeout=3)
        profile = r.stdout.strip() or None if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        pass
    ac, battery = None, None
    base = "/sys/class/power_supply"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        names = []
    for n in names:
        kind = _read(f"{base}/{n}/type")
        if kind == "Mains":
            on = _read(f"{base}/{n}/online")
            if on is not None:
                ac = (ac or False) or on == "1"
        elif kind == "Battery" and battery is None:
            battery = _read(f"{base}/{n}/status")
    cf = "/sys/devices/system/cpu/cpufreq/policy0"
    return {"profile": profile, "epp": _read(f"{cf}/energy_performance_preference"), "governor": _read(f"{cf}/scaling_governor"),
            "ac_online": ac, "battery": battery}


POWER_KEYS = ("profile", "epp", "governor", "ac_online")  # what changes speed (battery Charging -> Full does not)
POWER_START = power_state()  # sampled when the suite starts (every command imports this module first)


def power_changed(a, b):
    """Keys whose value differs between two power_state() samples."""
    return [k for k in POWER_KEYS if a.get(k) != b.get(k)]


def power_fmt(s):
    return ", ".join(f"{k} {s.get(k)}" for k in ("profile", "epp", "governor", "ac_online", "battery"))


def meta(binaries=()):
    end = power_state()
    return {"time": dt.datetime.now().isoformat(timespec="seconds"), "host": platform.node(), "kernel": platform.release(),
            "cpu": cpu_model(), "nproc": os.cpu_count(), "load1": round(os.getloadavg()[0], 2), "git": git_rev(),
            "argv": sys.argv, "binaries": {os.path.abspath(b): md5(b) for b in binaries if b},
            "power": {"start": POWER_START, "end": end, "changed": power_changed(POWER_START, end)}}


def write(path, kind, binaries=(), **body):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"schema": SCHEMA, "kind": kind, "meta": meta(binaries), **body}, f, indent=1)
    return path


def stamp():
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join("" if c is None else str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)
