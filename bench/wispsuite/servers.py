"""Server registry (30.10): bench/servers.json names every Wisp server the suite knows, with paths relative to
the repo root, so one definition serves compat, matrix, showdown, wispmark and idle. A server can also be any
finalwisp build (`fw:PATH [args]`) or any command (`NAME=COMMAND` with {port}).

Templates in "cmd", "cwd" and file contents: {port} {root} {bench} {dir} (a per-run scratch dir) {fw} (the finalwisp
binary: $FINALWISP_BIN or server/target/release/finalwisp)."""
import json, os, shlex
from . import proc

BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(BENCH)
REGISTRY = os.path.join(BENCH, "servers.json")
SCRATCH = os.path.join(BENCH, "results", "stale", "wst-scratch")  # generated server configs (gitignored)


class Server:
    def __init__(self, name, cmd, cwd=None, env=None, extra=None, files=None, ready_timeout=20, note=""):
        self.name, self.cmd, self.cwd, self.env = name, cmd, cwd, env or {}
        self.extra = list(extra or [])  # wbench run args for this server (e.g. --stall-ping-ms 1)
        self.files = files or {}
        self.ready_timeout, self.note = ready_timeout, note

    def expand(self, s, port, scratch):
        fw = os.environ.get("FINALWISP_BIN", os.path.join(ROOT, "server/target/release/finalwisp"))
        return (s.replace("{port}", str(port)).replace("{root}", ROOT).replace("{bench}", BENCH)
                .replace("{dir}", scratch).replace("{fw}", fw))

    def command(self, port, scratch):
        """(shell command, cwd) for this port; writes the server's config files into `scratch` first."""
        os.makedirs(scratch, exist_ok=True)
        for fname, spec in self.files.items():
            path = os.path.join(scratch, self.expand(fname, port, scratch))
            if isinstance(spec, str):
                text = self.expand(spec, port, scratch)
            else:  # {"json_base": path, "set": {...}}: a JSON config from a base file with keys overridden
                base = json.load(open(self.expand(spec["json_base"], port, scratch)))
                for k, v in spec.get("set", {}).items():
                    base[k] = port if v == "{port}" else v
                text = json.dumps(base)
            with open(path, "w") as f:
                f.write(text)
        cmd = self.expand(self.cmd, port, scratch)
        first = cmd.split(None, 1)[0] if cmd.strip() else ""
        if not cmd.startswith("exec ") and "&&" not in cmd and ";" not in cmd and "=" not in first:
            cmd = "exec " + cmd  # the shell becomes the server: signals and CPU sampling hit the server itself
        return cmd, (self.expand(self.cwd, port, scratch) if self.cwd else None)

    def start(self, port, scratch, log=None, wait=True):
        """Start on `port`; returns the Popen (its own process group). Raises RuntimeError if it never listens."""
        cmd, cwd = self.command(port, scratch)
        p = proc.spawn(cmd, shell=True, cwd=cwd, env=self.env, log=log)
        if wait and not proc.wait_port(port, self.ready_timeout, p):
            proc.stop(p)
            raise RuntimeError(f"{self.name} did not accept on :{port}" + (f" (log {log})" if log else ""))
        return p


def load(path=REGISTRY):
    with open(path) as f:
        return json.load(f)["servers"]


def finalwisp(path, args="", name=None):
    """A finalwisp build with the bench defaults (loopback + private targets allowed)."""
    path = os.path.abspath(path)
    return Server(name or os.path.basename(path), f"exec {shlex.quote(path)} --port {{port}} --allow-loopback --allow-private {args}".rstrip())


def resolve(spec, registry=None):
    """'name' (registry), 'fw:PATH [args]' (a finalwisp build) or 'NAME=COMMAND' (any server; {port} in COMMAND)."""
    if isinstance(spec, dict):  # a full server entry (run_matrix configs)
        return Server(spec["name"], spec["cmd"], spec.get("cwd"), spec.get("env"), spec.get("extra"),
                      spec.get("files"), spec.get("ready_timeout", 20), spec.get("note", ""))
    if spec.startswith("fw:"):
        path, _, args = spec[3:].partition(" ")
        return finalwisp(path, args)
    reg = registry if registry is not None else load()
    if spec in reg:
        e = reg[spec]
        return Server(spec, e["cmd"], e.get("cwd"), e.get("env"), e.get("extra"), e.get("files"),
                      e.get("ready_timeout", 20), e.get("note", ""))
    if "=" in spec:
        name, cmd = spec.split("=", 1)
        if "{port}" not in cmd:
            raise SystemExit(f"server '{name}': the command needs a {{port}} placeholder")
        return Server(name, cmd)
    raise SystemExit(f"unknown server '{spec}'. known: {', '.join(reg)}; or fw:PATH, or NAME='cmd --port {{port}}'")
