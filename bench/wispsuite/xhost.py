"""Cross-host mode (30.10): the server and the wbench targets run on THIS box, bound to the address that faces the
client host; `wbench run` runs on the client host over ssh. Used by `wst ab --client-ssh` and `wst regress --client-ssh`.

Safety: while a cross-host run lasts, iptables INPUT rules (comment "wst-xhost") at the top accept the server and
target ports only from the client host and from this box itself (lo: the server connects to the target on its
own address), and drop them from everyone else, so the server is never an open proxy. The rules are removed in a
finally block (also on SIGTERM / SIGINT / SIGHUP, which the suite turns into a normal exit); a leftover rule from a
killed run (SIGKILL) stops the next run unless --force-clean.
The client's wbench must exist at the same path as the local one (md5 compared). A remote `wbench run` is wrapped
in `timeout` and runs under ssh -tt, so it ends when the local side kills ssh (pty hangup) or at the latest when the
timeout fires.
"""
import contextlib, fcntl, os, re, shlex, shutil, signal, socket, subprocess, sys
from . import proc

COMMENT = "wst-xhost"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]
LOCK = os.environ.get("WST_XHOST_LOCK", "/run/wst-xhost.lock")  # one cross-host run per box: the rules of two runs would share the comment
cleanup_errors = []  # firewall teardown problems (reported by the caller; teardown itself never raises)


class XhostError(Exception):
    pass


def host_label(ssh_target):
    return ssh_target.rsplit("@", 1)[-1]


def ssh_cmd(ssh_target, remote, tty=False):
    """argv that runs the shell command string `remote` on ssh_target."""
    return SSH + (["-tt"] if tty else []) + [ssh_target, remote]


def remote_run(ssh_target, remote, timeout=30):
    """(rc, stdout) of a short remote command; rc None on timeout / ssh missing."""
    try:
        r = subprocess.run(ssh_cmd(ssh_target, remote), capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def client_ip(ssh_target):
    """IPv4 address of the client host as ssh resolves it (ssh -G honours ~/.ssh/config aliases)."""
    try:
        out = subprocess.run(["ssh", "-G", ssh_target], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        raise XhostError(f"ssh -G {ssh_target}: {e}")
    name = next((l.split(None, 1)[1].strip() for l in out.splitlines() if l.startswith("hostname ")), host_label(ssh_target))
    try:
        return socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError as e:
        raise XhostError(f"cannot resolve the client host {name} to IPv4: {e}")


def local_ip_towards(ip):
    """This box's source address for traffic to ip (the address the client reaches us on)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 9))  # UDP connect sends nothing; it only picks the route
        return s.getsockname()[0]
    finally:
        s.close()


def remote_md5(ssh_target, path):
    rc, out = remote_run(ssh_target, f"md5sum {shlex.quote(path)}")
    return out.split()[0] if rc == 0 and out.split() else None


def remote_strays(ssh_target):
    """`wbench run` processes already running on the client host (a leftover would share its CPU)."""
    rc, out = remote_run(ssh_target, "pgrep -af 'wbench run' || true")
    return [l for l in out.splitlines() if l.strip() and "pgrep" not in l]


def remote_tcp_pressure(ssh_target):
    """TcpExt TCPMemoryPressures on the client host; None if unreadable."""
    rc, out = remote_run(ssh_target, "cat /proc/net/netstat")
    try:
        lines = [l.split() for l in out.splitlines() if l.startswith("TcpExt:")]
        return int(dict(zip(lines[0][1:], lines[1][1:]))["TCPMemoryPressures"])
    except (IndexError, KeyError, ValueError):
        return None


def wbench_cmd(ssh_target, wb, args, timeout):
    """Local argv that runs `wbench run ARGS --json` on the client host, bounded by `timeout` there."""
    # --foreground: timeout stays in the pty's foreground group, so the hangup when the local ssh dies reaches it
    # (and wbench); without it GNU timeout moves to its own group and wbench runs on until the timeout
    remote = " ".join(shlex.quote(str(x)) for x in ["timeout", "--foreground", "-k", "5", str(int(timeout)), wb, "run", *args, "--json"])
    return ssh_cmd(ssh_target, remote, tty=True)


# ---------------------------------------------------------------- firewall
def _iptables():
    ipt = shutil.which("iptables")
    if not ipt:
        raise XhostError("iptables not found: cross-host mode needs it (the server must not be reachable from anyone but the client)")
    return ipt


def _ipt(*args):
    r = subprocess.run([_iptables(), "-w", "10", *args], capture_output=True, text=True)  # -w: wait for the xtables lock
    if r.returncode:
        raise XhostError(f"iptables {' '.join(args)}: {(r.stderr or r.stdout).strip()[:200]} (cross-host mode needs root)")
    return r.stdout


def leftover_rules():
    return [l for l in _ipt("-S", "INPUT").splitlines() if re.search(rf'--comment "?{COMMENT}"?( |$)', l)]


def remove_rules():
    """Delete every INPUT rule with our comment; returns how many."""
    n = 0
    for _ in range(100):
        rules = leftover_rules()
        if not rules:
            return n
        spec = shlex.split(rules[0])
        if spec[:2] != ["-A", "INPUT"]:
            raise XhostError(f"unexpected rule format: {rules[0]}")
        _ipt("-D", "INPUT", *spec[2:])
        n += 1
    raise XhostError("could not remove the wst-xhost rules")


def _rule_ports(rule):
    m = re.search(r"--dports (\S+)", rule)
    return [int(x) for x in m.group(1).split(",")] if m else []


@contextlib.contextmanager
def firewall(ports, allow_ip, force_clean=False):
    """INPUT rules for the run: ACCEPT tcp dports from allow_ip and from lo, DROP from everyone else. Holds a
    host-wide lock for the whole run. Teardown stops every process this run started before the rules go, never
    removes the rules while something still listens on a protected port, and never raises (errors go to
    cleanup_errors)."""
    _iptables()
    try:
        lockf = open(LOCK, "w")
    except OSError as e:
        raise XhostError(f"cannot open {LOCK}: {e} (cross-host mode needs root)")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lockf.close()
        raise XhostError(f"another cross-host run holds {LOCK}")
    try:
        left = leftover_rules()
        if left:
            if not force_clean:
                raise XhostError(f"{len(left)} leftover iptables rule(s) with comment {COMMENT} (a killed run?): "
                                 "stop any server left on those ports, then use --force-clean")
            busy = sorted({q for rule in left for q in _rule_ports(rule) if proc.listening(q)})
            if busy:  # a SIGKILLed run's server: removing the rules would make it an open proxy
                raise XhostError(f"--force-clean refused: ports {busy} protected by the leftover rules still have a listener "
                                 f"(pid {proc.listener_pid(busy[0])}); stop it first")
            remove_rules()
        dports = ",".join(str(p) for p in ports)
        base = ["-p", "tcp", "-m", "multiport", "--dports", dports, "-m", "comment", "--comment", COMMENT]
        try:
            # inserted at position 1 in reverse order: final order = accept client, accept lo, drop
            _ipt("-I", "INPUT", "1", *base, "-j", "DROP")
            _ipt("-I", "INPUT", "1", "-i", "lo", *base, "-j", "ACCEPT")
            _ipt("-I", "INPUT", "1", "-s", f"{allow_ip}/32", *base, "-j", "ACCEPT")
            yield
        finally:
            pending = None
            try:  # a signal here would skip the teardown: block them first, remember one that got in
                old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
            except BaseException as e:
                pending, old = e, signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
            try:
                proc.stop_all(0)  # nothing we started may outlive the rules
                busy = [q for q in ports if proc.listening(q)]
                if busy:
                    cleanup_errors.append(f"ports {busy} still have a listener (pid {proc.listener_pid(busy[0])}): "
                                          f"iptables rules {COMMENT} KEPT; stop it, then --force-clean")
                else:
                    remove_rules()
            except Exception as e:
                cleanup_errors.append(f"removing the {COMMENT} iptables rules failed: {e}")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old)
            for msg in cleanup_errors:
                print(f"xhost: {msg}", file=sys.stderr, flush=True)
            if pending is not None:
                raise pending
    finally:
        lockf.close()


class Xhost:
    """Everything a cross-host run needs, checked up front (raises XhostError)."""

    def __init__(self, ssh_target, wb, server_ip=None):
        self.ssh, self.label = ssh_target, "xhost:" + host_label(ssh_target)
        self.client_ip = client_ip(ssh_target)
        self.server_ip = server_ip or local_ip_towards(self.client_ip)
        rc, _ = remote_run(ssh_target, "true")
        if rc != 0:
            raise XhostError(f"ssh -o BatchMode=yes {ssh_target} true failed (rc {rc}): set up key login first")
        self.local_md5 = subprocess.run(["md5sum", wb], capture_output=True, text=True).stdout.split()[0]
        self.remote_md5 = remote_md5(ssh_target, wb)
        if self.remote_md5 is None:
            raise XhostError(f"wbench not found on {ssh_target} at {wb} (copy it there, same path)")
        strays = remote_strays(ssh_target)
        if strays:
            raise XhostError(f"wbench run already running on {ssh_target}: {strays[0][:120]}")

    def md5_problem(self):
        if self.local_md5 != self.remote_md5:
            return f"wbench on {self.ssh} differs from the local one (md5 {self.remote_md5} vs {self.local_md5})"
        return None

    def describe(self):
        return f"{self.label} (server {self.server_ip}, client {self.client_ip} via ssh {self.ssh})"
