"""Process control for the suite (30.10): every child runs in its own session (process group), is registered,
and is stopped as a whole group. SIGTERM/SIGINT/exit stop every registered group, so a stopped run leaves no strays.
"""
import atexit, os, re, signal, socket, subprocess, sys, threading, time

_live = []  # Popen objects, each the leader of its own session and process group
_SIGS = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}


def _child_unblock():
    """In the child before exec: the blocked mask is inherited across fork/exec; servers must get SIGTERM."""
    signal.pthread_sigmask(signal.SIG_UNBLOCK, _SIGS)


def spawn(cmd, *, shell=False, cwd=None, env=None, log=None, stdout=None, stderr=None):
    """Start cmd in a new session and register it. log: path (append) for stdout+stderr; default /dev/null."""
    out = open(log, "ab") if log else subprocess.DEVNULL
    text = stdout is not None or stderr is not None
    # no SIGTERM/SIGINT/SIGHUP between fork and registration: the handler must see every child we start
    old = signal.pthread_sigmask(signal.SIG_BLOCK, _SIGS)
    try:
        p = subprocess.Popen(cmd, shell=shell, cwd=cwd, env=dict(os.environ, **(env or {})),
                             stdout=stdout if stdout is not None else out,
                             stderr=stderr if stderr is not None else (subprocess.STDOUT if log else subprocess.DEVNULL),
                             stdin=subprocess.DEVNULL, start_new_session=True, text=text,
                             errors="replace" if text else None, preexec_fn=_child_unblock)
        _live.append(p)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
        if log:
            out.close()  # the child has its own copy
    return p


def group_pids(pgid):
    """Live (non-zombie) pids in process group pgid or in session pgid (our children lead both; a descendant
    that made its own group, e.g. GNU `timeout`, stays in the session)."""
    pids = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if (int(fields[2]) == pgid or int(fields[3]) == pgid) and fields[0] != "Z":
            pids.append(int(d))
    return pids


def _signal_session(leader, sig):
    """sig to the leader's process group and to every other process of its session; False if none is left."""
    hit = False
    try:
        os.killpg(leader, sig)
        hit = True
    except ProcessLookupError:
        pass
    for pid in group_pids(leader):
        try:
            os.kill(pid, sig)
            hit = True
        except ProcessLookupError:
            pass
    return hit


def stop(p, grace=3.0):
    """Stop p's whole process group: SIGTERM, wait up to `grace` s, then SIGKILL (grace=0: SIGKILL at once).
    Returns when the group is gone (or after 5 s of SIGKILL). p stays registered until then."""
    if p is None:
        return
    try:
        steps = ((signal.SIGTERM, grace), (signal.SIGKILL, 5.0)) if grace > 0 else ((signal.SIGKILL, 5.0),)
        for sig, wait in steps:
            if not _signal_session(p.pid, sig):
                break
            deadline = time.time() + wait
            while time.time() < deadline:
                if p.poll() is not None and not group_pids(p.pid):
                    return
                time.sleep(0.02)
    finally:
        try:
            p.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        if p in _live:
            _live.remove(p)


def stop_all(grace=1.0):
    for p in list(_live):
        stop(p, grace)


def run(cmd, *, timeout=None, shell=False, cwd=None, env=None):
    """Run cmd to completion in its own (registered) process group; returns (returncode, stdout, stderr).
    The run ends when cmd's own process exits (or at the timeout: returncode None); then the rest of its group and
    session is killed and the remaining output read. A child left behind that still holds the pipes (a test that
    died before stopping its server) no longer keeps the run open until the timeout (60.33 RC1 metrics step)."""
    p = spawn(cmd, shell=shell, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    got = {"out": [], "err": []}
    done = set()

    def drain(key, f):  # line by line, so what was read survives a bounded join that gives up
        for line in f:
            got[key].append(line)
        done.add(key)

    readers = [threading.Thread(target=drain, args=(k, f), daemon=True) for k, f in (("out", p.stdout), ("err", p.stderr))]
    # readers never take SIGTERM/SIGINT/SIGHUP (they inherit this mask): else one could take a signal during a later
    # spawn()'s fork-to-registration window and its handler would run before that child is registered (review)
    old = signal.pthread_sigmask(signal.SIG_BLOCK, _SIGS)
    try:
        for t in readers:
            t.start()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
    rc = None
    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    finally:
        stop(p, 0)  # the rest of the group and session: their pipe ends close, so the readers see EOF
        end = time.time() + 10  # deliberate: bounded; only a process that left the session (setsid) can still hold a pipe
        for t in readers:
            t.join(max(0.0, end - time.time()))
    lost = "" if done == {"out", "err"} else f"\n{INCOMPLETE} (a pipe is still held by a process outside the group)\n"
    return rc, "".join(got["out"]), "".join(got["err"]) + lost


INCOMPLETE = "proc.run: output incomplete"  # compat.step fails a step whose output has this line, whatever its judge


_installed = False


def install_handlers():
    """SIGTERM -> exit 143, SIGINT -> exit 130, SIGHUP -> exit 129; these and normal exit stop every registered group."""
    global _installed
    if _installed:
        return
    _installed = True

    def on_sig(signum, _frame):
        for s in _SIGS:
            signal.signal(s, signal.SIG_IGN)
        stop_all()
        sys.exit(128 + signum)
    for s in _SIGS:
        signal.signal(s, on_sig)
    atexit.register(stop_all)


# ---------------------------------------------------------------- ports
def listening(port):
    """True if any socket of this host's network namespace listens on TCP `port` (any user, v4 or v6)."""
    hexport = f"{port:04X}"
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn) as f:
                next(f)
                for line in f:
                    x = line.split()
                    if x[3] == "0A" and x[1].rsplit(":", 1)[1] == hexport:
                        return True
        except OSError:
            continue
    return False


def listener_pid(port):
    """pid of the (first) process that owns the listening socket on `port`, if this user can see it."""
    inodes = set()
    hexport = f"{port:04X}"
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn) as f:
                next(f)
                for line in f:
                    x = line.split()
                    if x[3] == "0A" and x[1].rsplit(":", 1)[1] == hexport:
                        inodes.add(f"socket:[{x[9]}]")
        except OSError:
            continue
    if not inodes:
        return None
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.readlink(f"/proc/{pid}/fd/{fd}") in inodes:
                    return int(pid)
        except OSError:
            continue
    return None


def strays(ports, listeners=True, cmdline=True):
    """Problems for ports that are already taken: a listener in this namespace (listeners), or a process whose
    command line has 'port N' (cmdline: catches a stray in another network namespace or one that has not bound
    yet). [] = all clear."""
    out = []
    for port in ports:
        if listeners and listening(port):
            out.append(f"port {port} already has a listener")
        elif cmdline:
            pat = re.compile(rf"port[ =]{port}( |$)")
            mine = _ancestors() | {q.pid for q in _live}  # our own command line (and our callers') may name the port
            for d in filter(str.isdigit, os.listdir("/proc")):
                if int(d) in mine:
                    continue
                try:
                    cl = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace").strip()
                except OSError:
                    continue
                if pat.search(cl):
                    out.append(f"stray process on port {port}: pid {d} {cl[:120]}")
                    break
    return out


def _ancestors():
    """This process and its parents (a shell or runner whose command line names the port is not a stray)."""
    out, pid = set(), os.getpid()
    while pid > 1 and pid not in out:
        out.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            break
    return out


def wait_port(port, timeout, proc=None, host="127.0.0.1"):
    """Wait until `port` accepts TCP connections; False on timeout or if proc exited first."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            pass
        if proc is not None and proc.poll() is not None:
            return False
        time.sleep(0.03)
    return False


def wait_free(port, timeout=5.0):
    deadline = time.time() + timeout
    while listening(port) and time.time() < deadline:
        time.sleep(0.05)
    return not listening(port)
