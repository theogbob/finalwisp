"""Socket poller for the browser sim busy-case trace (bench/browser; no root needed).

  python3 sockpoll.py WISP_PORT [ORIGIN_PORT]     (stops on SIGTERM or stdin EOF)

Every ~2 ms, an exact sock_diag lookup (netlink, one socket each, no dump) of the Wisp server socket and the
browser's socket of the same connection (127.0.0.1, found once via /proc/net/tcp: the established pair on
WISP_PORT with the most traffic); every ~25 ms also the summed Recv-Q of the server's sockets to ORIGIN_PORT.
Prints JSON lines [epoch ms, server bytes written (bytes_acked + Send-Q), server notsent, client bytes_received,
client Recv-Q, origin Recv-Q sum]. `ss` costs ~70 ms per call here (inet_diag dump), too coarse for this.
"""
import json, os, select, signal, socket, struct, sys, time

AF_NETLINK, NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY = 16, 4, 20
NLM_F_REQUEST, INET_DIAG_INFO = 1, 2
TCP_ESTABLISHED = 1


def established(port_local=None, port_remote=None):
    """[(lport, rport, rx_queue, tx_queue)] of established 127.0.0.1 sockets from /proc/net/tcp."""
    out = []
    with open("/proc/net/tcp") as f:
        next(f)
        for line in f:
            x = line.split()
            if x[3] != "01":
                continue
            lp, rp = int(x[1].split(":")[1], 16), int(x[2].split(":")[1], 16)
            if (port_local is None or lp == port_local) and (port_remote is None or rp == port_remote):
                tx, rx = (int(v, 16) for v in x[4].split(":"))
                out.append((lp, rp, rx, tx))
    return out


class Diag:
    def __init__(self):
        self.s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
        self.seq = 0

    def query(self, sport, dport):
        """(rqueue, wqueue, bytes_acked, bytes_received, notsent) of the 127.0.0.1:sport -> 127.0.0.1:dport socket."""
        self.seq += 1
        lo = socket.inet_aton("127.0.0.1")
        sid = struct.pack(">HH", sport, dport) + lo + b"\0" * 12 + lo + b"\0" * 12 + struct.pack("=I", 0) + struct.pack("=II", 0xFFFFFFFF, 0xFFFFFFFF)
        req = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_TCP, 1 << (INET_DIAG_INFO - 1), 0, 1 << TCP_ESTABLISHED) + sid
        msg = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST, self.seq, 0) + req
        self.s.send(msg)
        data = self.s.recv(65536)
        ln, typ = struct.unpack_from("=IH", data, 0)
        if typ != SOCK_DIAG_BY_FAMILY:
            return None
        body = data[16:ln]
        rq, wq = struct.unpack_from("=II", body, 4 + 48 + 4)
        off = 72
        while off + 4 <= len(body):
            alen, atyp = struct.unpack_from("=HH", body, off)
            if alen < 4:
                break
            if atyp == INET_DIAG_INFO and alen - 4 >= 148:
                acked, received = struct.unpack_from("=QQ", body, off + 4 + 120)
                (notsent,) = struct.unpack_from("=I", body, off + 4 + 144)
                return rq, wq, acked, received, notsent
            off += (alen + 3) & ~3
        return rq, wq, 0, 0, 0


def main():
    wport = int(sys.argv[1])
    oport = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "0" else None
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    d, pair, last_origin, orq, last_find = Diag(), None, 0.0, 0, 0.0
    out = sys.stdout
    while True:
        if select.select([sys.stdin], [], [], 0)[0] and not sys.stdin.read(1):
            return
        now = time.time()
        if pair is None or now - last_find > 0.5:
            last_find = now  # the busy case has one Wisp connection; re-check twice a second in case it changed
            cands = established(port_remote=wport)
            if cands:
                best = max(cands, key=lambda c: (c[2], c[0]))
                pair = (best[0], wport)
        if oport and now - last_origin > 0.025:
            last_origin = now
            orq = sum(c[2] for c in established(port_remote=oport))
        if pair:
            try:
                srv, cli = d.query(wport, pair[0]), d.query(pair[0], wport)
            except OSError:
                srv = cli = None
            if srv and cli:
                out.write(json.dumps([round(now * 1000, 1), srv[2] + srv[1], srv[4], cli[3], cli[0], orq]) + "\n")
                out.flush()
        time.sleep(0.002)


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
