#!/usr/bin/env python3
"""80.04 layer L8: did DATA and the server's CLOSE of a stream arrive in one TCP segment? (diagnostic for the closefail
workloads). Reads the pcaps of e2e.py --pcap-round (closefail runs), reassembles the
server -> client byte stream of each Wisp connection, parses the WebSocket frames (server frames are unmasked) and the Wisp
packet in each, and joins each stream with the client's outcome and its client-side arrival record (client.mjs --wslog:
s.resp = one entry per request joined to its stream). The client-read table needs no pcap: it covers every tapped
(epoxy / epoxy-v2) closefail run of the session; the wire table covers the --pcap-round runs.
usage: bench/e2e/pcapclose.py OUT [--json]"""
import bisect, json, os, struct, sys
from collections import defaultdict


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            e = "<"
        else:
            e = ">"
            magic = struct.unpack(">I", hdr[:4])[0]
        nano = magic == 0xa1b23c4d
        link = struct.unpack(e + "I", hdr[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts, tf, incl, _ = struct.unpack(e + "IIII", rh)
            data = f.read(incl)
            t = ts + tf / (1e9 if nano else 1e6)
            off = {1: 14, 113: 16, 276: 20, 0: 4}.get(link)
            if off is None:
                raise SystemExit(f"{path}: link type {link} not handled")
            ip = data[off:]
            if not ip or ip[0] >> 4 != 4:
                continue
            ihl = (ip[0] & 15) * 4
            tot = struct.unpack(">H", ip[2:4])[0]
            if ip[9] != 6:
                continue
            src, dst = ip[12:16], ip[16:20]
            tcp = ip[ihl:tot]
            sport, dport, seq = struct.unpack(">HHI", tcp[:8])
            doff = (tcp[12] >> 4) * 4
            flags = tcp[13]
            yield t, (src, sport, dst, dport), seq, flags, tcp[doff:]


def flows(path, port):
    """server -> client byte streams: {flow: (bytes, [(start, end, seg_no, t)])}"""
    isn, segs = {}, defaultdict(list)
    for n, (t, k, seq, flags, pl) in enumerate(packets(path)):
        if k[1] != port:
            continue
        if flags & 0x02:  # SYN-ACK
            isn[k] = seq + 1
            continue
        if pl and k in isn:
            segs[k].append(((seq - isn[k]) & 0xffffffff, pl, n, t))
    out = {}
    for k, lst in segs.items():
        buf = bytearray()
        bounds = []
        for off, pl, n, t in sorted(lst, key=lambda x: x[0]):
            if off + len(pl) <= len(buf):
                continue  # retransmission
            if off > len(buf):
                break  # a hole: stop here
            pl = pl[len(buf) - off:]
            bounds.append((len(buf), len(buf) + len(pl), n, t))
            buf += pl
        out[k] = (bytes(buf), bounds)
    return out


def frames(buf):
    """(start, end, wisp type, stream id, payload length) of each binary WS frame after the HTTP 101 header"""
    i = buf.find(b"\r\n\r\n")
    if i < 0:
        return
    i += 4
    while i + 2 <= len(buf):
        b0, b1 = buf[i], buf[i + 1]
        n, h = b1 & 127, 2
        if n == 126:
            n, h = struct.unpack(">H", buf[i + 2:i + 4])[0], 4
        elif n == 127:
            n, h = struct.unpack(">Q", buf[i + 2:i + 10])[0], 10
        if b1 & 128:
            h += 4
        if i + h + n > len(buf):
            return
        p = buf[i + h:i + h + n]
        if (b0 & 15) == 2 and n >= 5:
            yield i, i + h + n, p[0], struct.unpack("<I", p[1:5])[0], n - 5
        i += h + n


CLOSE_NOTIFY = 24  # TLS 1.3 close_notify record (5 header + 1 type + 2 alert + 16 tag): the target is Node TLS 1.3


def analyse_pcap(path, port):
    """per stream id: DATA frames [(payload bytes, segment no, t)] and the server CLOSE (segment no, t)"""
    res = {}
    for k, (buf, bounds) in flows(path, port).items():
        starts = [b[0] for b in bounds]
        seg = lambda off: bounds[bisect.bisect_right(starts, off) - 1]
        for s, e, typ, sid, n in frames(buf):
            d = res.setdefault(sid, {"data": [], "close": None})
            if typ == 2:
                b = seg(e - 1)
                d["data"].append((n, b[2], b[3]))
            elif typ == 4 and d["close"] is None:
                b = seg(s)
                d["close"] = (b[2], b[3])
    return res


def wire(p):
    """the last response-bearing DATA (not a lone close_notify) against the CLOSE: same segment?, gap us"""
    if not p or not p["close"]:
        return None, None
    rd = [x for x in p["data"] if x[0] != CLOSE_NOTIFY] or p["data"]
    if not rd:
        return None, None
    n, sg, t = rd[-1]
    return sg == p["close"][0], round(1e6 * (p["close"][1] - t), 1)


def client(x):
    """client side (client.mjs --wslog): response-bearing DATA in the CLOSE's socket read?, ms from it to the CLOSE"""
    d = x.get("data")
    if not d:
        return None, None
    rd = [y for y in d if y[0] != CLOSE_NOTIFY] or d
    return any(y[1] == 0 for y in rd), rd[-1][2] if len(rd[-1]) > 2 else None


def wilson(k, n, z=1.96):
    if not n:
        return "-"
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5 / den
    return f"{100 * p:.1f} % [{100 * max(0, c - h):.1f}, {100 * min(1, c + h):.1f}]"


def main():
    out = sys.argv[1]
    meta = json.load(open(os.path.join(out, "meta.json")))
    port = meta["port_base"] + 1
    rows = defaultdict(list)  # (arm, client) -> responses
    order = []
    lines = [json.loads(x) for x in open(os.path.join(out, "raw.jsonl")) if x.strip()]
    excl = {str(r["round"]) for r in lines if r.get("event") == "round" and (r.get("flag") or r.get("incomplete"))}
    if os.path.exists(os.path.join(out, "excluded.json")):
        excl |= set(json.load(open(os.path.join(out, "excluded.json"))))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import e2e
    excl |= set(e2e.overlap_exclusions(meta, lines))  # rounds overlapping foreign OVERLAP.jsonl windows
    for r in lines:
        if not str(r.get("w", "")).startswith("closefail") or not (r.get("res") or {}).get("ok") or str(r.get("round")) in excl:
            continue
        s = r["res"].get("s") or {}
        resp = s.get("resp")
        if not isinstance(resp, list) or not resp or "data" not in resp[0]:
            continue  # no tap (wisp-js / direct) or not joined
        pcp = analyse_pcap(os.path.join(out, r["pcap"]), port) if r.get("pcap") else None
        key = (r["arm"], r["client"])
        if key not in rows:
            order.append(key)
        for x in resp:
            cr, cg = client(x)
            ws, wg = wire(pcp.get(x["sid"])) if pcp is not None else (None, None)
            rows[key].append({"round": r.get("round"), "i": x["i"], "size": x["size"], "kept": bool(x["ok"]), "sid": x["sid"],
                              "client_resp_in_close_read": cr, "client_gap_ms": cg, "wire_resp_same_segment": ws, "wire_gap_us": wg,
                              "err": x.get("err"), "data": x.get("data")})
    if "--json" in sys.argv:
        print(json.dumps([{"arm": a, "client": c, "responses": rows[(a, c)]} for a, c in order], indent=1))
        return
    md = lambda xs: (sorted(xs)[len(xs) // 2] if xs else "-")
    print("Client read (every tapped closefail run): R = the response-bearing DATA came in the same socket read as the server's CLOSE")
    print()
    print("| arm | client | responses | lost | lost when R | lost when not R | R share | kept when R | lost, not R |")
    print("|---|---|---|---|---|---|---|---|---|")
    for a, c in order:
        g = rows[(a, c)]
        R = [p for p in g if p["client_resp_in_close_read"]]
        nR = [p for p in g if p["client_resp_in_close_read"] is False]
        lR, lnR = sum(not p["kept"] for p in R), sum(not p["kept"] for p in nR)
        print(f"| {a} | {c} | {len(g)} | {sum(not p['kept'] for p in g)} | {lR}/{len(R)} = {wilson(lR, len(R))} | {lnR}/{len(nR)} = {wilson(lnR, len(nR))} "
              f"| {wilson(len(R), len(g))} | {len(R) - lR} | {lnR} |")
    pw = [(k, [p for p in rows[k] if p["wire_resp_same_segment"] is not None]) for k in order]
    pw = [(k, g) for k, g in pw if g]
    if pw:
        print()
        print("Wire (pcap rounds): S = the response-bearing DATA and the CLOSE in one TCP segment; gap = CLOSE segment time - DATA segment time")
        print()
        print("| arm | client | outcome | responses | S | gap us (median) | R | client gap ms (median) |")
        print("|---|---|---|---|---|---|---|---|")
        for (a, c), g in pw:
            for kept in (False, True):
                h = [p for p in g if p["kept"] == kept]
                if h:
                    print(f"| {a} | {c} | {'kept' if kept else 'lost'} | {len(h)} | {sum(bool(p['wire_resp_same_segment']) for p in h)}/{len(h)} "
                          f"| {md([p['wire_gap_us'] for p in h if p['wire_gap_us'] is not None])} "
                          f"| {sum(bool(p['client_resp_in_close_read']) for p in h)}/{len(h)} | {md([p['client_gap_ms'] for p in h if p['client_gap_ms'] is not None])} |")


if __name__ == "__main__":
    main()
