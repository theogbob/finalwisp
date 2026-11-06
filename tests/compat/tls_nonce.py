#!/usr/bin/env python3
"""40.05 TLS 1.2 AES-GCM explicit nonces must never repeat across the rustls -> kTLS handover (20.13).
Records every server->client record of a TLS 1.2 session (Finished from rustls, then kTLS records: the
101 response and Wisp frames) and checks the 8-byte explicit nonces are all distinct.
Usage: tls_nonce.py PORT"""
import socket, ssl, struct, sys
port = int(sys.argv[1]); fails = 0
for cipher in ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2; ctx.set_ciphers(cipher)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO(); t = ctx.wrap_bio(inc, out)
    s = socket.create_connection(("127.0.0.1", port)); wire = bytearray()
    def pump():
        d = out.read()
        if d: s.sendall(d)
    def feed():
        d = s.recv(65536)
        if not d: raise EOFError
        wire.extend(d); inc.write(d)
    while True:
        try: t.do_handshake(); break
        except ssl.SSLWantReadError: pump(); feed()
    pump()
    t.write(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    pump()
    for _ in range(3):  # 101 + Wisp CONTINUE frame (+ maybe more), several kTLS records
        try: feed()
        except (socket.timeout, EOFError): break
        s.settimeout(0.3)
    s.close()
    # parse records; encrypted ones start after the server's ChangeCipherSpec (type 20)
    i, after_ccs, nonces, kinds = 0, False, [], []
    while i + 5 <= len(wire):
        typ, ln = wire[i], struct.unpack(">H", wire[i + 3:i + 5])[0]
        frag = wire[i + 5:i + 5 + ln]; i += 5 + ln
        if typ == 20: after_ccs = True; continue
        if after_ccs and len(frag) >= 8: nonces.append(bytes(frag[:8])); kinds.append(typ)
    ok = len(nonces) >= 2 and len(set(nonces)) == len(nonces)
    fails += not ok
    print(("PASS" if ok else "FAIL") + f" TLS1.2 {t.cipher()[0]}: {len(nonces)} encrypted server records (types {kinds}), explicit nonces distinct={len(set(nonces)) == len(nonces)} first={[n.hex() for n in nonces[:3]]}")
print("ALL PASS" if not fails else f"{fails} FAILURES"); sys.exit(1 if fails else 0)
