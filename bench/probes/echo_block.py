#!/usr/bin/env python3
"""blocking echo target, a thread per connection (recv then sendall: stops reading while its send is full)"""
import socket, sys, threading
def h(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(64)
while True:
    c, _ = l.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
