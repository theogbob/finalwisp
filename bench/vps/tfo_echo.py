#!/usr/bin/env python3
"""30.07 echo target with TCP Fast Open on the listener. Usage: tfo_echo.py HOST PORT"""
import socket, sys, threading
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
l = socket.socket(fam); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 256)
l.bind((sys.argv[1], int(sys.argv[2]))); l.listen(256)
def h(c):
    try:
        while (d := c.recv(65536)): c.sendall(d)
    except OSError: pass
    c.close()
while True:
    c, _ = l.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
