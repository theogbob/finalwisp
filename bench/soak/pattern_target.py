# 30.11 soak: pattern TCP target. Request: [u64 LE length][u64 LE seed]; reply: length bytes of
# the pattern (wispc.pattern_chunk), then a clean close (FIN). Stdlib only, one thread per connection.
import socket, struct, sys, threading
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from wispc import pattern_base, pattern_chunk


def handle(c):
    try:
        hdr = b""
        while len(hdr) < 16:
            d = c.recv(16 - len(hdr))
            if not d:
                return
            hdr += d
        n, seed = struct.unpack("<QQ", hdr)
        base = pattern_base(seed)
        i = 0
        while n > 0:
            ch = pattern_chunk(seed, i, base)[:n]
            c.sendall(ch)
            n -= len(ch)
            i += 1
        c.shutdown(socket.SHUT_WR)
        while c.recv(65536):
            pass
    except OSError:
        pass
    finally:
        c.close()


def main():
    port = int(sys.argv[1])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(1024)
    print(f"pattern target on {port}", flush=True)
    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


main()
