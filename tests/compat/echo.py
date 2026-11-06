# 40.02 tiny threaded TCP echo target for compat runs
import socketserver, sys
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while (d := self.request.recv(1 << 20)):
            self.request.sendall(d)
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
