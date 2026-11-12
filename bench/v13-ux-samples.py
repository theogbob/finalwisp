#!/usr/bin/env python3
"""60.60 the real outputs of the command line, one file per case (the samples of the note and of the docs).

usage: v13-ux-samples.py --bin FINALWISP --out DIR [--port 9860]
Each file starts with the command line ("$ finalwisp ...") and ends with "[exit N]". A started server is stopped
with SIGTERM after its start output; its shutdown lines are in the file. Host facts (threads, memory, limits) are
those of the machine that runs this. Output is captured through a pipe, so there is no colour and no wrapping of
warnings (on a terminal a warning is wrapped at 80 columns)."""
import argparse, os, signal, socket, subprocess, sys, tempfile, time

ap = argparse.ArgumentParser()
ap.add_argument("--bin", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--port", type=int, default=9860)
a = ap.parse_args()
os.makedirs(a.out, exist_ok=True)
tmp = tempfile.mkdtemp(prefix="v13ux-")
conf = os.path.join(tmp, "finalwisp.conf")
open(conf, "w").write("# a small config file\nport %d\nmax-conns 20000\nupstream socks5://user:pass@127.0.0.1:1080\n" % (a.port + 2))
os.chmod(conf, 0o600)


def shown(args):
    return "$ finalwisp " + " ".join(x.replace(tmp, "/etc/finalwisp") for x in args)


def write(name, args, out, rc):
    text = shown(args) + "\n" + out.replace(tmp, "/etc/finalwisp") + "[exit %d]\n" % rc
    open(os.path.join(a.out, name), "w").write(text)
    print("%-28s %3d lines, longest %3d" % (name, len(text.splitlines()), max(len(l) for l in text.splitlines())))


def once(name, args):
    p = subprocess.run([a.bin] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    write(name, args, p.stdout.decode("utf-8", "replace"), p.returncode)


def server(name, args, port):
    p = subprocess.Popen([a.bin] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    end = time.time() + 8
    while time.time() < end and p.poll() is None:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError:
            time.sleep(0.05)
    time.sleep(0.7)
    p.send_signal(signal.SIGTERM)
    out = p.communicate(timeout=20)[0].decode("utf-8", "replace")
    write(name, args, out, p.returncode)


P = a.port
once("real-help.txt", ["--help"])
for t in ["config", "listen", "tls", "client-ip", "limits", "destinations", "auth", "upstream", "dns", "logs", "memory", "advanced", "all"]:
    once("real-help-%s.txt" % t, ["--help", t])
once("real-help-unknown-topic.txt", ["--help", "limit"])
once("real-version.txt", ["--version"])
once("real-error-unknown.txt", ["--max-con", "100"])
once("real-error-unknown-word.txt", ["help"])
once("real-error-not-an-option.txt", ["--thraeds", "4"])
once("real-error-value.txt", ["--port", "abc"])
once("real-error-size.txt", ["--mem-budget", "lots"])
once("real-error-missing-value.txt", ["--tls-cert"])
once("real-error-switch-value.txt", ["--block-smtp=yes"])
once("real-error-removed.txt", ["--prio"])
once("real-error-pair.txt", ["--proxy-protocol", "tcp"])
bad = os.path.join(tmp, "bad.conf")
open(bad, "w").write("port 7000\nmax-conn 100\n")
once("real-error-config-unknown.txt", ["--config", bad])
open(bad, "w").write("port 7000\nthreads s3cretVALUE\n")
once("real-error-config-value.txt", ["--config", bad])
once("real-show-config.txt", ["--show-config"])
once("real-show-config-preset.txt", ["--preset", "public", "--config", conf, "--trusted-proxy", "127.0.0.1", "--no-udp", "--show-config"])
once("real-show-config-equals.txt", ["--port=%d" % P, "--max-conns=500", "--show-config"])
server("real-start-bare.txt", ["--port", str(P)], P)
server("real-start-preset.txt", ["--preset", "public", "--port", str(P + 1), "--trusted-proxy", "127.0.0.1"], P + 1)
server("real-start-config.txt", ["--preset", "public", "--config", conf, "--no-udp", "--metrics-listen", str(P + 3)], P + 2)
server("real-start-debug.txt", ["--port", str(P + 4), "--log-level", "debug"], P + 4)
server("real-start-warn.txt", ["--port", str(P + 5), "--log-level", "warn", "--real-ip-header", "x-real-ip"], P + 5)
