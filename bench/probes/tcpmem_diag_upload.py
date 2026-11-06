
import subprocess, time, threading, os, sys, re
import json
B=sys.argv[1]; TEST=sys.argv[2]; WB="/root/fw-base1/wbench2"
srv=subprocess.Popen([B,"--port","6950","--allow-loopback","--tcpmem-adapt","--metrics-interval","1"],stderr=subprocess.PIPE,text=True)
log=[]; threading.Thread(target=lambda:[log.append((round(time.time()-t0,2),l.rstrip())) for l in srv.stderr],daemon=True).start()
t0=time.time()
tg=subprocess.Popen([WB,"target","--port","6951","--mode",{"upload":"sink","download":"source"}[TEST]],stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
time.sleep(1)
rss=[]; stop=False
def samp():
    while not stop:
        try:
            st=open(f"/proc/{srv.pid}/status").read()
            r=int(re.search(r"VmRSS:\s+(\d+)",st).group(1))//1024
            tcp=[l for l in open("/proc/net/sockstat") if l.startswith("TCP:")][0].split()
            rss.append((round(time.time()-t0,1),r,int(tcp[tcp.index("mem")+1])))
        except Exception: pass
        time.sleep(0.25)
threading.Thread(target=samp,daemon=True).start()
out=subprocess.run([WB,"run","--url","ws://127.0.0.1:6950/","--target","127.0.0.1:6951","--test",TEST,"--conns","10","--streams","10","--duration","8","--warmup","1","--json"],capture_output=True,text=True,timeout=60).stdout
time.sleep(1.5); stop=True
srv.terminate(); srv.wait(10); tg.terminate(); tg.wait(5)
js=json.loads([l for l in out.splitlines() if l.startswith("{")][0])
ent=sum("tcp level 0 -> 1" in l for _,l in log); ex=sum("tcp level 1 -> 0" in l for _,l in log)
print(json.dumps(dict(bin=B, test=TEST, mib_s=js.get("mib_s_up") or js.get("mib_s_down"), entries=ent, exits=ex, peak_rss_mib=max(r for _,r,_ in rss), peak_tcp_pages=max(p for _,_,p in rss), level_lines=[l[10:200] for _,l in log if "tcp level" in l][:8])))
