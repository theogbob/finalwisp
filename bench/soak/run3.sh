#!/bin/bash
# 60.78 G05 soak driver, v1.4.0 candidate. usage: [FW_SOAK_DIR=DIR] run3.sh NAME MINUTES FW (run2.sh + hard timeouts)
# lane B adds --unread-close; smapsmon.py writes the anonymous mappings of both servers every 600 s.
ulimit -n $(ulimit -Hn)
cd "${FW_SOAK_DIR:-$HOME/fw-soak}" || exit 1  # the soak checkout (default ~/fw-soak)
N=$1; M=$2; FW=$3
mkdir -p runs
END=$(( $(date +%s) + M*60 + 120 ))
setsid nohup timeout --kill-after=600 $(( M*60 + 3600 )) python3 soak.py runs/$N --fw $FW --wbench ./wbench --no-scope --no-halfopen --no-deadtarget --tcp-safe --gap-scale 2.5 --minutes $M --args-a "--preset public" --args-b "--preset public --auto-balance --unread-close --log-conns --log-streams --metrics-listen 127.0.0.1:7190" > runs/$N.out 2>&1 < /dev/null &
echo $! > runs/$N.pid
sleep 20
setsid nohup timeout --kill-after=60 $(( M*60 + 3700 )) python3 scrape.py http://127.0.0.1:7190/metrics runs/$N.scrape.jsonl 15 --until $END > runs/scrape-$N.out 2>&1 < /dev/null &
echo $! > runs/$N.scrape.pid
setsid nohup timeout --kill-after=60 $(( M*60 + 3700 )) python3 smapsmon.py runs/$N runs/$N.smaps.jsonl --every 600 --until $END > runs/smaps-$N.out 2>&1 < /dev/null &
echo $! > runs/$N.smaps.pid
