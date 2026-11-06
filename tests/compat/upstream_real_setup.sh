#!/usr/bin/env bash
# 60.32 C6 the proxies for tests/compat/upstream_real.py, in a throwaway Debian 13 container (as root; it rewrites
# /etc/tinyproxy, /etc/squid and root's ssh keys). Packages: microsocks tinyproxy squid openssh-server openssh-client.
# microsocks :1080 (no auth), :1081 (u / p), OpenSSH `ssh -D` :1082, tinyproxy :8888 (BasicAuth u p), squid :3128
# (denies 192.0.2.9). Never run it on a real host.
set -euo pipefail
cat > /etc/tinyproxy/fw.conf <<'EOF'
Port 8888
Listen 127.0.0.1
Timeout 600
MaxClients 100
Allow 127.0.0.1
BasicAuth u p
DisableViaHeader Yes
EOF
cat > /etc/squid/fw.conf <<'EOF'
http_port 127.0.0.1:3128
acl bad dst 192.0.2.9
http_access deny bad
http_access allow localhost
http_access deny all
cache deny all
access_log none
cache_log /tmp/squid-cache.log
pid_filename /tmp/squid.pid
EOF
pkill tinyproxy || true; pkill squid || true; pkill microsocks || true
systemctl stop squid tinyproxy 2>/dev/null || true
nohup microsocks -i 127.0.0.1 -p 1080 >/tmp/ms0.log 2>&1 &
nohup microsocks -i 127.0.0.1 -p 1081 -u u -P p >/tmp/ms1.log 2>&1 &
tinyproxy -c /etc/tinyproxy/fw.conf
squid -f /etc/squid/fw.conf
mkdir -p /root/.ssh; [ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519
cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys
systemctl start ssh || service ssh start
sleep 1
nohup ssh -o StrictHostKeyChecking=no -N -D 127.0.0.1:1082 root@127.0.0.1 >/tmp/sshd.log 2>&1 &
sleep 3
ss -ltnp | grep -E "1080|1081|1082|8888|3128"
