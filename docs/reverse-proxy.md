# Reverse proxy

Put finalwisp behind nginx, Caddy, Cloudflare or a load balancer. The proxy holds the certificate and port 443, and
finalwisp still sees the real address of each client.

## Quick setup

1. Start finalwisp. It listens on `127.0.0.1:6001` by default, so only programs on the same machine can reach it:

   ```sh
   finalwisp --preset public --trusted-proxy 127.0.0.1
   ```

2. Point the proxy at it. Caddy (it gets the certificate itself):

   ```caddy
   wisp.example.com {
       reverse_proxy 127.0.0.1:6001
   }
   ```

   Or nginx: use the [server block below](#nginx).

3. Check it from another machine:

   ```sh
   curl https://wisp.example.com/
   # finalwisp: this is a Wisp server
   ```

Clients then connect to `wss://wisp.example.com/`.

`--preset public` is for a server that anyone can reach; see [securing a public server](public-server.md). The
rest of this page explains each part and the other setups:

- [What matters with any proxy](#what-matters-with-any-proxy)
- [nginx](#nginx), [Caddy](#caddy), [Cloudflare](#cloudflare)
- [How the client address is read](#how-the-client-address-is-read)
- [What the server can and cannot tell](#what-the-server-can-and-cannot-tell): setups that look right and are not
- [Unix socket between the proxy and finalwisp](#unix-socket-between-the-proxy-and-finalwisp)
- [PROXY protocol behind a TCP load balancer](#proxy-protocol-behind-a-tcp-load-balancer)

## What matters with any proxy

The usual setup: nginx or Caddy terminates TLS on port 443 and forwards to finalwisp on `127.0.0.1:6001`. Use it to
share port 443 with a website, or when the kernel has no TLS support. The cost is speed: the proxy copies every byte
through user space, while finalwisp's own TLS path stays in the kernel.

Two things matter with any proxy:

1. **Idle timeouts.** finalwisp never closes an idle Wisp connection and sends no Wisp pings while a connection is idle (one known issue after a mass reconnect: see [known limits](troubleshooting.md#known-limits)). Proxies do close
   idle connections: nginx after `proxy_read_timeout` (60 s by default), even while the client is still sending.
   Raise the timeout.
2. **Client addresses.** Without help, finalwisp sees every client as the proxy's address, so per-IP limits would
   hit everyone at once and the logs show only the proxy. Start finalwisp with `--trusted-proxy 127.0.0.1` and have
   the proxy send `X-Forwarded-For`. Trust only a proxy that sets the header itself: see
   [what the server can and cannot tell](#what-the-server-can-and-cannot-tell).

## nginx

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

server {
    listen 443 ssl;
    server_name wisp.example.com;
    ssl_certificate     /etc/letsencrypt/live/wisp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wisp.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:6001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;   # the 60 s default cuts idle Wisp connections
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

```sh
finalwisp --host 127.0.0.1 --port 6001 --trusted-proxy 127.0.0.1
```

To serve Wisp under a path next to a website, use `location /wisp/ { ... }` with the same lines, and give clients
`wss://wisp.example.com/wisp/`.

The short form, inside the `server { ... }` block of the website:

```nginx
location /wisp/ {
    proxy_pass http://127.0.0.1:6001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;   # nginx closes idle WebSockets after 60 s by default
}
```

## Caddy

```caddy
wisp.example.com {
    reverse_proxy 127.0.0.1:6001
}
```

Caddy handles WebSocket upgrades, sets `X-Forwarded-For` and has no idle timeout by default. On a config reload Caddy
closes proxied WebSockets; `stream_close_delay` keeps them open longer:

```caddy
wisp.example.com {
    reverse_proxy 127.0.0.1:6001 {
        stream_close_delay 5m
    }
}
```

## Cloudflare

Cloudflare proxies WebSockets. It is commonly reported to close idle WebSockets after about 100 seconds (its
documentation gives no number). finalwisp cannot prevent that, because it sends nothing on an idle connection: clients should reconnect,
or send some traffic now and then. For the client address, set `--trusted-proxy` to Cloudflare's published address
ranges and either keep `X-Forwarded-For` or use `--real-ip-header cf-connecting-ip`. If another proxy sits between
Cloudflare and finalwisp, list that proxy too.

## How the client address is read

- Only a peer inside `--trusted-proxy` may name the client. From anyone else the header is ignored.
- Every address in `--trusted-proxy` can claim to be any client, so list only your proxies, never a range that also
  holds clients.
- `X-Forwarded-For` is read from right to left. Trusted hops are skipped, and the first other entry is the client. An
  entry the client wrote itself further left does not count.
- With `--real-ip-header x-real-ip` (nginx: `proxy_set_header X-Real-IP $remote_addr;`), the header holds one address.
- A trusted request without the header is not limited per IP. An unreadable header makes the proxy the client.
- Over `--max-conns-per-ip` or `--conn-rate-per-ip`, a client behind a proxy gets `429 Too Many Requests`; a direct
  client is reset at accept.

## What the server can and cannot tell

finalwisp sees connections and requests. It cannot ask what stands in front of it, and at startup nothing shows. Some
wrong setups show in the requests, and then it prints a [hint](logs-metrics.md#runtime-hints-and-warnings). Others look exactly like
a correct setup. The table lists both kinds. The hint numbers are those of the
[runtime hints](logs-metrics.md#runtime-hints-and-warnings) table. "Address" is the client address finalwisp uses for the per-address rules
and the logs.

| in front of finalwisp | address finalwisp uses | does finalwisp notice? | fix |
|---|---|---|---|
| nothing: direct clients | the real one; a client's own `X-Forwarded-For` is ignored | nothing to notice | |
| nginx or Caddy that is not in `--trusted-proxy` | the proxy's address, for every user | Yes, if the proxy sends a forwarding header: Caddy always does, nginx with its `X-Forwarded-For` line does. Hint 1, only with a per-IP limit, `--conn-share` (the `public` preset sets it) or `--trusted-proxy` set. Hint 1 needs the proxy to connect from a loopback or private address: a proxy on another host with a public address gets no hint. nginx without the line sends no header: only hint 3 (with a per-IP limit or `--conn-share`) | `--trusted-proxy` with the proxy's address, and the header line below |
| nginx in `--trusted-proxy` **without** its `X-Forwarded-For` line | whatever address the client writes into its own `X-Forwarded-For` header: nginx passes that header on unchanged. Without one: the proxy's address | **No**, when the client sends the header. The client chooses its own address and so escapes every per-address rule. Without a client header: hint 2 | add the header line below. Never trust a proxy that does not set the header itself |
| nginx with the line, or Caddy, in `--trusted-proxy` | the real one, also when the client sends its own header | correct | |
| a CDN in front of a trusted nginx, the CDN not in `--trusted-proxy` (from the header rule above; not tested with a real CDN) | the CDN node's address (the right-to-left walk stops there), for all users that come through that node | No | list the CDN's published ranges in `--trusted-proxy` too |
| a TCP load balancer or a NAT that sends no PROXY protocol header | the balancer's address, for every user | Not from a request. Hint 3, if that address is a loopback or private one and a per-IP limit or `--conn-share` is set | `--proxy-protocol`, if the balancer can send the header |
| a Docker published port (`-p 6001:6001`) | IPv4 clients: the real one. IPv6 clients: the bridge gateway address (for example `172.17.0.1`), for all of them. A client on the Docker host itself: the host's address or the gateway | Hint 3 only, and only with a per-IP limit or `--conn-share`: the image as shipped starts with the `public` preset, which sets `--conn-share` | publish the port on an IPv4 address only (`-p 0.0.0.0:6001:6001`), or put a reverse proxy in front and trust it |
| a school, an office or a mobile carrier: many users behind one public address | that one address, for all of them | No. It looks the same as one heavy user | none needed: this is why the `public` preset has no per-address numbers |

The header lines:

```nginx
# nginx, with finalwisp --trusted-proxy 127.0.0.1
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

`$proxy_add_x_forwarded_for` appends the address nginx saw to whatever the client sent. finalwisp reads the list from
the right and skips trusted hops, so entries the client wrote do not count. In our test with this line, a client that
sent its own `X-Forwarded-For` was still seen with its real address; without the line, the same client was seen with
the address it had made up.

```caddy
# Caddy, with finalwisp --trusted-proxy 127.0.0.1: nothing to add
reverse_proxy 127.0.0.1:6001
```

Caddy sets `X-Forwarded-For` itself and drops the one the client sent.

Also check which addresses the front listens on: a default Caddy site and a default Docker published port listen on
IPv6 as well as IPv4.

## Unix socket between the proxy and finalwisp

`--listen-unix PATH` adds a listener on a Unix socket, next to the TCP one. The proxy then talks to finalwisp
without a loopback TCP hop. The socket always speaks plain `ws://`.

```sh
finalwisp --host 127.0.0.1 --port 6001 --listen-unix /run/finalwisp/wisp.sock
```

```nginx
proxy_pass http://unix:/run/finalwisp/wisp.sock;   # the rest of the location block as above
```

```caddy
wisp.example.com {
    reverse_proxy unix//run/finalwisp/wisp.sock
}
```

- Who may connect is who may write the socket file. Its mode is 660 (`--unix-mode`). Give the directory the proxy's
  group. With systemd: `RuntimeDirectory=finalwisp`, `RuntimeDirectoryMode=2750` and `Group=www-data` in the unit.
  Without systemd: `install -d -m 2750 -o finalwisp -g www-data /run/finalwisp`.
- Clients on the socket are trusted like a `--trusted-proxy`: their `X-Forwarded-For` names the client. So only a
  proxy that sets the header itself may reach the socket. nginx with `$proxy_add_x_forwarded_for` and Caddy do.
- A second finalwisp on the same path refuses to start (a `PATH.lock` file beside the socket is locked). A socket left
  behind by a crash is replaced. A clean shutdown removes the socket.
- The TCP listener stays on. Keep it on `127.0.0.1` if only the proxy should reach finalwisp.
- Download caps, dead-peer detection and built-in TLS do not apply to Unix socket clients.

## PROXY protocol behind a TCP load balancer

A layer-4 load balancer (AWS NLB, HAProxy in `mode tcp`, an nginx `stream {}` block) can put the client's address in
a PROXY protocol header. Turn it on in finalwisp and in the balancer at the same time:

```sh
finalwisp --host 0.0.0.0 --port 6001 --proxy-protocol tcp --proxy-protocol-from 10.0.0.0/16
```

Balancer side: AWS NLB target group attribute `proxy_protocol_v2.enabled`, HAProxy `send-proxy-v2`, nginx stream
`proxy_protocol on`. For HAProxy to a Unix socket: `server fw unix@/run/finalwisp/wisp.sock send-proxy-v2` with
`--proxy-protocol unix`.

- Every connection on that listener must start with the header (v1 or v2). Without it, the connection is reset.
- Only peers in `--proxy-protocol-from` may send it. List only the balancers. An NLB that preserves client addresses
  connects from the client's own address; then the list must be `0.0.0.0/0,::/0` (finalwisp warns), and your
  firewall or security group must let nothing but the balancer reach the port.
- TLS still ends in finalwisp if you use `--tls-cert`: the header comes before the TLS handshake.
- Health checks work: a LOCAL header, or a plain TCP connect and close. A LOCAL check counts as a new connection
  from the balancer's own address, so with `--conn-rate-per-ip` keep R above the check rate of each balancer node.
- With an HTTP proxy or CDN in front of the balancer, also list that hop in `--trusted-proxy`, so its
  `X-Forwarded-For` names the client.
