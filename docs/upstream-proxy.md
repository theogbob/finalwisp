# Upstream proxy and Tor

`--upstream` sends every TCP stream through one SOCKS5 or HTTP CONNECT proxy. Use it to give all clients one exit
address, or to send them through Tor.

```sh
finalwisp --upstream socks5://127.0.0.1:1080
finalwisp --upstream http://user:secret@proxy.example.com:3128
```

- [How it behaves](#how-it-behaves)
- [Tor](#tor)

## How it behaves

- DNS, the destination policy, the limits and the memory budget still run in finalwisp. Only an allowed IP address is
  sent to the proxy.
- There is never a fallback to direct connections. If the proxy fails, the stream fails.
- The proxy's address is not checked against the policy: a proxy on `127.0.0.1` works without `--allow-loopback`.
  A proxy name is resolved at startup and again every 30 s.
- Credentials go to the proxy in clear text (SOCKS and HTTP Basic both do that). Put the URL in a config file with mode
  0600, not on the command line, where other users can read it.
- UDP streams are refused, because neither proxy type carries them here. TLS to the proxy (`https://`) is not
  supported.
- `--connect-timeout` covers the whole setup: the connect to the proxy, its handshake and its connect to the target.

Tested with microsocks, OpenSSH `ssh -D`, tinyproxy (with Basic auth), squid and Tor.

## Tor

```sh
sudo apt install tor     # listens on 127.0.0.1:9050 by default
finalwisp --upstream socks5h://127.0.0.1:9050 --upstream-trust-dns --connect-timeout 30
```

- Use `socks5h://` with `--upstream-trust-dns`. Tor then resolves every name at the exit, and finalwisp sends no DNS
  query at all. With plain `socks5://`, finalwisp resolves the names itself, so your resolver sees every site your
  users visit.
- `.onion` addresses work with `socks5h://` (not with `socks5://`).
- Set `--connect-timeout 30` (the default is 10). The timeout covers Tor's circuit setup and the target connect. A
  first stream after Tor starts can take several seconds, a `.onion` up to about 9 s in our tests, and Tor retries a
  stalled stream on a new circuit only after 10-15 s.
- With `socks5h://`, the address rules cannot see where a name points (the exit resolves it). Host and port rules still
  apply, IP addresses still go through the address rules, and loopback names are still refused locally. finalwisp warns about this at startup.
- If Tor stops, new streams fail at once and finalwisp keeps running. Once Tor is back, streams work again without a
  restart.
- All clients share Tor's circuits, because finalwisp sends one set of SOCKS credentials (none).
- UDP is refused (Tor carries no UDP).
