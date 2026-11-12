//! 20.05 HTTP upgrade to WebSocket (Wisp at `/`, legacy wsproxy at `/prefix/host:port`).

use super::*;

impl Worker {
    pub(super) fn handle_http(&mut self, ci: u32) {
        // 60.20 C2 the client-IP header is captured only from a trusted peer (anyone else's is never read)
        let capture = self.cfg.clientip.as_ref().and_then(|cip| {
            let p = self.peers_of.get(ci as usize)?.as_ref()?;
            cip.is_trusted(p.ip).then_some(&*cip.header)
        });
        let c = self.clients.at(ci);
        let req = match http::parse_capture(&c.rbuf[..c.rlen], capture) {
            http::Parsed::Partial => {
                if c.rlen >= http::MAX_REQUEST {
                    http::simple(&mut c.obuf, "431 Request Header Fields Too Large", "too large\n");
                    self.begin_close(ci, Why::ProtocolError);
                } else {
                    c.need = c.rlen + 1024;
                }
                return;
            }
            http::Parsed::Bad => {
                http::simple(&mut c.obuf, "400 Bad Request", "bad request\n");
                self.begin_close(ci, Why::ProtocolError);
                return;
            }
            http::Parsed::Done(r, n) => {
                c.rpos = n;
                c.need = 0;
                r
            }
        };
        let Some(up) = req.upgrade else {
            http::simple(&mut c.obuf, "200 OK", "finalwisp: this is a Wisp server\n");
            self.begin_close(ci, Why::ServerClose);
            return;
        };
        let ip_ok = self.client_ip(ci, &req.fwd);
        if self.meter {
            self.meter_keyed(ci); // 60.25 C10b the key is final now: charge the bootstrap bytes
        }
        if !ip_ok {
            let c = self.clients.at(ci);
            http::simple(&mut c.obuf, "429 Too Many Requests", "too many connections from this address\n");
            self.begin_close(ci, Why::Limit);
            return;
        }
        let c = self.clients.at(ci);
        let path = req.path.split('?').next().unwrap_or("/").to_string();
        if path.ends_with('/') {
            // 20.18: with auth on, clients without the subprotocol header get the v2 handshake too
            // (as epoxy-server does; simple-wisp-client sends no header). v1 cannot authenticate.
            let v2 = up.protocol.is_some() || self.cfg.ext.auth_required();
            if v2 && self.cfg.ext.key_auth() {
                c.challenge = ext::new_challenge();
                if c.challenge.is_none() {
                    http::simple(&mut c.obuf, "503 Service Unavailable", "no randomness\n");
                    self.begin_close(ci, Why::ServerClose);
                    return;
                }
            }
            http::switching(&mut c.obuf, &up);
            if let Some(l) = connlog::entry(&mut self.connlog, ci) {
                l.proto = if v2 { connlog::Proto::V2 } else { connlog::Proto::V1 };
            }
            let c = self.clients.at(ci);
            if v2 {
                // Wisp v2: INFO (ext::Ext::info: 2.0 + extension records); CONTINUE follows the
                // client's INFO.
                let info = self.cfg.ext.info(c.challenge.as_deref());
                c.push_wisp(PKT_INFO, 0, &info);
                c.state = CState::WaitInfo;
            } else {
                // 20.26 r4: under memory pressure the handshake grants the stage's small first credit, so
                // a new stream's first burst is small and needs no CONTINUE of its own (on_connect)
                let n = self.cfg.buffer.min(self.st.hs);
                c.hs_credit = n;
                c.push_wisp(PKT_CONTINUE, 0, &n.to_le_bytes());
                c.state = CState::Open;
            }
            self.mark_dirty(ci);
        } else if self.cfg.ext.auth_required() {
            // 20.18: wsproxy has no handshake to carry credentials, so it would bypass auth
            http::simple(&mut c.obuf, "403 Forbidden", "wsproxy is disabled when authentication is required\n");
            if let Some(l) = connlog::entry(&mut self.connlog, ci) {
                l.auth = connlog::Auth::Failed; // as a v1 client refused with auth required (review)
            }
            self.begin_close(ci, Why::AuthFailed);
        } else {
            // legacy wsproxy: /prefix/host:port
            let last = path.rsplit('/').next().unwrap_or("");
            let parsed = last.rsplit_once(':').and_then(|(h, p)| {
                let h = h.trim_start_matches('[').trim_end_matches(']');
                let h = percent_decode(h);
                Some((h, p.parse::<u16>().ok()?))
            });
            let Some((host, port)) = parsed.filter(|(h, p)| policy::valid_host(h) && *p != 0) else {
                http::simple(&mut c.obuf, "400 Bad Request", "bad wsproxy target\n");
                self.begin_close(ci, Why::ProtocolError);
                return;
            };
            if self.cfg.policy.as_ref().is_some_and(|p| !p.allows(false, &host, port)) {
                // 60.20 C1: the request rules before the 101 (an HTTP status, not a WebSocket that closes at once)
                http::simple(&mut c.obuf, "403 Forbidden", "target refused by the server's policy\n");
                self.stats.refuse_policy.bump();
                self.begin_close(ci, Why::Limit);
                return;
            }
            let live = self.targets.slots.len() - self.targets.free.len();
            if !self.st.admit || live >= self.max_streams {
                // 20.26 memory pressure: no new streams (review: wsproxy must not bypass admission)
                http::simple(&mut c.obuf, "503 Service Unavailable", "server under memory pressure\n");
                self.begin_close(ci, Why::PressureShed);
                return;
            }
            if !self.stream_token(ci) {
                // 60.20 C3b --stream-rate-per-ip: the wsproxy stream takes a token like a CONNECT
                let c = self.clients.at(ci);
                http::simple(&mut c.obuf, "429 Too Many Requests", "stream rate limit for this address\n");
                self.begin_close(ci, Why::Limit);
                return;
            }
            let c = self.clients.at(ci);
            http::switching(&mut c.obuf, &up);
            c.state = CState::Wsproxy;
            if let Some(l) = connlog::entry(&mut self.connlog, ci) {
                l.proto = connlog::Proto::Wsproxy;
            }
            self.mark_dirty(ci);
            if let Some(t) = self.new_target(ci, 0, host, port, true, false) {
                self.clients.at(ci).proxy_target = Some(t);
            }
        }
    }
}

impl Worker {
    /// 60.20 C2/C3b after the HTTP request: a trusted proxy's client gets its real IP from the header and is charged
    /// now (a direct peer was charged at accept). false = over --max-conns-per-ip or (60.40) --conn-rate-per-ip (429).
    fn client_ip(&mut self, ci: u32, fwd: &[Vec<u8>]) -> bool {
        let Some(cip) = &self.cfg.clientip else { return true };
        let Some(p) = self.peers_of.get_mut(ci as usize).and_then(Option::as_mut) else { return true };
        if !cip.is_trusted(p.ip) {
            // headers from an untrusted peer are ignored; it was charged at accept (60.59: hint (a), out of line)
            return self.untrusted_peer(ci);
        }
        let (ip, got) = cip.real_ip(p.ip, fwd);
        match got {
            Some(clientip::Got::Bad) => self.stats.realip_bad.bump(),
            Some(clientip::Got::Missing) => {
                self.stats.realip_missing.bump();
                crate::hints::realip_missing(p.ip, &cip.header); // 60.59 hint (b), cold
            }
            _ => {}
        }
        if ip != p.ip {
            if let Some(l) = connlog::entry(&mut self.connlog, ci) {
                l.via = Some(p.ip); // 60.24 the proxy
            }
        }
        p.ip = ip;
        let Some(t) = &cip.table else { return true };
        if got == Some(clientip::Got::Missing) {
            // no header (and C7 unix peers without one): not charged (fail open, 60.22), never the proxy's shared key.
            // An unparsable header is charged to the last trusted hop (fail safe: such clients share one key).
            return true;
        }
        let k = clientip::key(ip);
        match Self::ip_charge(self.fd_mask, &self.fdg, self.idx, cip, t, k, ip) {
            clientip::Charge::Charged => {
                // 60.31 (60.28 invariant) a trusted peer (a --trusted-proxy, the unix sentinel) is never charged at
                // accept, so there is no earlier key that this overwrite would leak
                debug_assert!(p.key.is_none(), "a trusted peer was charged at accept: its key would leak");
                p.key = Some(k)
            }
            clientip::Charge::Untracked => self.stats.ip_untracked.bump(),
            r @ (clientip::Charge::Refused | clientip::Charge::Rate | clientip::Charge::Share) => {
                self.ip_refused(r);
                return false;
            }
        }
        true
    }

    /// 60.59 hint (a), for a peer that is not a trusted proxy, after its HTTP request was parsed: a loopback or private
    /// peer may be a reverse proxy that --trusted-proxy does not list, so look for a forwarding header in the request
    /// (hints::fwd_untrusted: counter and rate-limited line). Always true: a hint changes nothing. Out of line and cold:
    /// client_ip is inlined into the frame loop's function (process_frames), which gets one call and no scan code.
    #[cold]
    #[inline(never)]
    fn untrusted_peer(&mut self, ci: u32) -> bool {
        let Some(ip) = self.peer(ci).map(|p| p.ip).filter(|&ip| crate::hints::local(ip)) else { return true };
        if let Some(cip) = &self.cfg.clientip {
            let c = self.clients.at(ci);
            crate::hints::fwd_untrusted(ip, &c.rbuf[..c.rpos], &cip.header, &self.stats);
        }
        true
    }

    /// 60.20 C3b --stream-rate-per-ip: one token from the client's key (no key or no rate: always true)
    pub(super) fn stream_token(&mut self, ci: u32) -> bool {
        let Some(t) = self.cfg.clientip.as_ref().and_then(|c| c.table.as_ref()).filter(|t| t.has_rate()) else { return true };
        let Some(k) = self.peer(ci).and_then(|p| p.key) else { return true };
        if t.take(k, clientip::now_ms()) {
            return true;
        }
        self.stats.refuse_ip_rate.bump();
        false
    }
}

pub(super) fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
