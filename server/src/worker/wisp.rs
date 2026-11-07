//! 10.01 Wisp messages from the client: the v2 INFO reply (WaitInfo), CONNECT, CLOSE, DATA. The server side of the
//! handshake (v1 CONTINUE, v2 INFO) is in upgrade.rs.

use super::*;

// 10.01 Wisp packet types, stream types and the close reasons this server sends (wire values; ext.rs has the v2
// extension ids and the handshake/auth reasons CLOSE_INCOMPATIBLE 0x04 and 0xc0-0xc2)
const PKT_CONNECT: u8 = 0x01;
pub(super) const PKT_DATA: u8 = 0x02;
pub(super) const PKT_CONTINUE: u8 = 0x03;
pub(super) const PKT_CLOSE: u8 = 0x04;
pub(super) const PKT_INFO: u8 = 0x05;
pub(super) const STREAM_TCP: u8 = 0x01;
pub(super) const STREAM_UDP: u8 = 0x02;
pub(super) const CLOSE_VOLUNTARY: u8 = 0x02; // the target closed (EOF)
pub(super) const CLOSE_NETWORK: u8 = 0x03; // network error (also net::data_reason's default)
pub(super) const CLOSE_INVALID: u8 = 0x41; // bad CONNECT (short, unknown type, empty host, port 0, UDP with --no-udp)
pub(super) const CLOSE_UNREACHABLE: u8 = 0x42; // no address / unreachable (net::connect_reason has the errno map)
pub(super) const CLOSE_TIMEOUT: u8 = 0x43; // connect timeout
pub(super) const CLOSE_BLOCKED: u8 = 0x48; // every address refused by the SSRF filter (net::Filter)
pub(super) const CLOSE_THROTTLED: u8 = 0x49; // no admission (memory level 2+, stream limit), DNS in-flight limit, upload over its backlog cap, per-destination rate (60.39, after DNS)

impl Worker {
    pub(super) fn on_message(&mut self, ci: u32, m: &[u8]) {
        let state = self.clients.at(ci).state;
        if state == CState::Wsproxy {
            if let Some((ti, tg)) = self.clients.at(ci).proxy_target {
                if self.targets.get(ti, tg).is_some() {
                    self.write_target(ti, m);
                }
            }
            return;
        }
        if m.len() < 5 {
            return; // malformed: ignore like the reference servers
        }
        let ty = m[0];
        let sid = u32::from_le_bytes([m[1], m[2], m[3], m[4]]);
        let body = &m[5..];
        if ty == PKT_DATA && state == CState::Open {
            let Some(&ti) = self.clients.at(ci).streams.get(&sid) else { return };
            let t = self.targets.at(ti);
            if t.udp {
                return self.udp_send(ti, body); // 20.16: one datagram, no credit
            }
            t.since += 1;
            if let Some(s) = t.cv.as_mut() {
                s.on_data(body.len()); // 20.30
            }
            // 20.26 r4 mean upload packet size (after_write); halved at 2^20 packets so the mean follows
            t.upkts += 1;
            t.ubytes += body.len() as u64;
            t.umax = t.umax.max(body.len() as u32); // (frames are at most MAX_FRAME)
            if t.upkts == 1 << 20 {
                (t.upkts, t.ubytes) = (t.upkts / 2, t.ubytes / 2);
            }
            let in_rbuf = {
                let rb = &self.clients.at(ci).rbuf;
                let (lo, hi) = (rb.as_ptr() as usize, rb.as_ptr() as usize + rb.len());
                let p = body.as_ptr() as usize;
                p >= lo && p + body.len() <= hi
            };
            let t = self.targets.at(ti);
            if in_rbuf && t.state == TState::Open && t.pend.len() == t.phead && !body.is_empty() {
                self.stage_upload(ti, body);
            } else {
                self.flush_upload();
                if self.targets.slots.get(ti as usize).is_some_and(|s| s.1.is_some()) {
                    self.write_target(ti, body); // flush may have closed ti (write error)
                }
            }
            return;
        }
        self.flush_upload(); // keep order: CONNECT/CLOSE/etc. must not overtake staged data
        if state == CState::WaitInfo {
            // body[0] = the client's Wisp version major (2), not a packet or stream type
            if ty == PKT_INFO && sid == 0 && body.len() >= 2 && body[0] == 2 {
                // 20.18: auth decision on the client's extension records (ext::Ext::check)
                let c = self.clients.at(ci);
                let verdict = self.cfg.ext.check(&body[2..], c.challenge.as_deref());
                c.challenge = None;
                match verdict {
                    Ok(()) => {
                        if let Some(l) = connlog::entry(&mut self.connlog, ci) {
                            l.auth = if self.cfg.ext.auth_required() { connlog::Auth::Ok } else { connlog::Auth::None };
                        }
                        let c = self.clients.at(ci);
                        let n = self.cfg.buffer.min(self.st.hs); // 20.26 r4
                        c.hs_credit = n;
                        c.push_wisp(PKT_CONTINUE, 0, &n.to_le_bytes());
                        c.state = CState::Open;
                        self.mark_dirty(ci);
                    }
                    Err(reason) => self.wisp_reject(ci, reason),
                }
            } else if ty == PKT_INFO && sid == 0 {
                self.wisp_reject(ci, ext::CLOSE_INCOMPATIBLE); // incompatible version
            } else if ty == PKT_CLOSE && sid == 0 {
                // 60.05 H6: the client rejected our INFO (protocol: CLOSE(0, reason), then it closes the
                // WebSocket): a clean close, not a protocol error or an auth refusal
                let c = self.clients.at(ci);
                c.challenge = None;
                ws::push_frame(&mut c.obuf, OP_CLOSE, &[&1000u16.to_be_bytes()]);
                self.begin_close(ci, Why::ClientClose);
            } else if self.cfg.ext.auth_required() {
                self.wisp_reject(ci, ext::CLOSE_AUTH_REQUIRED); // 20.18: v1 traffic, no credentials
            } else {
                connlog::set_why(&mut self.connlog, ci, Why::ProtocolError); // 60.24 Wisp traffic before the INFO
                self.ws_fail(ci, 1002);
            }
            return;
        }
        match ty {
            PKT_CONNECT => self.on_connect(ci, sid, body),
            PKT_CLOSE => {
                if let Some(ti) = self.clients.at(ci).streams.remove(&sid) {
                    self.close_target(ti, None);
                }
            }
            _ => {} // CONTINUE/INFO from client after handshake: ignore
        }
    }

    fn on_connect(&mut self, ci: u32, sid: u32, body: &[u8]) {
        let c = self.clients.at(ci);
        if sid == 0 || c.streams.contains_key(&sid) {
            return; // deliberate: ignore invalid/duplicate ids instead of killing the live stream
        }
        if let Some(l) = connlog::entry(&mut self.connlog, ci) {
            l.connects += 1; // 60.24 (refused = connects - opened)
        }
        let c = self.clients.at(ci);
        if body.len() < 3 {
            c.push_wisp(PKT_CLOSE, sid, &[CLOSE_INVALID]);
            self.stats.close[CLOSE_INVALID as usize].bump(); // 60.12
            self.mark_dirty(ci);
            if self.cfg.log_streams {
                // 60.35
                self.slog_refused(ci, sid, body, CLOSE_INVALID, SWhy::Invalid, "");
            }
            return;
        }
        let stype = body[0];
        let port = u16::from_le_bytes([body[1], body[2]]);
        // 20.16: UDP in v1 and v2. deliberate: a v2 client that did not list extension 0x01 may still
        // open UDP streams (it evidently supports them; wisp-js, epoxy and wispurr accept it too).
        let udp = stype == STREAM_UDP;
        let host = match std::str::from_utf8(&body[3..]) {
            Ok(h) if port != 0 && (stype == STREAM_TCP || udp) && policy::valid_host(h) => h,
            _ => {
                // bad type / port / host (60.20 C1: empty, over 255 bytes, NUL, control, space) -> invalid
                c.push_wisp(PKT_CLOSE, sid, &[CLOSE_INVALID]);
                self.stats.close[CLOSE_INVALID as usize].bump(); // 60.12
                self.mark_dirty(ci);
                if self.cfg.log_streams {
                    self.slog_refused(ci, sid, body, CLOSE_INVALID, SWhy::Invalid, "");
                }
                return;
            }
        };
        // 60.20 C1 destination policy, before the stream cap, memory admission and DNS: a refused CONNECT takes no
        // slot, no budget, no lookup. UDP with --no-udp is a policy refusal too (Q7: 0x48, was 0x41).
        if (udp && !self.cfg.udp) || self.cfg.policy.as_ref().is_some_and(|p| !p.allows(udp, host, port)) {
            c.push_wisp(PKT_CLOSE, sid, &[CLOSE_BLOCKED]);
            self.stats.close[CLOSE_BLOCKED as usize].bump();
            self.stats.refuse_policy.bump();
            self.mark_dirty(ci);
            if self.cfg.log_streams {
                self.slog_refused(ci, sid, body, CLOSE_BLOCKED, SWhy::Policy, "");
                // (names the rule)
            }
            return;
        }
        let host = host.to_string();
        // 60.20 C3a --max-streams-per-conn: c.streams holds every stream of this connection from CONNECT until
        // close_target (resolving, connecting, open). Before memory admission, so a client over its own cap is counted
        // as `limit` also under pressure. UDP streams count; wsproxy (one stream) never gets here.
        if self.cfg.max_streams_per_conn > 0 && c.streams.len() >= self.cfg.max_streams_per_conn as usize {
            c.push_wisp(PKT_CLOSE, sid, &[CLOSE_THROTTLED]);
            self.stats.close[CLOSE_THROTTLED as usize].bump();
            self.stats.refuse_limit.bump();
            self.mark_dirty(ci);
            if self.cfg.log_streams {
                self.slog_refused(ci, sid, body, CLOSE_THROTTLED, SWhy::Limit, "max_streams_per_conn");
            }
            return;
        }
        let live = self.targets.slots.len() - self.targets.free.len();
        if !self.st.admit || live >= self.max_streams {
            // 20.26 hard memory pressure, or as many streams as the capped socket buffers allow: no new streams (0x49 throttled; wisp-js and epoxy report it
            // as a failed stream, the connection stays up)
            c.push_wisp(PKT_CLOSE, sid, &[CLOSE_THROTTLED]);
            self.stats.close[CLOSE_THROTTLED as usize].bump(); // 60.12
            (if self.st.admit { &self.stats.refuse_streams } else { &self.stats.refuse_admit }).bump();
            self.mark_dirty(ci);
            if self.cfg.log_streams {
                let rule = if self.st.admit { "stream_cap" } else { "admission" };
                self.slog_refused(ci, sid, body, CLOSE_THROTTLED, SWhy::Pressure, rule);
            }
            return;
        }
        // 60.20 C3b --stream-rate-per-ip, last: no token is spent while policy, the cap or memory refuse
        if self.cfg.clientip.is_some() && !self.stream_token(ci) {
            let c = self.clients.at(ci);
            c.push_wisp(PKT_CLOSE, sid, &[CLOSE_THROTTLED]);
            self.stats.close[CLOSE_THROTTLED as usize].bump();
            self.mark_dirty(ci);
            if self.cfg.log_streams {
                self.slog_refused(ci, sid, body, CLOSE_THROTTLED, SWhy::Limit, "stream_rate");
            }
            return;
        }
        self.stats.connects.bump(); // 60.12 (before new_target: it may fail the stream at once, e.g. DNS)
        if let Some(l) = connlog::entry(&mut self.connlog, ci) {
            l.opened += 1;
        }
        if let Some((ti, _)) = self.new_target(ci, sid, host, port, false, udp) {
            self.clients.at(ci).streams.insert(sid, ti);
            let (g, hs) = (self.st.hs.min(self.cfg.buffer), self.clients.at(ci).hs_credit);
            if !udp && g != hs {
                // 20.26 memory pressure: shrink the handshake's credit for this stream at once (r4:
                // only when this client's handshake granted something else than the stage's first
                // credit; also back up to --buffer for a client that did its handshake under pressure)
                let t = self.targets.at(ti);
                (t.credit, t.allow) = (g, next_allow(hs, 0, g));
                self.push_continue(ci, ti, sid, g);
            }
        }
    }
}
