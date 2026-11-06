//! 30.16 wbench error kinds (pointer 30.01): every counted error also gets one key, so `error_kinds` in the JSON
//! sums to `errors` (the text lines stop after MAX_PRINTED_ERRORS). Keys: `stream_0xNN` (server CLOSE of a stream,
//! by reason), `conn_close_0xNN` (CLOSE on stream 0), `ws_N` (WebSocket close code), `errno_N` (OS error),
//! `setup_timeout`, `handshake_timeout`, `timeout`, `eof`, `upgrade` (non-101 answer), `tls` (a TLS error), `proto` (malformed input
//! from the server), `join_timeout` (a connection task that did not finish), `other` (anything else).
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct ErrKinds {
    /// deliberate: an array, not map keys: churn at memory level 2+ counts millions of stream closes per run
    stream: [u64; 256],
    other: BTreeMap<String, u64>,
}

impl Default for ErrKinds {
    fn default() -> Self {
        ErrKinds { stream: [0; 256], other: BTreeMap::new() }
    }
}

impl ErrKinds {
    pub fn stream_close(&mut self, reason: u8) {
        self.stream[reason as usize] += 1;
    }
    pub fn key(&mut self, k: &str) {
        match self.other.get_mut(k) {
            Some(n) => *n += 1,
            None => {
                self.other.insert(k.to_string(), 1);
            }
        }
    }
    /// count an error by its message (the strings run.rs and connchurn.rs return; see classify)
    pub fn msg(&mut self, m: &str) {
        let k = classify(m);
        self.key(&k);
    }
    pub fn merge(&mut self, o: &ErrKinds) {
        for (a, b) in self.stream.iter_mut().zip(o.stream.iter()) {
            *a += b;
        }
        for (k, n) in &o.other {
            *self.other.entry(k.clone()).or_insert(0) += n;
        }
    }
    pub fn total(&self) -> u64 {
        self.stream.iter().sum::<u64>() + self.other.values().sum::<u64>()
    }
    /// JSON object, keys sorted (stream reasons first), zero counts left out
    pub fn json(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (r, n) in self.stream.iter().enumerate().filter(|(_, n)| **n > 0) {
            parts.push(format!("\"stream_0x{r:02x}\":{n}"));
        }
        for (k, n) in &self.other {
            parts.push(format!("\"{k}\":{n}")); // keys come from classify: [a-z0-9_] only
        }
        format!("{{{}}}", parts.join(","))
    }
}

fn after<'a>(s: &'a str, pat: &str) -> Option<&'a str> {
    s.find(pat).map(|i| &s[i + pat.len()..])
}

fn lead(s: &str, f: fn(&char) -> bool) -> String {
    s.chars().take_while(f).collect::<String>().to_ascii_lowercase()
}

/// The key of one error message (without the "conn N: " prefix the printed line adds).
pub fn classify(m: &str) -> String {
    // review: messages that embed server-controlled text (the HTTP status line, rustls alerts) are keyed
    // first, so that text cannot look like a reason, a code, an errno or a timeout
    if m.contains("ws upgrade failed") {
        return "upgrade".to_string();
    }
    if m.contains("tls: ") {
        return "tls".to_string();
    }
    if let Some(r) = after(m, "reason 0x") {
        let h = lead(r, char::is_ascii_hexdigit);
        if !h.is_empty() {
            let kind = if m.contains("connection CLOSE") { "conn_close" } else { "stream" };
            return format!("{kind}_0x{h:0>2}");
        }
    }
    if m.contains("closed") {
        if let Some(r) = after(m, "(code ") {
            let d = lead(r, char::is_ascii_digit);
            if !d.is_empty() {
                return format!("ws_{d}");
            }
        }
    }
    if let Some(r) = after(m, "(os error ") {
        let d = lead(r, char::is_ascii_digit);
        if !d.is_empty() {
            return format!("errno_{d}");
        }
    }
    let k = if m.ends_with("setup timeout") {
        "setup_timeout"
    } else if m.contains("timeout waiting for Wisp CONTINUE") {
        "handshake_timeout"
    } else if m.contains("timeout") {
        "timeout"
    } else if m.ends_with(": eof") || m == "eof" || m.contains("eof during ws handshake") || m.contains("eof during tls handshake") || m.contains("connection closed by server") {
        "eof"
    } else if ["short wisp packet", "short CONTINUE", "unknown wisp packet type", "masked frame", "unexpected ws opcode",
               "ws frame", "bad initial CONTINUE", "ws handshake response too large"]
        .iter()
        .any(|p| m.contains(p))
    {
        "proto"
    } else {
        "other"
    };
    k.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_every_message_form() {
        // the messages run.rs, connchurn.rs and ws.rs produce (with the prefixes the callers add)
        for (m, k) in [
            ("server closed stream 7 (reason 0x49)", "stream_0x49"),
            ("server sent connection CLOSE (reason 0x41)", "conn_close_0x41"),
            ("stream closed by the server (reason 0x49)", "stream_0x49"),
            ("websocket closed by server (code 1013)", "ws_1013"),
            ("server closed before CONTINUE (code 1013)", "ws_1013"),
            ("server closed the WebSocket before the echo (code 1000)", "ws_1000"),
            ("read: Connection reset by peer (os error 104)", "errno_104"),
            ("write: Broken pipe (os error 32)", "errno_32"),
            ("waiting for the echo: Connection reset by peer (os error 104)", "errno_104"),
            ("connect/upgrade: Connection refused (os error 111)", "errno_111"),
            ("Connection refused (os error 111)", "errno_111"),
            ("socket: Bad file descriptor (os error 9)", "errno_9"),
            ("setup timeout", "setup_timeout"),
            ("timeout waiting for Wisp CONTINUE handshake", "handshake_timeout"),
            ("timeout (10 s)", "timeout"),
            ("websocket TCP connection closed by server", "eof"),
            ("waiting for CONTINUE: eof", "eof"),
            ("connect/upgrade: eof during ws handshake", "eof"),
            ("eof during ws handshake", "eof"),
            ("ws upgrade failed: HTTP/1.1 503 Service Unavailable", "upgrade"),
            ("connect/upgrade: ws upgrade failed: HTTP/1.1 503 timeout (reason 0x49) (os error 104)", "upgrade"),
            ("tls: received fatal alert: timeout (code 1013)", "tls"),
            ("eof during tls handshake", "eof"),
            ("connect/upgrade: eof during tls handshake", "eof"),
            ("short wisp packet (3 bytes)", "proto"),
            ("short CONTINUE", "proto"),
            ("unknown wisp packet type 9", "proto"),
            ("server sent a masked frame", "proto"),
            ("unexpected ws opcode 3 (in_frag=false)", "proto"),
            ("ws frame too large", "proto"),
            ("bad initial CONTINUE (5 bytes, or credit 0)", "proto"),
            ("read: received corrupt message of type InvalidContentType", "other"),
            ("", "other"),
            ("reason 0x", "other"), // no digits: not a reason
        ] {
            assert_eq!(classify(m), k, "{m:?}");
        }
    }

    #[test]
    fn counts_merge_total_json() {
        let mut a = ErrKinds::default();
        a.stream_close(0x49);
        a.stream_close(0x49);
        a.msg("read: Connection reset by peer (os error 104)");
        let mut b = ErrKinds::default();
        b.stream_close(0x02);
        b.key("join_timeout");
        b.msg("read: Connection reset by peer (os error 104)");
        a.merge(&b);
        assert_eq!(a.total(), 6);
        assert_eq!(a.json(), r#"{"stream_0x02":1,"stream_0x49":2,"errno_104":2,"join_timeout":1}"#);
        assert_eq!(ErrKinds::default().json(), "{}");
    }
}
