//! 20.03 HTTP/1.1 upgrade handling (request parse + responses).

pub const MAX_REQUEST: usize = 16 * 1024;

pub struct Request {
    pub path: String,
    pub upgrade: Option<Upgrade>,
    /// 60.20 C2 the lines of the captured header (parse_capture), in order; empty when none is captured
    pub fwd: Vec<Vec<u8>>,
}

pub struct Upgrade {
    pub accept: String,
    pub protocol: Option<String>,
}

pub enum Parsed {
    Partial,
    Bad,
    Done(Request, usize),
}

fn has_token(v: &[u8], token: &str) -> bool {
    std::str::from_utf8(v).map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))).unwrap_or(false)
}

#[cfg(test)]
pub fn parse(buf: &[u8]) -> Parsed {
    parse_capture(buf, None)
}

/// parse, also keeping every line of header `capture` (lowercase name, matched ASCII case-insensitively; 60.20 C2)
pub fn parse_capture(buf: &[u8], capture: Option<&str>) -> Parsed {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let n = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Parsed::Partial,
        Err(_) => return Parsed::Bad,
    };
    if req.method != Some("GET") || req.version != Some(1) {
        return Parsed::Bad;
    }
    let path = req.path.unwrap_or("/").to_string();
    let (mut up, mut conn, mut key, mut ver, mut proto) = (false, false, None, false, None);
    let mut fwd = Vec::new();
    for h in req.headers.iter() {
        let name = h.name;
        if capture.is_some_and(|c| name.eq_ignore_ascii_case(c)) {
            fwd.push(h.value.to_vec());
        }
        if name.eq_ignore_ascii_case("upgrade") {
            up |= has_token(h.value, "websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            conn |= has_token(h.value, "upgrade");
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            key = std::str::from_utf8(h.value).ok().map(|s| s.trim().to_string());
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            ver = h.value.trim_ascii() == b"13";
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            // Echo the first offered subprotocol, otherwise browsers abort the socket.
            proto = std::str::from_utf8(h.value).ok().and_then(|s| s.split(',').next()).map(|s| s.trim().to_string());
        }
    }
    let upgrade = match (up && conn && ver, key) {
        // RFC 6455 4.2.1: key is base64 of 16 bytes -> 24 chars ending in "=="
        (true, Some(k)) if k.len() == 24 && k.ends_with("==") => Some(Upgrade { accept: crate::ws::accept_key(&k), protocol: proto }),
        (true, _) => return Parsed::Bad,
        _ => None,
    };
    Parsed::Done(Request { path, upgrade, fwd }, n)
}

pub fn switching(out: &mut Vec<u8>, u: &Upgrade) {
    out.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    out.extend_from_slice(u.accept.as_bytes());
    if let Some(p) = &u.protocol {
        if !p.is_empty() {
            out.extend_from_slice(b"\r\nSec-WebSocket-Protocol: ");
            out.extend_from_slice(p.as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n\r\n");
}

pub fn simple(out: &mut Vec<u8>, status: &str, body: &str) {
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nServer: finalwisp\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn up(req: &str) -> Option<Upgrade> {
        match parse(req.as_bytes()) {
            Parsed::Done(r, _) => r.upgrade,
            _ => None,
        }
    }
    #[test]
    fn upgrade_rules() {
        let k = "dGhlIHNhbXBsZSBub25jZQ==";
        let ok = format!("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {k}\r\nSec-WebSocket-Version: 13\r\n\r\n");
        assert!(up(&ok).is_some());
        let split = format!("GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {k}\r\nSec-WebSocket-Version: 13\r\n\r\n");
        assert!(up(&split).is_some());
        assert!(matches!(parse(ok.replace("HTTP/1.1", "HTTP/1.0").as_bytes()), Parsed::Bad));
        assert!(matches!(parse(ok.replace(k, "short").as_bytes()), Parsed::Bad));
        let p = up(&ok.replace("\r\n\r\n", "\r\nSec-WebSocket-Protocol: wisp-v2, other\r\n\r\n")).unwrap();
        assert_eq!(p.protocol.as_deref(), Some("wisp-v2"));
    }

    #[test]
    fn capture_header_lines() {
        let req =
            "GET / HTTP/1.1\r\nX-Forwarded-For: 1.1.1.1\r\nHost: x\r\nx-forwarded-FOR: 2.2.2.2, 3.3.3.3\r\nX-Real-IP: 9.9.9.9\r\n\r\n";
        let Parsed::Done(r, _) = parse_capture(req.as_bytes(), Some("x-forwarded-for")) else { panic!() };
        assert_eq!(r.fwd, vec![b"1.1.1.1".to_vec(), b"2.2.2.2, 3.3.3.3".to_vec()], "every line, in order, any case");
        let Parsed::Done(r, _) = parse(req.as_bytes()) else { panic!() };
        assert!(r.fwd.is_empty(), "nothing captured without a name");
        let Parsed::Done(r, _) = parse_capture(req.as_bytes(), Some("cf-connecting-ip")) else { panic!() };
        assert!(r.fwd.is_empty());
    }
}
