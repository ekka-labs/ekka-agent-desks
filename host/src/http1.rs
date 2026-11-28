//! A small HTTP/1.1 client half: one request, one response, `Connection: close`. Used over Docker's Unix socket
//! and over TLS for downloads. Bodies are read as the server frames them (length, chunked, or to the end) and every
//! size is capped, so a hostile or broken peer cannot make this read without end.

use std::io::{self, BufRead, Read, Write};

use crate::error::{failed, Result};

const MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;

pub struct Response<R: BufRead> {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: Body<R>,
}

impl<R: BufRead> Response<R> {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The whole body, at most `max` bytes.
    pub fn bytes(mut self, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        (&mut self.body)
            .take(max as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|e| failed(format!("reading an answer: {e}")))?;
        if out.len() > max {
            return Err(failed(format!("an answer was larger than {max} bytes")));
        }
        Ok(out)
    }
}

pub fn write_request(
    w: &mut impl Write,
    method: &str,
    target: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn line(r: &mut impl BufRead) -> Result<String> {
    let mut buf = Vec::new();
    r.take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf).map_err(|e| failed(format!("reading an answer: {e}")))?;
    if buf.len() > MAX_LINE {
        return Err(failed("an answer's header line was too long"));
    }
    if !buf.ends_with(b"\n") {
        return Err(failed("an answer ended before its headers did"));
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| failed("an answer's header was not text"))
}

pub fn read_response<R: BufRead>(mut r: R) -> Result<Response<R>> {
    let status_line = line(&mut r)?;
    let mut parts = status_line.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        return Err(failed("an answer had no status line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(failed("an answer was not HTTP/1"));
    }
    let status: u16 = code.parse().map_err(|_| failed("an answer's status was not a number"))?;
    let mut headers = Vec::new();
    loop {
        let l = line(&mut r)?;
        if l.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(failed("an answer had too many headers"));
        }
        let (k, v) = l.split_once(':').ok_or_else(|| failed("an answer had a malformed header"))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let find = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
    let body = if find("Transfer-Encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        Body::Chunked { inner: r, left: 0, done: false }
    } else if let Some(n) = find("Content-Length") {
        let n: u64 = n.parse().map_err(|_| failed("an answer's length was not a number"))?;
        Body::Length(r.take(n))
    } else if status == 204 || status == 304 {
        Body::Length(r.take(0))
    } else {
        Body::Eof(r)
    };
    Ok(Response { status, headers, body })
}

pub enum Body<R: BufRead> {
    Length(io::Take<R>),
    Chunked { inner: R, left: u64, done: bool },
    Eof(R),
}

impl<R: BufRead> Read for Body<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::Length(t) => t.read(buf),
            Body::Eof(r) => r.read(buf),
            Body::Chunked { inner, left, done } => {
                if *done || buf.is_empty() {
                    return Ok(0);
                }
                if *left == 0 {
                    let size = chunk_size(inner)?;
                    if size == 0 {
                        // Trailers, then the empty line.
                        loop {
                            let l = line(inner).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.reason))?;
                            if l.is_empty() {
                                break;
                            }
                        }
                        *done = true;
                        return Ok(0);
                    }
                    *left = size;
                }
                let want = buf.len().min(*left as usize);
                let n = inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "a chunk ended early"));
                }
                *left -= n as u64;
                if *left == 0 {
                    let mut crlf = [0u8; 2];
                    inner.read_exact(&mut crlf)?;
                    if &crlf != b"\r\n" {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "a chunk did not end with CRLF"));
                    }
                }
                Ok(n)
            }
        }
    }
}

fn chunk_size(r: &mut impl BufRead) -> io::Result<u64> {
    let l = line(r).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.reason))?;
    let hex = l.split(';').next().unwrap_or("").trim();
    if hex.is_empty() || hex.len() > 15 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "a chunk size was not a number"));
    }
    u64::from_str_radix(hex, 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a chunk size was not hex"))
}

/// `s` with every byte outside the unreserved set percent-encoded, for a query value.
pub fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_chunked_answer_is_read_whole_and_a_length_is_honoured() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: b\r\n\r\n4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nT: 1\r\n\r\n";
        let r = read_response(Cursor::new(&raw[..])).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("x-a"), Some("b"));
        assert_eq!(r.bytes(100).unwrap(), b"Wikipedia");
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\nabcdef";
        assert_eq!(read_response(Cursor::new(&raw[..])).unwrap().bytes(10).unwrap(), b"abc");
    }

    #[test]
    fn an_answer_over_its_cap_is_refused() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        assert!(read_response(Cursor::new(&raw[..])).unwrap().bytes(5).is_err());
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWikiXX";
        assert!(read_response(Cursor::new(&raw[..])).unwrap().bytes(100).is_err(), "a broken chunk is an error");
    }

    #[test]
    fn query_values_are_escaped() {
        assert_eq!(query_escape("{\"a\":\"b c\"}"), "%7B%22a%22%3A%22b%20c%22%7D");
        assert_eq!(query_escape("linux/arm64"), "linux%2Farm64");
    }
}
