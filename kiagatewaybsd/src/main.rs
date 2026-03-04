#![forbid(unsafe_code)]
use std::{collections::HashMap, sync::Arc, time::Duration};
use std::time::SystemTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use uuid::Uuid;
use pledge::pledge_promises;
use unveil::unveil;

const MAX_HTTP_HEADERS: usize = 32 * 1024;
const MAX_TLS_INITIAL: usize = 32 * 1024;
const MAX_TLS_RECORDS_TO_SCAN: usize = 8;
const READ_CHUNK: usize = 1024;
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_CLIENTHELLO_READ_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[derive(Clone, Copy)]
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self { Self { b, i: 0 } }

    fn rem(&self) -> usize { self.b.len().saturating_sub(self.i) }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.i.checked_add(n)? > self.b.len() { return None; }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(((s[0] as u16) << 8) | (s[1] as u16))
    }

    fn u24_usize(&mut self) -> Option<usize> {
        let s = self.take(3)?;
        Some(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | (s[2] as usize))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn write_http_error(mut client: TcpStream, resp: &[u8]) -> std::io::Result<()> {
    client.write_all(resp).await
}

async fn handle_http(
    mut client: TcpStream,
    config: Arc<Config>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; READ_CHUNK];

    let header_end: Option<usize> = timeout(HTTP_HEADER_READ_TIMEOUT, async {
        loop {
            match client.read(&mut tmp).await {
                Ok(0) => return None,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > MAX_HTTP_HEADERS {
                        return Some(usize::MAX);
                    }
                    if let Some(pos) = find_http_header_end(&buf) {
                        return Some(pos);
                    }
                }
                Err(_) => return None,
            }
        }
    })
    .await
    .unwrap_or(None);

    let Some(end_pos) = header_end else {
        let _ = write_http_error(client, b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n").await;
        return Ok(());
    };

    if end_pos == usize::MAX {
        let _ = write_http_error(client, b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n").await;
        return Ok(());
    }

    let header_part_end = end_pos + 4;
    let (header_part, rest) = buf.split_at(header_part_end);

    let host = match extract_host(header_part) {
        Some(h) => h,
        None => {
            let _ = write_http_error(client, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await;
            return Ok(());
        }
    };

    let backend_addr = match config.http_backends.get(&host) {
        Some(addr) => addr.clone(),
        None => {
            let _ = write_http_error(client, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n").await;
            return Ok(());
        }
    };

    let mut backend = match timeout(BACKEND_CONNECT_TIMEOUT, TcpStream::connect(&backend_addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            let _ = write_http_error(client, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n").await;
            return Ok(());
        }
    };

    backend.write_all(header_part).await?;

    if !rest.is_empty() {
        backend.write_all(rest).await?;
    }

    let _ = timeout(PROXY_IDLE_TIMEOUT, async {
        let _ = copy_bidirectional(&mut client, &mut backend).await;
    })
    .await;

    Ok(())
}

async fn handle_https(
    mut client: TcpStream,
    config: Arc<Config>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; READ_CHUNK];

    let sni: Option<String> = timeout(TLS_CLIENTHELLO_READ_TIMEOUT, async {
        loop {
            match client.read(&mut tmp).await {
                Ok(0) => return None,
                Ok(n) => {
                    if buf.len() + n > MAX_TLS_INITIAL {
                        return None;
                    }
                    buf.extend_from_slice(&tmp[..n]);

                    if let Some(sni) = extract_sni(&buf) {
                        return Some(sni);
                    }

                    if buf.len() >= MAX_TLS_INITIAL {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    })
    .await
    .unwrap_or(None);

    let Some(sni) = sni else {
        return Ok(());
    };

    let backend_addr = match config.https_backends.get(&sni) {
        Some(addr) => addr.clone(),
        None => return Ok(()),
    };

    let mut backend = match timeout(BACKEND_CONNECT_TIMEOUT, TcpStream::connect(&backend_addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(()),
    };

    backend.write_all(&buf).await?;

    let _ = timeout(PROXY_IDLE_TIMEOUT, async {
        let _ = copy_bidirectional(&mut client, &mut backend).await;
    })
    .await;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Config {
    https_backends: HashMap<String, String>,
    http_backends: HashMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    pledge_promises![Stdio Inet Rpath Getpw Unveil].unwrap();

    let config_path = std::env::args().nth(1).unwrap_or_else(|| "servers.toml".to_string());
    unveil(&config_path, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();
    let srversstr = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            println!("Unable to open config {} due to error: {e}", &config_path);
            std::process::exit(1);
        }
    };
    let config: Config = toml::from_str(&srversstr)?;
    let config = Arc::new(config);
    let printcfg = srversstr.replace("\n", " ");
    let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);

    println!("{ts} <-> kiagateway >>> service starting: HTTP (Host header inspection) on port 80, HTTPS (SNI inspection) on port 443");
    println!("{ts} <-> kiagateway >>> service config loaded: {}", printcfg);

    let http = TcpListener::bind("0.0.0.0:80").await?;
    let config_http = config.clone();

    tokio::spawn(async move {
        loop {
            match http.accept().await {
                Ok((socket, addr)) => {
                    let cfg = config_http.clone();
                    let txid = Uuid::new_v4().to_string();
                    tokio::spawn(async move {
                        if let Err(e) = handle_http(socket, cfg).await {
                            let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                            println!("{ts} - {txid} - kiagateway >>> HTTP ERROR {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    let txid = Uuid::new_v4().to_string();
                    let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                    println!("{ts} - {txid} - kiagateway >>> HTTP accept ERROR: {}", e);
                }
            }
        }
    });

    let https = TcpListener::bind("0.0.0.0:443").await?;
    let config_https = config.clone();

    loop {
        match https.accept().await {
            Ok((socket, addr)) => {
                let cfg = config_https.clone();
                let txid = Uuid::new_v4().to_string();
                tokio::spawn(async move {
                    if let Err(e) = handle_https(socket, cfg).await {
                        let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                        println!("{ts} - {txid} - kiagateway >>> HTTPS ERROR {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                let txid = Uuid::new_v4().to_string();
                let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                println!("{ts} - {txid} - kiagateway >>> HTTPS accept ERROR: {}", e);
            }
        }
    }
}

fn is_valid_http_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 { return false; }
    if host.bytes().any(|c| c <= 0x20 || c == 0x7f) { return false; }
    let h = host.strip_suffix('.').unwrap_or(host);

    if h.starts_with('[') {
        if !h.ends_with(']') { return false; }
        let inner = &h[1..h.len()-1];
        if inner.is_empty() || inner.len() > 100 { return false; }
        return inner.bytes().all(|c| {
            matches!(c,
                b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' |
                b':' | b'.'
            )
        });
    }

    h.bytes().all(|c| matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-'))
}

fn parse_host_value(raw: &str) -> Option<String> {
    let mut v = raw.trim();
    if v.is_empty() { return None; }
    if v.bytes().any(|c| c <= 0x20 || c == 0x7f) { return None; }

    if let Some(rest) = v.strip_prefix('[') {
        let end = rest.find(']')?;
        let host_inner = &rest[..end];
        let after = &rest[end+1..];
        let host = format!("[{}]", host_inner);

        if !after.is_empty() {
            let after = after.trim();
            if let Some(port) = after.strip_prefix(':') {
                if port.parse::<u16>().is_err() { return None; }
            } else {
                return None;
            }
        }
        let host_lc = host.to_ascii_lowercase();
        if is_valid_http_host(&host_lc) { Some(host_lc) } else { None }
    } else {
        if let Some(pos) = v.rfind(':') {
            if v[..pos].contains(':') {
                return None;
            }
            let (h, p) = v.split_at(pos);
            let p = &p[1..];
            if !p.is_empty() {
                if p.parse::<u16>().is_ok() {
                    v = h;
                } else {
                    return None;
                }
            }
        }

        let host_lc = v.to_ascii_lowercase();
        if is_valid_http_host(&host_lc) { Some(host_lc) } else { None }
    }
}

fn extract_host(headers: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(headers).ok()?;
    let mut found: Option<String> = None;

    for line in text.split("\r\n") {
        if line.len() >= 5 && line.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            if found.is_some() {
                return None;
            }
            let val = line[5..].trim();
            found = parse_host_value(val);
            found.as_ref()?;
        }
    }
    found
}

fn is_valid_sni(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 { return false; }
    if s.bytes().any(|c| c <= 0x20 || c == 0x7f) { return false; }
    let h = s.strip_suffix('.').unwrap_or(s);
    h.bytes().all(|c| matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-'))
}

fn extract_sni_from_clienthello_handshake(handshake_msg: &[u8]) -> Option<String> {
    let mut c = Cur::new(handshake_msg);
    let msg_type = c.u8()?;
    if msg_type != 0x01 { return None; }
    let hlen = c.u24_usize()?;
    if c.rem() < hlen { return None; }
    let body = c.take(hlen)?;
    let mut ch = Cur::new(body);
    ch.skip(2 + 32)?;
    let sid_len = ch.u8()? as usize;
    ch.skip(sid_len)?;
    let cs_len = ch.u16()? as usize;
    ch.skip(cs_len)?;
    let comp_len = ch.u8()? as usize;
    ch.skip(comp_len)?;
    if ch.rem() < 2 { return None; }
    let exts_len = ch.u16()? as usize;
    if ch.rem() < exts_len { return None; }
    let exts = ch.take(exts_len)?;
    let mut ex = Cur::new(exts);

    while ex.rem() >= 4 {
        let ext_type = ex.u16()?;
        let ext_len = ex.u16()? as usize;
        if ex.rem() < ext_len { return None; }
        let ext_data = ex.take(ext_len)?;

        if ext_type == 0 {
            let mut sn = Cur::new(ext_data);
            let list_len = sn.u16()? as usize;
            if sn.rem() < list_len { return None; }
            let list = sn.take(list_len)?;
            let mut li = Cur::new(list);

            while li.rem() >= 3 {
                let name_type = li.u8()?;
                let name_len = li.u16()? as usize;
                if li.rem() < name_len { return None; }
                let name_bytes = li.take(name_len)?;

                if name_type == 0 {
                    let name_str = std::str::from_utf8(name_bytes).ok()?;
                    let name_lc = name_str.to_ascii_lowercase();
                    if is_valid_sni(&name_lc) {
                        return Some(name_lc);
                    } else {
                        return None;
                    }
                }
            }
            return None;
        }
    }

    None
}

fn extract_sni(data: &[u8]) -> Option<String> {
    let mut i = 0usize;
    let mut records_seen = 0usize;
    let mut hs_accum: Vec<u8> = Vec::with_capacity(4096);

    while i + 5 <= data.len() && records_seen < MAX_TLS_RECORDS_TO_SCAN {
        let content_type = data[i];
        let _ver = &data[i+1..i+3];
        let rlen = ((data[i+3] as usize) << 8) | (data[i+4] as usize);
        i += 5;
        if i.checked_add(rlen)? > data.len() {
            return None;
        }
        let payload = &data[i..i + rlen];
        i += rlen;
        records_seen += 1;

        if content_type != 0x16 {
            continue;
        }

        if hs_accum.len().checked_add(payload.len())? > MAX_TLS_INITIAL {
            return None;
        }
        hs_accum.extend_from_slice(payload);

        if hs_accum.len() < 4 {
            continue;
        }
        if hs_accum[0] != 0x01 {
            return None;
        }
        let hlen = ((hs_accum[1] as usize) << 16) | ((hs_accum[2] as usize) << 8) | (hs_accum[3] as usize);
        let total = 4usize.checked_add(hlen)?;
        if hs_accum.len() < total {
            continue;
        }

        return extract_sni_from_clienthello_handshake(&hs_accum[..total]);
    }

    None
}
