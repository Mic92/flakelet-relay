//! SRV lookup through the system resolver (`res_query` from libresolv,
//! present on glibc, musl and macOS) with a small parser for the answer.

use std::ffi::{CString, c_char, c_int};
use std::time::Duration;

use crate::client::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub ttl: u32,
}

pub const SERVICE: &str = "_flakelet-relay._tcp";
const CLASS_IN: c_int = 1;
const TYPE_SRV: c_int = 33;

#[link(name = "resolv")]
unsafe extern "C" {
    #[cfg_attr(target_vendor = "apple", link_name = "res_9_query")]
    fn res_query(
        dname: *const c_char,
        class: c_int,
        ty: c_int,
        answer: *mut u8,
        anslen: c_int,
    ) -> c_int;
}

/// Relay URLs for `domain` ordered by priority, then weight descending,
/// and the smallest TTL seen (for re-resolving).
pub async fn relays(domain: &str) -> Result<(Vec<Url>, Duration), String> {
    let name = format!("{SERVICE}.{domain}");
    let mut records = lookup(&name).await?;
    records.sort_by(|a, b| (a.priority, b.weight).cmp(&(b.priority, a.weight)));
    let ttl = records.iter().map(|r| r.ttl).min().unwrap_or(60);
    let urls = records
        .into_iter()
        .map(|r| Url {
            host: r.target,
            port: r.port,
            path: String::new(),
        })
        .collect();
    Ok((urls, Duration::from_secs(ttl.into())))
}

pub async fn lookup(name: &str) -> Result<Vec<Record>, String> {
    let cname = CString::new(name).map_err(|_| format!("bad DNS name {name}"))?;
    let owned = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 65536];
        let cap = c_int::try_from(buf.len()).expect("fits");
        // SAFETY: cname is NUL-terminated and outlives the call, buf is
        // writable for cap bytes, res_query writes at most anslen bytes.
        let n = unsafe { res_query(cname.as_ptr(), CLASS_IN, TYPE_SRV, buf.as_mut_ptr(), cap) };
        let n = usize::try_from(n).map_err(|_| format!("SRV {owned}: lookup failed"))?;
        parse_response(&buf[..n.min(buf.len())]).map_err(|e| format!("SRV {owned}: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Read a possibly compressed name at `pos`, return it and the position
/// after it in the original stream.
fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos).ok_or("truncated name")? as usize;
        if len == 0 {
            return Ok((out, end.unwrap_or(pos + 1)));
        }
        if len & 0xC0 == 0xC0 {
            let lo = *msg.get(pos + 1).ok_or("truncated pointer")? as usize;
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3F) << 8) | lo;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len).ok_or("truncated label")?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        pos += 1 + len;
    }
    Err("name too long".into())
}

fn be16(msg: &[u8], pos: usize) -> Result<u16, String> {
    let b = msg.get(pos..pos + 2).ok_or("truncated")?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn parse_response(msg: &[u8]) -> Result<Vec<Record>, String> {
    if msg.len() < 12 {
        return Err("short response".into());
    }
    let flags = be16(msg, 2)?;
    if flags & 0x8000 == 0 {
        return Err("not a response".into());
    }
    match flags & 0x000F {
        0 => {}
        3 => return Err("NXDOMAIN".into()),
        rc => return Err(format!("rcode {rc}")),
    }
    let qd = be16(msg, 4)?;
    let an = be16(msg, 6)?;
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(msg, pos)?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        let (_, p) = read_name(msg, pos)?;
        let rtype = be16(msg, p)?;
        let ttl_b = msg.get(p + 4..p + 8).ok_or("truncated")?;
        let ttl = u32::from_be_bytes([ttl_b[0], ttl_b[1], ttl_b[2], ttl_b[3]]);
        let rdlen = be16(msg, p + 8)? as usize;
        let rdata = p + 10;
        if rtype == 33 {
            let (target, _) = read_name(msg, rdata + 6)?;
            out.push(Record {
                priority: be16(msg, rdata)?,
                weight: be16(msg, rdata + 2)?,
                port: be16(msg, rdata + 4)?,
                target,
                ttl,
            });
        }
        pos = rdata + rdlen;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Response with one SRV answer whose owner name is a pointer to the
    /// question and whose target uses a pointer for the domain suffix.
    #[test]
    fn parses_compressed_srv() {
        let mut m = Vec::new();
        m.extend_from_slice(&[0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        let qname: u8 = 12;
        for l in ["_x", "_tcp", "example", "org"] {
            m.push(u8::try_from(l.len()).unwrap());
            m.extend_from_slice(l.as_bytes());
        }
        let example = qname + 3 + 5; // offset of "example"
        m.push(0);
        m.extend_from_slice(&[0, 33, 0, 1]);
        // answer: name ptr, type, class, ttl, rdlen, prio, weight, port, target
        m.extend_from_slice(&[0xC0, qname, 0, 33, 0, 1, 0, 0, 1, 44]);
        let rdlen_at = m.len();
        m.extend_from_slice(&[0, 0, 0, 10, 0, 5, 0x1d, 0x13]);
        m.push(5);
        m.extend_from_slice(b"relay");
        m.extend_from_slice(&[0xC0, example]);
        let rdlen = u16::try_from(m.len() - rdlen_at - 2).unwrap();
        m[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
        let r = parse_response(&m).unwrap();
        assert_eq!(
            r,
            vec![Record {
                priority: 10,
                weight: 5,
                port: 7443,
                target: "relay.example.org".into(),
                ttl: 300
            }]
        );
        assert!(parse_response(&m[..11]).is_err());
    }
}
