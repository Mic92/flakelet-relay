//! Server-sent events: encoder for the relay, line parser for push.

use crate::proto::Event;

#[must_use]
pub fn encode(ev: &Event) -> String {
    let data = serde_json::to_string(ev).expect("event is serializable");
    format!("event: {}\ndata: {data}\n\n", ev.name())
}

/// Feed bytes, get complete events. `data:` is JSON with a `type` field
/// matching `event:`, so the parser only needs `data`.
#[derive(Default)]
pub struct Parser {
    buf: String,
    data: String,
}

impl Parser {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buf.push_str(&String::from_utf8_lossy(chunk));
        let mut out = Vec::new();
        while let Some(nl) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=nl).collect();
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if !self.data.is_empty() {
                    if let Ok(ev) = serde_json::from_str(&self.data) {
                        out.push(ev);
                    }
                    self.data.clear();
                }
            } else if let Some(d) = line.strip_prefix("data:") {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(d.strip_prefix(' ').unwrap_or(d));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_split_across_chunks() {
        let first = encode(&Event::Progress {
            target: "eve/x".into(),
        });
        let second = encode(&Event::Wave { index: 1 });
        let all = format!("{first}: comment\n\n{second}");
        let (head, tail) = all.as_bytes().split_at(7);
        let mut parser = Parser::default();
        let mut evs = parser.push(head);
        evs.extend(parser.push(tail));
        assert_eq!(evs.len(), 2);
        assert!(matches!(evs[0], Event::Progress { .. }));
        assert!(matches!(evs[1], Event::Wave { index: 1 }));
    }
}
