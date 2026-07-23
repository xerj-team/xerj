//! PDF text extraction — a self-contained content-stream scanner (no
//! external PDF crate: the workspace release profile is panic=abort, so a
//! panicky dependency would take the whole process down; this scanner is
//! Result-only by construction).
//!
//! Strategy: locate `stream…endstream` ranges, peel the stream filter chain
//! (ASCII85 / ASCIIHex over Flate, or Flate alone) via `decoded_content`,
//! (or use raw bodies that already look like content streams), then scan for
//! text-showing operators: `(…) Tj`, `(…) '`, `[…] TJ`, with PDF string
//! escapes and hex strings. Newlines derive from Td/TD/T*/ET ops. `/Title`
//! is pulled from the document info dictionary when present.

use super::{emit_document, ExtractStats, Sink};
use anyhow::Result;
use std::io::Read;
use std::path::Path;

const PDF_CAP: u64 = 512 << 20;
const STREAM_INFLATE_CAP: u64 = 64 << 20;

pub fn extract(path: &Path, sink: Sink) -> Result<ExtractStats> {
    let mut stats = ExtractStats::default();
    let size = std::fs::metadata(path)?.len();
    if size > PDF_CAP {
        stats.junk += 1;
        return Ok(stats);
    }
    let bytes = std::fs::read(path)?;
    let mut text = String::new();
    for body in stream_bodies(&bytes) {
        if let Some(content) = decoded_content(body) {
            scan_text_ops(&content, &mut text);
        }
    }
    let title = doc_title(&bytes).unwrap_or_else(|| {
        text.lines()
            .find(|l| !l.trim().is_empty())
            .map(|l| l.trim().chars().take(200).collect())
            .unwrap_or_else(|| {
                path.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "untitled".into())
            })
    });
    let body = text.trim();
    if body.is_empty() {
        stats.junk += 1;
        return Ok(stats);
    }
    emit_document(&title, &[], body, sink, &mut stats);
    Ok(stats)
}

fn stream_bodies(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(p) = find(bytes, i, b"stream") {
        // must be the keyword, not part of "endstream"
        let word_ok = p == 0 || !bytes[p - 1].is_ascii_alphanumeric();
        let mut start = p + b"stream".len();
        if start < bytes.len() && bytes[start] == b'\r' {
            start += 1;
        }
        if start < bytes.len() && bytes[start] == b'\n' {
            start += 1;
        }
        match find(bytes, start, b"endstream") {
            Some(e) if word_ok => {
                out.push(&bytes[start..e]);
                i = e + b"endstream".len();
            }
            Some(e) => {
                i = e + b"endstream".len();
            }
            None => break,
        }
    }
    out
}

fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    memchr::memmem::find(&hay[from..], needle).map(|p| p + from)
}

fn inflate(body: &[u8]) -> Option<Vec<u8>> {
    let mut d = flate2::read::ZlibDecoder::new(body).take(STREAM_INFLATE_CAP);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok()?;
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Peel a stream's filter chain and return decoded bytes that look like a PDF
/// content stream, or `None`.
///
/// The stream we scanned may be wrapped in `ASCII85Decode` or `ASCIIHexDecode`
/// *before* `FlateDecode` — reportlab and many programmatic PDF generators emit
/// `/Filter [ /ASCII85Decode /FlateDecode ]`. The old code only tried Flate (or
/// raw), so those PDFs decoded to gibberish, failed the content check, and were
/// silently dropped — while Word/LibreOffice PDFs (Flate-only) worked. Rather
/// than parse the object graph to read each stream's exact `/Filter`, try the
/// small set of real-world chains cheapest-first and accept the first result
/// that actually contains text operators. All decoders are allocation-bounded
/// and panic-free (the workspace is `panic = "abort"`, so a panicky PDF crate
/// is not an option — this stays dependency-free by design).
fn decoded_content(body: &[u8]) -> Option<Vec<u8>> {
    // 1. FlateDecode only (Word / LibreOffice / most exporters).
    if let Some(d) = inflate(body) {
        if looks_like_content(&d) {
            return Some(d);
        }
    }
    // 2. Uncompressed content stream.
    if looks_like_content(body) {
        return Some(body.to_vec());
    }
    // 3. ASCII85, optionally over Flate (reportlab, ReportLab-based tools).
    if let Some(a) = ascii85_decode(body) {
        if let Some(d) = inflate(&a) {
            if looks_like_content(&d) {
                return Some(d);
            }
        }
        if looks_like_content(&a) {
            return Some(a);
        }
    }
    // 4. ASCIIHex, optionally over Flate.
    if let Some(h) = asciihex_decode(body) {
        if let Some(d) = inflate(&h) {
            if looks_like_content(&d) {
                return Some(d);
            }
        }
        if looks_like_content(&h) {
            return Some(h);
        }
    }
    None
}

/// PDF `ASCII85Decode`. Whitespace is ignored, `z` is shorthand for four zero
/// bytes, `~>` terminates. Returns `None` on any byte outside the alphabet, so
/// binary (Flate) or ASCII-hex bodies fall through to another branch rather
/// than decode to garbage.
fn ascii85_decode(input: &[u8]) -> Option<Vec<u8>> {
    let data = input.strip_prefix(b"<~").unwrap_or(input);
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut n = 0usize;
    let mut saw = false;
    // Cap output like the inflate path so a hostile stream can't balloon memory.
    let cap = STREAM_INFLATE_CAP as usize;
    for &b in data {
        match b {
            b'~' => break, // `~>` end-of-data
            b'z' if n == 0 => {
                out.extend_from_slice(&[0, 0, 0, 0]);
                saw = true;
            }
            b'!'..=b'u' => {
                group[n] = b - b'!';
                n += 1;
                saw = true;
                if n == 5 {
                    let mut val: u32 = 0;
                    for &g in &group {
                        val = val.checked_mul(85)?.checked_add(g as u32)?;
                    }
                    out.extend_from_slice(&val.to_be_bytes());
                    n = 0;
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0 => {}
            _ => return None,
        }
        if out.len() > cap {
            return None;
        }
    }
    if n > 0 {
        // Final partial group: pad the missing places with the max digit (`u`),
        // then emit `n - 1` bytes.
        for g in group.iter_mut().skip(n) {
            *g = 84;
        }
        let mut val: u32 = 0;
        for &g in &group {
            val = val.checked_mul(85)?.checked_add(g as u32)?;
        }
        out.extend_from_slice(&val.to_be_bytes()[..n - 1]);
    }
    (saw && !out.is_empty()).then_some(out)
}

/// PDF `ASCIIHexDecode`. Whitespace ignored, `>` terminates, a trailing odd
/// nibble is padded with 0. Any non-hex, non-whitespace byte returns `None`.
fn asciihex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut hi: Option<u8> = None;
    let mut saw = false;
    for &b in input {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b'>' => break,
            b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0 => continue,
            _ => return None,
        };
        saw = true;
        match hi.take() {
            None => hi = Some(v),
            Some(h) => out.push((h << 4) | v),
        }
    }
    if let Some(h) = hi {
        out.push(h << 4);
    }
    (saw && !out.is_empty()).then_some(out)
}

fn looks_like_content(b: &[u8]) -> bool {
    let head = &b[..b.len().min(4096)];
    memchr::memmem::find(head, b"BT").is_some()
        || memchr::memmem::find(head, b"Tj").is_some()
        || memchr::memmem::find(head, b"TJ").is_some()
}

/// PDFDocEncoding ≈ latin-1 for the printable range — good enough for
/// generated PDFs; unknown bytes are passed through as latin-1.
fn scan_text_ops(content: &[u8], out: &mut String) {
    let mut i = 0usize;
    let mut pending: Vec<String> = Vec::new(); // strings awaiting an operator
    let mut line = String::new();
    let flush_line = |line: &mut String, out: &mut String| {
        let t = line.trim();
        if !t.is_empty() {
            out.push_str(t);
            out.push('\n');
        }
        line.clear();
    };
    while i < content.len() {
        match content[i] {
            b'(' => {
                let (s, ni) = parse_literal_string(content, i);
                pending.push(s);
                i = ni;
            }
            b'<' if i + 1 < content.len() && content[i + 1] != b'<' => {
                let (s, ni) = parse_hex_string(content, i);
                pending.push(s);
                i = ni;
            }
            b'[' => {
                // TJ array: collect strings until ]
                let mut j = i + 1;
                let mut parts: Vec<String> = Vec::new();
                while j < content.len() && content[j] != b']' {
                    match content[j] {
                        b'(' => {
                            let (s, nj) = parse_literal_string(content, j);
                            parts.push(s);
                            j = nj;
                        }
                        b'<' => {
                            let (s, nj) = parse_hex_string(content, j);
                            parts.push(s);
                            j = nj;
                        }
                        _ => j += 1,
                    }
                }
                pending.push(parts.join(""));
                i = j + 1;
            }
            b'%' => {
                // comment to EOL
                i = memchr::memchr(b'\n', &content[i..])
                    .map(|p| i + p + 1)
                    .unwrap_or(content.len());
            }
            c if c.is_ascii_alphabetic() || c == b'\'' || c == b'"' || c == b'*' => {
                let start = i;
                while i < content.len()
                    && (content[i].is_ascii_alphanumeric()
                        || matches!(content[i], b'\'' | b'"' | b'*'))
                {
                    i += 1;
                }
                let op = &content[start..i];
                match op {
                    b"Tj" | b"TJ" | b"'" | b"\"" => {
                        for s in pending.drain(..) {
                            if !line.is_empty() && !line.ends_with(' ') {
                                line.push(' ');
                            }
                            line.push_str(&s);
                        }
                        if op == b"'" || op == b"\"" {
                            flush_line(&mut line, out);
                        }
                    }
                    b"Td" | b"TD" | b"T*" | b"ET" => {
                        pending.clear();
                        flush_line(&mut line, out);
                    }
                    b"BT" => {
                        pending.clear();
                    }
                    _ => {
                        pending.clear();
                    }
                }
            }
            _ => i += 1,
        }
        if out.len() > 32 << 20 {
            break; // hard safety cap
        }
    }
    flush_line(&mut line, out);
}

fn parse_literal_string(b: &[u8], open: usize) -> (String, usize) {
    let mut s = String::new();
    let mut i = open + 1;
    let mut depth = 1usize;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => {
                let c = b[i + 1];
                match c {
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    b'(' => s.push('('),
                    b')' => s.push(')'),
                    b'\\' => s.push('\\'),
                    b'0'..=b'7' => {
                        // up to 3 octal digits
                        let mut v = 0u32;
                        let mut n = 0;
                        while n < 3 && i + 1 + n < b.len() && (b'0'..=b'7').contains(&b[i + 1 + n])
                        {
                            v = v * 8 + (b[i + 1 + n] - b'0') as u32;
                            n += 1;
                        }
                        if let Some(ch) = char::from_u32(v) {
                            s.push(ch);
                        }
                        i += n + 1;
                        continue;
                    }
                    b'\n' => {} // line continuation
                    other => s.push(other as char),
                }
                i += 2;
            }
            b'(' => {
                depth += 1;
                s.push('(');
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return (s, i + 1);
                }
                s.push(')');
                i += 1;
            }
            c => {
                s.push(c as char); // latin-1 passthrough
                i += 1;
            }
        }
        if s.len() > 1 << 20 {
            break;
        }
    }
    (s, i)
}

fn parse_hex_string(b: &[u8], open: usize) -> (String, usize) {
    let mut i = open + 1;
    let mut nibbles: Vec<u8> = Vec::new();
    while i < b.len() && b[i] != b'>' {
        let c = b[i];
        if c.is_ascii_hexdigit() {
            nibbles.push(c);
        }
        i += 1;
        if nibbles.len() > 1 << 20 {
            break;
        }
    }
    if nibbles.len() % 2 == 1 {
        nibbles.push(b'0');
    }
    let mut s = String::new();
    for pair in nibbles.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap_or(0);
        let lo = (pair[1] as char).to_digit(16).unwrap_or(0);
        if let Some(ch) = char::from_u32(hi * 16 + lo) {
            s.push(ch);
        }
    }
    (s, i + 1)
}

fn doc_title(bytes: &[u8]) -> Option<String> {
    let p = memchr::memmem::find(bytes, b"/Title")?;
    let after = &bytes[p + 6..(p + 4096).min(bytes.len())];
    let start = after.iter().position(|&c| !c.is_ascii_whitespace())?;
    match after[start] {
        b'(' => {
            let (s, _) = parse_literal_string(after, start);
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        b'<' => {
            let (s, _) = parse_hex_string(after, start);
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn ascii85_round_trip() {
        // base64.a85encode(b"PDF text sample 123")
        let dec = ascii85_decode(b":ddbqFCf]=+ELt.E,9).0etN").expect("a85");
        assert_eq!(dec, b"PDF text sample 123");
    }

    #[test]
    fn ascii85_ignores_whitespace_and_terminator() {
        let dec = ascii85_decode(b":ddbq FCf]=\n+ELt.E,9).0etN~>trailing").expect("a85");
        assert_eq!(dec, b"PDF text sample 123");
    }

    #[test]
    fn ascii85_z_shorthand_is_four_zeros() {
        assert_eq!(ascii85_decode(b"z").unwrap(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn ascii85_rejects_binary() {
        // A Flate/zlib header is not valid ASCII85 — must return None so the
        // cascade falls through to inflate() instead of decoding garbage.
        assert!(ascii85_decode(&[0x78, 0x9c, 0xff, 0x00, 0x13]).is_none());
    }

    #[test]
    fn asciihex_round_trip() {
        let dec = asciihex_decode(b"425420312030203020312037322037323020546D>").unwrap();
        assert_eq!(dec, b"BT 1 0 0 1 72 720 Tm");
    }

    #[test]
    fn asciihex_odd_nibble_padded() {
        assert_eq!(asciihex_decode(b"4>").unwrap(), vec![0x40]);
    }

    /// The regression that started this: a content stream compressed with
    /// Flate and wrapped in ASCII85 — the `/Filter [/ASCII85Decode /FlateDecode]`
    /// chain reportlab emits. The old scanner only tried Flate, so this decoded
    /// to gibberish and the whole PDF was silently dropped as junk.
    #[test]
    fn ascii85_over_flate_yields_content() {
        // base64.a85encode(zlib.compress(b"BT ... (Hello from a compressed PDF stream) Tj ... ET")) + b"~>"
        let body: &[u8] = &[71,97,114,103,94,59,40,116,115,39,33,40,39,36,86,70,33,68,101,95,58,94,71,48,67,100,45,115,84,78,97,105,82,85,84,47,39,63,49,60,56,53,114,46,42,99,82,103,80,59,47,77,57,100,109,59,36,95,44,92,59,94,97,55,73,56,107,109,79,91,60,33,94,84,68,35,103,108,79,104,37,48,54,72,34,111,43,76,48,126,62];
        let content = decoded_content(body).expect("must decode the ASCII85+Flate chain");
        let s = String::from_utf8_lossy(&content);
        assert!(s.contains("Hello from a compressed PDF stream"), "got: {s}");
        assert!(s.contains("Tj"), "must contain text-showing operator");
    }

    #[test]
    fn plain_flate_still_works() {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"BT (word doc style) Tj ET").unwrap();
        let flated = enc.finish().unwrap();
        let content = decoded_content(&flated).expect("flate-only must still decode");
        assert!(String::from_utf8_lossy(&content).contains("word doc style"));
    }
}
