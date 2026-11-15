//! Rich-note helpers (PRD §6.6 / §8.4): a small Markdown subset for `rich_text` blocks and the JSON
//! format of `table` blocks. Pure and allocation-light; input is untrusted, never executed, and never
//! logged.
//!
//! Markdown subset: `#`..`######` headings, `- `/`* ` bullets, `1. ` numbered items, and the inline
//! styles `**bold**`, `*italic*`, `_italic_` and `` `code` ``. Each non-empty line is one block; unclosed
//! markers stay literal. UIs render [`parse_markdown`] output and never reimplement the parsing.

use crate::error::{Error, Result};

/// Input above this size is not parsed (DoS guard); it is shown as one plain paragraph.
const MAX_MARKDOWN_BYTES: usize = 256 * 1024;
/// Table limits (rows, columns, bytes per cell).
pub const MAX_TABLE_ROWS: usize = 200;
/// Maximum columns of a table block.
pub const MAX_TABLE_COLS: usize = 20;
/// Maximum bytes of one table cell.
pub const MAX_TABLE_CELL_BYTES: usize = 4000;

/// Kind of a Markdown block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdBlockKind {
    /// Plain paragraph.
    Paragraph,
    /// Heading; `level` is 1..=6.
    Heading,
    /// Bullet list item.
    Bullet,
    /// Numbered list item; `level` is the number as typed.
    Numbered,
}

/// A run of text with one style combination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdSpan {
    /// Visible text (markers removed).
    pub text: String,
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Inline code.
    pub code: bool,
}

/// One parsed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdBlock {
    /// Block kind.
    pub kind: MdBlockKind,
    /// Heading level (1..=6) or list number; 0 otherwise.
    pub level: u32,
    /// Styled runs.
    pub spans: Vec<MdSpan>,
}

fn plain(text: &str) -> MdSpan {
    MdSpan {
        text: text.to_string(),
        bold: false,
        italic: false,
        code: false,
    }
}

/// If `rest` (just after an opening delimiter) holds a non-empty run closed by `close`, returns
/// `(inner, after_close)`.
fn take_until<'a>(rest: &'a str, close: &str) -> Option<(&'a str, &'a str)> {
    let end = rest.find(close)?;
    if end == 0 {
        return None;
    }
    Some((&rest[..end], &rest[end + close.len()..]))
}

fn flush(buf: &mut String, bold: bool, italic: bool, out: &mut Vec<MdSpan>) {
    if !buf.is_empty() {
        out.push(MdSpan {
            text: core::mem::take(buf),
            bold,
            italic,
            code: false,
        });
    }
}

fn inline(s: &str, bold: bool, italic: bool, out: &mut Vec<MdSpan>) {
    let mut buf = String::new();
    let mut rest = s;
    let mut prev: Option<char> = None;
    while let Some(c) = rest.chars().next() {
        let after_c = &rest[c.len_utf8()..];
        if rest.starts_with("**") {
            if let Some((inner, after)) = take_until(&rest[2..], "**") {
                flush(&mut buf, bold, italic, out);
                inline(inner, true, italic, out);
                rest = after;
                prev = Some('*');
                continue;
            }
            // Unclosed `**`: keep both markers literal so the second cannot open an italic run.
            buf.push_str("**");
            rest = rest.get(2..).unwrap_or_default();
            prev = Some('*');
            continue;
        } else if c == '`' {
            if let Some((inner, after)) = take_until(after_c, "`") {
                flush(&mut buf, bold, italic, out);
                out.push(MdSpan {
                    text: inner.to_string(),
                    bold,
                    italic,
                    code: true,
                });
                rest = after;
                prev = Some('`');
                continue;
            }
        } else if c == '*' || (c == '_' && !prev.is_some_and(char::is_alphanumeric)) {
            let mut delim = [0u8; 4];
            let delim: &str = c.encode_utf8(&mut delim);
            let tight = |inner: &str| {
                !inner.starts_with(char::is_whitespace) && !inner.ends_with(char::is_whitespace)
            };
            if let Some((inner, after)) = take_until(after_c, delim).filter(|(i, _)| tight(i)) {
                flush(&mut buf, bold, italic, out);
                inline(inner, bold, true, out);
                rest = after;
                prev = Some(c);
                continue;
            }
        }
        buf.push(c);
        prev = Some(c);
        rest = after_c;
    }
    flush(&mut buf, bold, italic, out);
}

fn parse_line(line: &str) -> Option<MdBlock> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    let hashes = t.chars().take_while(|&c| c == '#').count();
    let (kind, level, body) = if (1..=6).contains(&hashes) && t[hashes..].starts_with(' ') {
        (MdBlockKind::Heading, hashes as u32, t[hashes..].trim())
    } else if let Some(b) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")) {
        (MdBlockKind::Bullet, 0, b.trim())
    } else {
        let digits = t.chars().take_while(char::is_ascii_digit).count();
        match t[digits..].strip_prefix(". ") {
            Some(b) if (1..=9).contains(&digits) => (
                MdBlockKind::Numbered,
                t[..digits].parse().unwrap_or(1),
                b.trim(),
            ),
            _ => (MdBlockKind::Paragraph, 0, t),
        }
    };
    let mut spans = Vec::new();
    inline(body, false, false, &mut spans);
    Some(MdBlock { kind, level, spans })
}

/// Parse the Markdown subset into blocks. Never fails: anything unrecognised is plain text.
pub fn parse_markdown(text: &str) -> Vec<MdBlock> {
    if text.len() > MAX_MARKDOWN_BYTES {
        return Vec::from([MdBlock {
            kind: MdBlockKind::Paragraph,
            level: 0,
            spans: Vec::from([plain(text)]),
        }]);
    }
    text.lines().filter_map(parse_line).collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TableWire {
    rows: Vec<Vec<String>>,
}

fn normalize(mut rows: Vec<Vec<String>>) -> Result<Vec<Vec<String>>> {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    if rows.is_empty()
        || cols == 0
        || rows.len() > MAX_TABLE_ROWS
        || cols > MAX_TABLE_COLS
        || rows
            .iter()
            .flatten()
            .any(|c| c.len() > MAX_TABLE_CELL_BYTES)
    {
        return Err(Error::InvalidInput);
    }
    for r in &mut rows {
        r.resize(cols, String::new());
    }
    Ok(rows)
}

/// Parse a `table` block body (`{"rows":[["h1","h2"],["a","b"]]}`; the first row is the header).
/// Ragged rows are padded to a rectangle. Out-of-limit or malformed input is rejected.
pub fn parse_table(json: &str) -> Result<Vec<Vec<String>>> {
    let wire: TableWire = serde_json::from_str(json).map_err(|_| Error::Corrupted)?;
    normalize(wire.rows)
}

/// Serialize rows into a `table` block body, validating the limits.
pub fn serialize_table(rows: Vec<Vec<String>>) -> Result<String> {
    let rows = normalize(rows)?;
    serde_json::to_string(&TableWire { rows }).map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(text: &str, bold: bool, italic: bool, code: bool) -> MdSpan {
        MdSpan {
            text: text.into(),
            bold,
            italic,
            code,
        }
    }

    #[test]
    fn headings_lists_and_paragraphs() {
        let b = parse_markdown("# Title\n\n- one\n* two\n3. three\nplain\n#nospace");
        let kinds: Vec<_> = b.iter().map(|b| (b.kind, b.level)).collect();
        assert_eq!(
            kinds,
            [
                (MdBlockKind::Heading, 1),
                (MdBlockKind::Bullet, 0),
                (MdBlockKind::Bullet, 0),
                (MdBlockKind::Numbered, 3),
                (MdBlockKind::Paragraph, 0),
                (MdBlockKind::Paragraph, 0),
            ]
        );
        assert_eq!(b[5].spans, [span("#nospace", false, false, false)]);
        assert!(parse_markdown("####### seven")[0].kind == MdBlockKind::Paragraph);
    }

    #[test]
    fn inline_styles() {
        let b = parse_markdown("a **b** *c* _d_ `e*f` g");
        assert_eq!(
            b[0].spans,
            [
                span("a ", false, false, false),
                span("b", true, false, false),
                span(" ", false, false, false),
                span("c", false, true, false),
                span(" ", false, false, false),
                span("d", false, true, false),
                span(" ", false, false, false),
                span("e*f", false, false, true),
                span(" g", false, false, false),
            ]
        );
    }

    #[test]
    fn nested_bold_italic() {
        let b = parse_markdown("**a *b* c**");
        assert_eq!(
            b[0].spans,
            [
                span("a ", true, false, false),
                span("b", true, true, false),
                span(" c", true, false, false),
            ]
        );
    }

    #[test]
    fn unclosed_markers_and_snake_case_stay_literal() {
        let b = parse_markdown("**open and snake_case_name and 2 * 3");
        let joined: String = b[0].spans.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(joined, "**open and snake_case_name and 2 * 3");
        assert!(b[0].spans.iter().all(|s| !s.bold && !s.italic && !s.code));
    }

    #[test]
    fn unicode_is_preserved_and_oversize_is_plain() {
        let b = parse_markdown("**contraseña** ñandú");
        assert_eq!(b[0].spans[0], span("contraseña", true, false, false));
        let big = "# x\n".repeat(MAX_MARKDOWN_BYTES);
        let b = parse_markdown(&big);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].kind, MdBlockKind::Paragraph);
    }

    #[test]
    fn table_round_trip_and_padding() {
        let json = serialize_table(vec![vec!["h1".into(), "h2".into()], vec!["a".into()]]).unwrap();
        let rows = parse_table(&json).unwrap();
        assert_eq!(rows, [["h1", "h2"], ["a", ""]]);
        assert_eq!(serialize_table(rows.clone()).unwrap(), json);
    }

    #[test]
    fn table_limits_and_garbage_are_rejected() {
        assert!(matches!(parse_table("nope"), Err(Error::Corrupted)));
        assert!(matches!(
            parse_table("{\"rows\":[]}"),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            parse_table("{\"rows\":[[]]}"),
            Err(Error::InvalidInput)
        ));
        let too_wide = vec![vec![String::new(); MAX_TABLE_COLS + 1]];
        assert!(matches!(
            serialize_table(too_wide),
            Err(Error::InvalidInput)
        ));
        let too_tall = vec![vec![String::new()]; MAX_TABLE_ROWS + 1];
        assert!(matches!(
            serialize_table(too_tall),
            Err(Error::InvalidInput)
        ));
        let big_cell = vec![vec!["x".repeat(MAX_TABLE_CELL_BYTES + 1)]];
        assert!(matches!(
            serialize_table(big_cell),
            Err(Error::InvalidInput)
        ));
    }
}
