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

/// Returns the non-empty run of `rest` (just after an opening delimiter) closed by `close`.
fn take_until<'a>(rest: &'a str, close: &str) -> Option<&'a str> {
    let end = rest.find(close)?;
    if end == 0 {
        return None;
    }
    rest.get(..end)
}

/// A styled stretch of one line, as byte offsets into that line. `marker` runs are syntax (`**`, `#`,
/// `- `, indentation) and carry no visible text in the rendered note.
struct Run {
    start: usize,
    len: usize,
    bold: bool,
    italic: bool,
    code: bool,
    marker: bool,
}

fn push_run(out: &mut Vec<Run>, start: usize, len: usize, style: (bool, bool, bool), marker: bool) {
    if len > 0 {
        out.push(Run {
            start,
            len,
            bold: style.0,
            italic: style.1,
            code: style.2,
            marker,
        });
    }
}

/// Tokenizes inline styles of `s` (which starts at byte `base` of its line). Runs cover `s` fully.
fn inline(s: &str, base: usize, bold: bool, italic: bool, out: &mut Vec<Run>) {
    let mut plain_start = 0usize;
    let mut i = 0usize;
    let mut prev: Option<char> = None;
    while let Some(rest) = s.get(i..).filter(|r| !r.is_empty()) {
        let Some(c) = rest.chars().next() else { break };
        let after_c = rest.get(c.len_utf8()..).unwrap_or_default();
        let style = (bold, italic, false);
        if rest.starts_with("**") {
            let body = rest.get(2..).unwrap_or_default();
            if let Some(inner) = take_until(body, "**") {
                push_run(out, base + plain_start, i - plain_start, style, false);
                push_run(out, base + i, 2, style, true);
                inline(inner, base + i + 2, true, italic, out);
                push_run(out, base + i + 2 + inner.len(), 2, style, true);
                i += 4 + inner.len();
                plain_start = i;
                prev = Some('*');
                continue;
            }
            // Unclosed `**`: keep both markers literal so the second cannot open an italic run.
            i += 2;
            prev = Some('*');
            continue;
        } else if c == '`' {
            if let Some(inner) = take_until(after_c, "`") {
                push_run(out, base + plain_start, i - plain_start, style, false);
                push_run(out, base + i, 1, style, true);
                push_run(out, base + i + 1, inner.len(), (bold, italic, true), false);
                push_run(out, base + i + 1 + inner.len(), 1, style, true);
                i += 2 + inner.len();
                plain_start = i;
                prev = Some('`');
                continue;
            }
        } else if c == '*' || (c == '_' && !prev.is_some_and(char::is_alphanumeric)) {
            let mut delim = [0u8; 4];
            let delim: &str = c.encode_utf8(&mut delim);
            let tight = |inner: &str| {
                !inner.starts_with(char::is_whitespace) && !inner.ends_with(char::is_whitespace)
            };
            if let Some(inner) = take_until(after_c, delim).filter(|inner| tight(inner)) {
                push_run(out, base + plain_start, i - plain_start, style, false);
                push_run(out, base + i, 1, style, true);
                inline(inner, base + i + 1, bold, true, out);
                push_run(out, base + i + 1 + inner.len(), 1, style, true);
                i += 2 + inner.len();
                plain_start = i;
                prev = Some(c);
                continue;
            }
        }
        i += c.len_utf8();
        prev = Some(c);
    }
    push_run(
        out,
        base + plain_start,
        s.len() - plain_start,
        (bold, italic, false),
        false,
    );
}

struct Line {
    kind: MdBlockKind,
    level: u32,
    runs: Vec<Run>,
}

/// Number of leading bytes of `s` that are spaces or tabs.
fn blank_prefix(s: &str) -> usize {
    s.len() - s.trim_start_matches([' ', '\t']).len()
}

/// Splits a line into its block kind and styled runs (covering the whole line).
fn tokenize_line(line: &str) -> Line {
    let lead = blank_prefix(line);
    let t = line.get(lead..).unwrap_or_default();
    let mut runs = Vec::new();
    push_run(&mut runs, 0, lead, (false, false, false), true);

    let hashes = t.chars().take_while(|&c| c == '#').count();
    let after_hashes = t.get(hashes..).unwrap_or_default();
    let (kind, level, marker_len) = if (1..=6).contains(&hashes) && after_hashes.starts_with(' ') {
        (MdBlockKind::Heading, hashes as u32, hashes)
    } else if t.starts_with("- ") || t.starts_with("* ") {
        (MdBlockKind::Bullet, 0, 1)
    } else {
        let digits = t.chars().take_while(char::is_ascii_digit).count();
        match t.get(digits..).and_then(|r| r.strip_prefix(". ")) {
            Some(_) if (1..=9).contains(&digits) => (
                MdBlockKind::Numbered,
                t.get(..digits).and_then(|d| d.parse().ok()).unwrap_or(1),
                digits + 1,
            ),
            _ => (MdBlockKind::Paragraph, 0, 0),
        }
    };
    let mut body_start = 0;
    if marker_len > 0 {
        let gap = blank_prefix(t.get(marker_len..).unwrap_or_default());
        body_start = marker_len + gap;
        push_run(&mut runs, lead, body_start, (false, false, false), true);
    }
    let body = t.get(body_start..).unwrap_or_default();
    inline(body, lead + body_start, false, false, &mut runs);
    Line { kind, level, runs }
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
    text.lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let parsed = tokenize_line(line);
            let spans = parsed
                .runs
                .iter()
                .filter(|r| !r.marker)
                .filter_map(|r| {
                    Some(MdSpan {
                        text: line.get(r.start..r.start + r.len)?.to_string(),
                        bold: r.bold,
                        italic: r.italic,
                        code: r.code,
                    })
                })
                .collect();
            MdBlock {
                kind: parsed.kind,
                level: parsed.level,
                spans,
            }
        })
        .collect()
}

/// A styled stretch of the *raw* editor text, in UTF-16 code units (what `NSRange` and JS strings use).
/// Ranges are contiguous, in order and cover every character except the `\n` separators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdRange {
    /// Start offset in UTF-16 code units from the beginning of the text.
    pub start: u32,
    /// Length in UTF-16 code units.
    pub length: u32,
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Inline code.
    pub code: bool,
    /// Syntax characters (`**`, `#`, `- `, indentation) that an editor may dim.
    pub marker: bool,
    /// Heading level (1..=6) of the line this range is on, else 0.
    pub heading: u32,
}

/// Styles the raw text of a note for live editing. Uses the same tokenizer as [`parse_markdown`], so the
/// editor and the rendered note always agree. Input above the size cap returns no ranges (plain text).
pub fn highlight_markdown(text: &str) -> Vec<MdRange> {
    if text.len() > MAX_MARKDOWN_BYTES {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset: u32 = 0;
    for line in text.split('\n') {
        let parsed = tokenize_line(line);
        let heading = if parsed.kind == MdBlockKind::Heading {
            parsed.level
        } else {
            0
        };
        for r in &parsed.runs {
            let Some(slice) = line.get(r.start..r.start + r.len) else {
                continue;
            };
            let length = slice.encode_utf16().count() as u32;
            out.push(MdRange {
                start: offset,
                length,
                bold: r.bold,
                italic: r.italic,
                code: r.code,
                marker: r.marker,
                heading,
            });
            offset += length;
        }
        offset += 1;
    }
    out
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
    fn highlight_covers_every_character_with_utf16_offsets() {
        let text = "## Título ñ\n  - a **b** `c` 😀 *d*\n\nplain _e_";
        let ranges = highlight_markdown(text);
        let mut expected = 0u32;
        for line in text.split('\n') {
            let start = expected;
            let covered: u32 = ranges
                .iter()
                .filter(|r| {
                    r.start >= start && r.start < start + line.encode_utf16().count() as u32
                })
                .map(|r| r.length)
                .sum();
            assert_eq!(covered, line.encode_utf16().count() as u32, "{line}");
            expected += line.encode_utf16().count() as u32 + 1;
        }
        // Contiguous and ordered.
        let mut at = 0;
        for r in &ranges {
            assert!(r.start >= at);
            at = r.start + r.length;
        }
    }

    #[test]
    fn highlight_marks_syntax_and_styles() {
        let r = highlight_markdown("# Hi **b**");
        assert!(r[0].marker && r[0].heading == 1 && r[0].length == 2);
        let bold = r.iter().find(|r| r.bold && !r.marker).unwrap();
        assert_eq!((bold.start, bold.length), (7, 1));
        assert!(r.iter().any(|r| r.marker && !r.bold));
        assert!(r.iter().filter(|r| r.marker).all(|r| r.heading == 1));
        let c = highlight_markdown("a `x` b");
        assert!(c.iter().any(|r| r.code && !r.marker && r.length == 1));
        assert!(highlight_markdown(&"x".repeat(MAX_MARKDOWN_BYTES + 1)).is_empty());
        assert_eq!(highlight_markdown("").len(), 0);
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
