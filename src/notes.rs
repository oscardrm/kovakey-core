//! Note/code parsing helpers: heuristic language detection for fenced or pasted code blocks.
//! Pure and allocation-light; input is untrusted and is never executed.

/// Languages the detector can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    /// JSON.
    Json,
    /// SQL.
    Sql,
    /// JavaScript / TypeScript.
    JavaScript,
    /// Python.
    Python,
    /// Bash / shell.
    Bash,
    /// YAML.
    Yaml,
    /// Could not tell; treat as plain text.
    PlainText,
}

impl Language {
    /// Stable identifier stored in `note_blocks.language`.
    pub fn id(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Sql => "sql",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Bash => "bash",
            Self::Yaml => "yaml",
            Self::PlainText => "plaintext",
        }
    }

    /// Parse a stored/selected identifier (manual language switcher).
    pub fn from_id(id: &str) -> Self {
        match id.to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            "sql" => Self::Sql,
            "javascript" | "js" | "typescript" | "ts" => Self::JavaScript,
            "python" | "py" => Self::Python,
            "bash" | "sh" | "shell" | "zsh" => Self::Bash,
            "yaml" | "yml" => Self::Yaml,
            _ => Self::PlainText,
        }
    }
}

/// Input above this size is not analysed (DoS guard); it is reported as plain text.
const MAX_ANALYSED_BYTES: usize = 256 * 1024;

fn looks_like_json(t: &str) -> bool {
    let ok_frame =
        (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']'));
    ok_frame
        && (t.contains("\":")
            || t.contains("\" :")
            || t == "[]"
            || t == "{}"
            || t.starts_with("[\"")
            || t.starts_with("[1"))
        && balanced(t)
}

fn balanced(t: &str) -> bool {
    let (mut depth, mut in_str, mut esc) = (0i64, false, false);
    for c in t.chars() {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

/// Detect the most likely language of `code`.
pub fn detect_language(code: &str) -> Language {
    let t = code.trim();
    if t.is_empty() || t.len() > MAX_ANALYSED_BYTES {
        return Language::PlainText;
    }
    if looks_like_json(t) {
        return Language::Json;
    }
    let lower = t.to_lowercase();
    let lines: Vec<&str> = t.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let first = lines.first().copied().unwrap_or("");

    if first.starts_with("#!") && (first.contains("sh") || first.contains("bash")) {
        return Language::Bash;
    }
    if first.starts_with("#!") && first.contains("python") {
        return Language::Python;
    }

    let sql_start = [
        "select ",
        "insert into",
        "update ",
        "delete from",
        "create table",
        "alter table",
        "drop table",
        "with ",
    ];
    if sql_start.iter().any(|k| lower.starts_with(k))
        && (lower.contains(" from ")
            || lower.contains(" set ")
            || lower.contains(" values")
            || lower.contains("table")
            || lower.contains(" as "))
    {
        return Language::Sql;
    }

    let mut score = [0i32; 4]; // js, python, bash, yaml
    for l in &lines {
        let low = l.to_lowercase();
        if [
            "const ",
            "let ",
            "var ",
            "function ",
            "=> ",
            "console.log",
            "import {",
            "export ",
            "require(",
        ]
        .iter()
        .any(|k| low.contains(k))
            || l.ends_with(';')
        {
            score[0] += 2;
        }
        if [
            "def ", "elif ", "print(", "import ", "from ", "self.", "None", "True", "False",
        ]
        .iter()
        .any(|k| l.contains(k))
            && !l.ends_with(';')
        {
            score[1] += 1;
        }
        if l.ends_with(':')
            && (low.starts_with("def ")
                || low.starts_with("class ")
                || low.starts_with("if ")
                || low.starts_with("for ")
                || low.starts_with("while "))
        {
            score[1] += 3;
        }
        if [
            "echo ", "sudo ", "export ", "cd ", "grep ", "curl ", "chmod ", "apt ", "$(", "fi",
            "then", "done",
        ]
        .iter()
        .any(|k| low.starts_with(k) || low == *k)
            || l.starts_with("$ ")
        {
            score[2] += 2;
        }
        if (l.contains(": ") || l.ends_with(':'))
            && !l.contains('{')
            && !l.contains(';')
            && !l.contains('(')
        {
            score[3] += 1;
        }
        if l.starts_with("- ") {
            score[3] += 1;
        }
    }
    if t.starts_with("---") {
        score[3] += 3;
    }
    let best = score
        .iter()
        .enumerate()
        .max_by_key(|(i, s)| (**s, std::cmp::Reverse(*i)))
        .map(|(i, s)| (i, *s));
    match best {
        Some((0, s)) if s >= 2 => Language::JavaScript,
        Some((1, s)) if s >= 2 => Language::Python,
        Some((2, s)) if s >= 2 => Language::Bash,
        Some((3, s)) if s >= 2 => Language::Yaml,
        _ => Language::PlainText,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_languages_from_samples() {
        let cases: [(&str, Language); 11] = [
            ("{\"name\": \"fake\", \"list\": [1, 2]}", Language::Json),
            ("[\n  {\"a\": 1}\n]", Language::Json),
            ("SELECT id, name FROM users WHERE id = 1;", Language::Sql),
            ("CREATE TABLE t (id INT);", Language::Sql),
            ("const x = 1;\nconsole.log(x);", Language::JavaScript),
            ("function f(a) { return a + 1; }", Language::JavaScript),
            ("def f(x):\n    return x\n\nprint(f(1))", Language::Python),
            ("#!/bin/bash\necho hi", Language::Bash),
            ("sudo apt update\ncd /tmp\necho done", Language::Bash),
            (
                "name: fake\nservices:\n  db:\n    image: postgres\nlist:\n  - a\n  - b",
                Language::Yaml,
            ),
            ("just some words here", Language::PlainText),
        ];
        for (code, expected) in cases {
            assert_eq!(detect_language(code), expected, "{code}");
        }
    }

    #[test]
    fn invalid_json_is_not_reported_as_json() {
        assert_ne!(detect_language("{\"a\": [1, 2}"), Language::Json);
    }

    #[test]
    fn empty_and_oversized_input_is_plain_text() {
        assert_eq!(detect_language("   "), Language::PlainText);
        assert_eq!(
            detect_language(&"a".repeat(MAX_ANALYSED_BYTES + 1)),
            Language::PlainText
        );
    }

    #[test]
    fn language_ids_round_trip_and_aliases_work() {
        for l in [
            Language::Json,
            Language::Sql,
            Language::JavaScript,
            Language::Python,
            Language::Bash,
            Language::Yaml,
            Language::PlainText,
        ] {
            assert_eq!(Language::from_id(l.id()), l);
        }
        assert_eq!(Language::from_id("JS"), Language::JavaScript);
        assert_eq!(Language::from_id("yml"), Language::Yaml);
        assert_eq!(Language::from_id("???"), Language::PlainText);
    }

    #[test]
    fn detection_is_deterministic() {
        let s = "echo hi\ncd /";
        assert_eq!(detect_language(s), detect_language(s));
    }
}
