//! Domain matching for autofill: which saved logins may be offered to a page (PRD §9.6, ADR 0006,
//! ADR 0026).
//!
//! Rules (never substring matching, so `evil-example.com` and `example.com.evil.io` never match
//! `example.com`):
//! * the page must be **HTTPS**;
//! * the saved URL and the page must share the same **registrable domain** (eTLD+1) according to
//!   the bundled Public Suffix List snapshot, which is updated per release and never fetched at
//!   runtime;
//! * hosts are compared as ASCII. Internationalized hosts must be given in their punycode form
//!   (browsers' URL parsers already do this); a non-ASCII host never matches.
//!
//! The URL reader is deliberately small and strict: it follows the WHATWG authority rules that
//! matter for phishing (userinfo before `@`, `\` treated as `/`, port stripping, trailing dot) and
//! rejects anything it does not understand instead of guessing.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::models::ItemType;
use crate::ops::ItemSummary;

/// Snapshot of <https://publicsuffix.org/list/public_suffix_list.dat> (MPL-2.0 header retained).
const BUNDLED_LIST: &str = include_str!("../data/public_suffix_list.dat");

const MAX_HOST_LEN: usize = 253;

/// Parsed Public Suffix List.
///
/// Implements the standard algorithm: the longest matching rule wins, exception rules (`!`)
/// override wildcard rules (`*.`), and an unlisted TLD falls back to the implicit `*` rule (one
/// label). ICANN and PRIVATE sections are both honored (e.g. `github.io`).
#[derive(Debug, Default)]
pub struct PublicSuffixList {
    rules: HashSet<String>,
    wildcards: HashSet<String>,
    exceptions: HashSet<String>,
}

impl PublicSuffixList {
    /// Parses the `.dat` text. Comment lines (`//`) and anything after the first whitespace on a
    /// line are ignored.
    pub fn parse(contents: &str) -> Self {
        let mut list = Self::default();
        for raw in contents.lines() {
            let Some(line) = raw.split_whitespace().next() else {
                continue;
            };
            if line.starts_with("//") {
                continue;
            }
            let rule = line.to_ascii_lowercase();
            if let Some(rest) = rule.strip_prefix('!') {
                list.exceptions.insert(rest.to_string());
            } else if let Some(rest) = rule.strip_prefix("*.") {
                list.wildcards.insert(rest.to_string());
            } else {
                list.rules.insert(rule);
            }
        }
        list
    }

    /// The list bundled with the core (parsed once).
    pub fn bundled() -> &'static Self {
        static LIST: OnceLock<PublicSuffixList> = OnceLock::new();
        LIST.get_or_init(|| Self::parse(BUNDLED_LIST))
    }

    /// `true` when no rule was loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.wildcards.is_empty() && self.exceptions.is_empty()
    }

    /// The last `count` labels of `labels` joined with dots.
    fn tail(labels: &[&str], count: usize) -> Option<String> {
        let start = labels.len().checked_sub(count)?;
        Some(labels.get(start..)?.join("."))
    }

    /// Number of labels in the public suffix of `labels` (lowercase, left to right).
    fn suffix_len(&self, labels: &[&str]) -> usize {
        let mut best = 1; // implicit "*" rule
        for count in 1..=labels.len() {
            let Some(candidate) = Self::tail(labels, count) else {
                continue;
            };
            if self.exceptions.contains(&candidate) {
                return count - 1;
            }
            if self.rules.contains(&candidate) {
                best = best.max(count);
            }
            // `*.parent` matches `candidate` when its parent (one label shorter) is a wildcard base.
            if count >= 2 {
                if let Some(parent) = Self::tail(labels, count - 1) {
                    if self.wildcards.contains(&parent) {
                        best = best.max(count);
                    }
                }
            }
        }
        best
    }

    /// eTLD+1 of `host`, or `host` itself when it is a public suffix, an IP address or a single
    /// label. `host` is lowercased first.
    pub fn registrable_domain(&self, host: &str) -> String {
        let host = host.to_ascii_lowercase();
        let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
        if labels.len() < 2 || host.contains(':') || is_ipv4(&labels) {
            return host;
        }
        let suffix = self.suffix_len(&labels);
        if labels.len() <= suffix {
            return host;
        }
        Self::tail(&labels, suffix + 1).unwrap_or(host)
    }
}

fn is_ipv4(labels: &[&str]) -> bool {
    labels.len() == 4
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// eTLD+1 of `host` using the bundled list.
pub fn registrable_domain(host: &str) -> String {
    PublicSuffixList::bundled().registrable_domain(host)
}

/// Scheme (lowercase) and host of a URL string.
#[derive(Debug, PartialEq, Eq)]
struct UrlParts {
    scheme: Option<String>,
    host: String,
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && !host.starts_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Reads scheme and host. A missing scheme is allowed (users type `example.com`); a scheme must be
/// `http` or `https`. Returns `None` for anything unusual.
fn parse_url(url: &str) -> Option<UrlParts> {
    let trimmed = url.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, rest)) => {
            let s = s.to_ascii_lowercase();
            if s != "http" && s != "https" {
                return None;
            }
            (Some(s), rest)
        }
        None => (None, trimmed),
    };
    // WHATWG: `\` ends the authority like `/` for special schemes.
    let authority = rest.split(['/', '\\', '?', '#']).next()?;
    // Everything before the last `@` is userinfo, never the host.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(inner) = host_port.strip_prefix('[') {
        // IPv6 literal: kept verbatim (it never has a registrable domain).
        let (addr, tail) = inner.split_once(']')?;
        if !tail.is_empty() && !tail.strip_prefix(':').is_some_and(all_digits) {
            return None;
        }
        if addr.is_empty()
            || !addr
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return None;
        }
        addr.to_ascii_lowercase()
    } else {
        let host = match host_port.rsplit_once(':') {
            Some((h, port)) if all_digits(port) => h,
            Some(_) => return None,
            None => host_port,
        };
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host).to_string();
        if !valid_host(&host) {
            return None;
        }
        host
    };
    Some(UrlParts { scheme, host })
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Host of `url` (lowercase, no port, no trailing dot), or `None` if it is not an http(s) URL the
/// reader understands.
pub fn host_of(url: &str) -> Option<String> {
    parse_url(url).map(|p| p.host)
}

/// Whether a saved login with URL `item_url` may be offered on `page_url`.
///
/// `page_url` must be `https://`; the registrable domains must be equal. A missing or unreadable
/// saved URL never matches.
pub fn matches_page(item_url: Option<&str>, page_url: &str) -> bool {
    matches_page_with(PublicSuffixList::bundled(), item_url, page_url)
}

fn matches_page_with(list: &PublicSuffixList, item_url: Option<&str>, page_url: &str) -> bool {
    let Some(page) = parse_url(page_url) else {
        return false;
    };
    if page.scheme.as_deref() != Some("https") {
        return false;
    }
    let Some(item) = item_url.and_then(parse_url) else {
        return false;
    };
    list.registrable_domain(&item.host) == list.registrable_domain(&page.host)
}

/// The live logins (credential items, not trashed) whose URL matches `page_url`, in input order.
pub fn logins_for_page(items: Vec<ItemSummary>, page_url: &str) -> Vec<ItemSummary> {
    items
        .into_iter()
        .filter(|i| {
            i.item_type == ItemType::Credential
                && i.trashed_at.is_none()
                && matches_page(i.url.as_deref(), page_url)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_list_is_loaded_and_answers_known_cases() {
        let list = PublicSuffixList::bundled();
        assert!(!list.is_empty());
        for (host, expected) in [
            ("example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("example.co.uk", "example.co.uk"),
            ("www.example.co.uk", "example.co.uk"),
            ("mysite.github.io", "mysite.github.io"),
            ("www.mysite.github.io", "mysite.github.io"),
            ("foo.blogspot.com", "foo.blogspot.com"),
            ("co.uk", "co.uk"),
            ("com", "com"),
            ("localhost", "localhost"),
            ("EXAMPLE.COM", "example.com"),
            ("unlisted.zzzzz", "unlisted.zzzzz"),
            ("www.unlisted.zzzzz", "unlisted.zzzzz"),
            ("10.0.0.1", "10.0.0.1"),
            ("::1", "::1"),
        ] {
            assert_eq!(list.registrable_domain(host), expected, "{host}");
        }
    }

    #[test]
    fn wildcard_and_exception_rules_follow_the_standard_algorithm() {
        let list = PublicSuffixList::parse("// c\njp\n*.kobe.jp\n!city.kobe.jp\n");
        assert_eq!(list.registrable_domain("www.city.kobe.jp"), "city.kobe.jp");
        assert_eq!(list.registrable_domain("a.b.kobe.jp"), "a.b.kobe.jp");
        assert_eq!(list.registrable_domain("b.kobe.jp"), "b.kobe.jp");
        assert_eq!(list.registrable_domain("x.example.jp"), "example.jp");
    }

    #[test]
    fn empty_list_degrades_to_the_one_label_rule() {
        let list = PublicSuffixList::parse("");
        assert!(list.is_empty());
        assert_eq!(list.registrable_domain("www.example.co.uk"), "co.uk");
    }

    #[test]
    fn url_reader_extracts_the_real_host() {
        for (url, host) in [
            ("https://example.com", "example.com"),
            ("https://EXAMPLE.com:8443/a?b=c#d", "example.com"),
            ("example.com", "example.com"),
            ("example.com/path", "example.com"),
            ("http://example.com.", "example.com"),
            ("https://user:pw@example.com/x", "example.com"),
            // Phishing shapes: the host is what follows `@` / precedes `\`.
            ("https://example.com@evil.com/", "evil.com"),
            ("https://example.com:pw@evil.com/", "evil.com"),
            ("https://evil.com\\@example.com/", "evil.com"),
            ("https://evil.com#@example.com", "evil.com"),
            ("https://evil.com?@example.com", "evil.com"),
            ("https://[2001:db8::1]:8443/x", "2001:db8::1"),
            ("https://xn--bcher-kva.example/", "xn--bcher-kva.example"),
        ] {
            assert_eq!(host_of(url).as_deref(), Some(host), "{url}");
        }
    }

    #[test]
    fn url_reader_rejects_what_it_does_not_understand() {
        for url in [
            "",
            "   ",
            "javascript:alert(1)",
            "ftp://example.com",
            "file:///etc/passwd",
            "https://",
            "https:///x",
            "https://exa mple.com",
            "https://bücher.example",
            "https://a..b.com",
            "https://.example.com",
            "https://example.com:notaport",
            "https://example.com:123456",
            "https://[::1",
            "https://[]",
            "https://[xyz]",
            "data:text/html,hi",
        ] {
            assert_eq!(host_of(url), None, "{url:?}");
        }
    }

    #[test]
    fn matches_by_registrable_domain_over_https_only() {
        let yes = |item: &str, page: &str| matches_page(Some(item), page);
        assert!(yes("https://example.com", "https://example.com/login"));
        assert!(yes("example.com", "https://www.example.com/login"));
        assert!(yes(
            "https://accounts.example.com",
            "https://shop.example.com"
        ));
        assert!(yes("http://example.com", "https://example.com"));
        assert!(yes("https://example.co.uk", "https://login.example.co.uk"));
        assert!(yes("https://EXAMPLE.com:8443", "https://example.com"));
        assert!(yes("https://10.0.0.1", "https://10.0.0.1/x"));
    }

    #[test]
    fn look_alikes_and_unsafe_pages_never_match() {
        let no = |item: Option<&str>, page: &str| !matches_page(item, page);
        let s = Some("https://example.com");
        // Not substring matching.
        assert!(no(s, "https://evil-example.com"));
        assert!(no(s, "https://example.com.evil.io"));
        assert!(no(s, "https://notexample.com"));
        assert!(no(s, "https://example.com.evil.io/example.com"));
        // Userinfo and backslash tricks on the page URL.
        assert!(no(s, "https://example.com@evil.com/"));
        assert!(no(s, "https://evil.com\\@example.com/"));
        // Plain HTTP, other schemes, garbage.
        assert!(no(s, "http://example.com"));
        assert!(no(s, "ftp://example.com"));
        assert!(no(s, "javascript:alert(1)"));
        assert!(no(s, ""));
        // Missing or unreadable saved URL.
        assert!(no(None, "https://example.com"));
        assert!(no(Some(""), "https://example.com"));
        assert!(no(Some("not a url"), "https://example.com"));
        // Look-alike through a public suffix: siblings on a shared suffix are different owners.
        assert!(no(Some("https://alice.github.io"), "https://bob.github.io"));
        assert!(no(Some("https://a.co.uk"), "https://b.co.uk"));
        assert!(no(Some("https://github.io"), "https://evil.github.io"));
        // Punycode look-alikes are different hosts; non-ASCII hosts never match.
        assert!(no(s, "https://xn--exmple-cua.com"));
        assert!(no(s, "https://exämple.com"));
        // IP literals only match themselves.
        assert!(no(Some("https://10.0.0.1"), "https://10.0.0.2"));
        assert!(no(Some("https://1.example.com"), "https://10.0.0.1"));
    }

    fn summary(id: &str, kind: ItemType, url: Option<&str>, trashed: bool) -> ItemSummary {
        ItemSummary {
            id: id.to_string(),
            item_type: kind,
            title: id.to_string(),
            url: url.map(str::to_string),
            vault_id: "v".to_string(),
            category_id: None,
            color: None,
            favorite: false,
            use_count: 0,
            last_used_at: None,
            updated_at: 1,
            tags: Vec::new(),
            trashed_at: trashed.then_some(5),
        }
    }

    #[test]
    fn logins_for_page_keeps_only_live_matching_credentials_in_order() {
        let items = vec![
            summary(
                "a",
                ItemType::Credential,
                Some("https://example.com"),
                false,
            ),
            summary(
                "b",
                ItemType::Credential,
                Some("https://evil-example.com"),
                false,
            ),
            summary("c", ItemType::Note, Some("https://example.com"), false),
            summary("d", ItemType::Credential, Some("https://example.com"), true),
            summary("e", ItemType::Credential, None, false),
            summary(
                "f",
                ItemType::Credential,
                Some("www.example.com/login"),
                false,
            ),
        ];
        let ids: Vec<String> = logins_for_page(items, "https://login.example.com/")
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ids, ["a", "f"]);
    }

    proptest::proptest! {
        /// Arbitrary text never panics the reader, and any host it returns is plain lowercase
        /// ASCII that cannot smuggle a path, userinfo or port into a comparison.
        #[test]
        fn reader_never_panics_and_only_returns_clean_hosts(url in ".{0,80}") {
            if let Some(host) = host_of(&url) {
                proptest::prop_assert!(!host.is_empty());
                proptest::prop_assert!(host.is_ascii());
                proptest::prop_assert!(!host.contains(['/', '\\', '@', '?', '#', ' ']));
                proptest::prop_assert_eq!(host.to_ascii_lowercase(), host);
            }
            let _ = matches_page(Some(&url), &url);
        }

        /// A page never matches a saved URL on a different registrable domain.
        #[test]
        fn different_labels_never_match(a in "[a-z]{3,10}", b in "[a-z]{3,10}") {
            proptest::prop_assume!(a != b);
            let item = format!("https://{a}.com");
            let page = format!("https://www.{b}.com");
            proptest::prop_assert!(!matches_page(Some(&item), &page));
        }
    }
}
