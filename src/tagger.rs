//! Lightweight, deterministic heuristic auto-tagger. Pure function of title, URL, item type and
//! field kinds; no network, no ML. Output is sorted and de-duplicated.

/// A suggested tag with a display color.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TagSuggestion {
    /// Tag name including `#`, e.g. `#bank`.
    pub name: &'static str,
    /// Hex color.
    pub color: &'static str,
}

struct Rule {
    tag: &'static str,
    color: &'static str,
    keywords: &'static [&'static str],
    item_types: &'static [&'static str],
    field_kinds: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        tag: "#bank",
        color: "#16A34A",
        keywords: &[
            "bank",
            "banco",
            "paypal",
            "visa",
            "mastercard",
            "credit",
            "debit",
            "santander",
            "chase",
            "wise",
            "revolut",
        ],
        item_types: &["card"],
        field_kinds: &[],
    },
    Rule {
        tag: "#dev",
        color: "#2563EB",
        keywords: &[
            "github",
            "gitlab",
            "bitbucket",
            "npm",
            "docker",
            "stackoverflow",
            "jira",
            "vercel",
            "netlify",
            "api",
            "sdk",
        ],
        item_types: &["dev_secret"],
        field_kinds: &["key", "env", "hash"],
    },
    Rule {
        tag: "#server",
        color: "#7C3AED",
        keywords: &[
            "ssh",
            "server",
            "aws",
            "azure",
            "gcp",
            "digitalocean",
            "linode",
            "vps",
            "postgres",
            "mysql",
            "mongo",
            "redis",
            "database",
        ],
        item_types: &["database"],
        field_kinds: &[],
    },
    Rule {
        tag: "#gov",
        color: "#DC2626",
        keywords: &[
            ".gov",
            "gob.",
            "sii.cl",
            "irs",
            "tax",
            "impuesto",
            "passport",
            "pasaporte",
            "rut",
            "dmv",
            "licencia",
        ],
        item_types: &["identity"],
        field_kinds: &[],
    },
    Rule {
        tag: "#travel",
        color: "#0891B2",
        keywords: &[
            "airline", "airbnb", "booking", "expedia", "hotel", "flight", "vuelo", "latam",
            "delta", "united", "ryanair", "uber", "travel",
        ],
        item_types: &["travel"],
        field_kinds: &[],
    },
    Rule {
        tag: "#social",
        color: "#DB2777",
        keywords: &[
            "facebook",
            "instagram",
            "twitter",
            "x.com",
            "linkedin",
            "tiktok",
            "reddit",
            "discord",
            "whatsapp",
            "telegram",
        ],
        item_types: &[],
        field_kinds: &[],
    },
    Rule {
        tag: "#shopping",
        color: "#EA580C",
        keywords: &[
            "amazon",
            "ebay",
            "aliexpress",
            "mercadolibre",
            "shopify",
            "walmart",
            "etsy",
        ],
        item_types: &[],
        field_kinds: &[],
    },
    Rule {
        tag: "#email",
        color: "#CA8A04",
        keywords: &["gmail", "outlook", "proton", "yahoo", "icloud", "mail"],
        item_types: &[],
        field_kinds: &[],
    },
    Rule {
        tag: "#2fa",
        color: "#475569",
        keywords: &[],
        item_types: &[],
        field_kinds: &["totp"],
    },
];

/// Suggest tags for an item.
pub fn suggest_tags(
    title: &str,
    url: Option<&str>,
    item_type: &str,
    field_kinds: &[&str],
) -> Vec<TagSuggestion> {
    let haystack = format!(
        "{} {}",
        title.to_lowercase(),
        url.unwrap_or("").to_lowercase()
    );
    let mut out: Vec<TagSuggestion> = RULES
        .iter()
        .filter(|r| {
            r.keywords.iter().any(|k| haystack.contains(k))
                || r.item_types.contains(&item_type)
                || field_kinds.iter().any(|f| r.field_kinds.contains(f))
        })
        .map(|r| TagSuggestion {
            name: r.tag,
            color: r.color,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type Case<'a> = (
        &'a str,
        Option<&'a str>,
        &'a str,
        &'a [&'a str],
        &'a [&'a str],
    );

    fn names(v: Vec<TagSuggestion>) -> Vec<&'static str> {
        v.into_iter().map(|t| t.name).collect()
    }

    #[test]
    fn table_driven_suggestions() {
        let cases: [Case; 7] = [
            (
                "GitHub",
                Some("https://github.com"),
                "credential",
                &[],
                &["#dev"],
            ),
            ("Banco Santander", None, "credential", &[], &["#bank"]),
            ("Prod DB", None, "database", &[], &["#server"]),
            (
                "SII",
                Some("https://www.sii.cl"),
                "credential",
                &[],
                &["#gov"],
            ),
            ("Trip", None, "travel", &[], &["#travel"]),
            ("Gmail", None, "credential", &["totp"], &["#2fa", "#email"]),
            ("Random thing", None, "credential", &[], &[]),
        ];
        for (title, url, ty, kinds, expected) in cases {
            assert_eq!(
                names(suggest_tags(title, url, ty, kinds)),
                expected,
                "{title}"
            );
        }
    }

    #[test]
    fn suggestions_are_deterministic_sorted_and_unique() {
        let a = suggest_tags(
            "AWS ssh server",
            Some("https://aws.amazon.com"),
            "database",
            &["key", "env"],
        );
        let b = suggest_tags(
            "AWS ssh server",
            Some("https://aws.amazon.com"),
            "database",
            &["key", "env"],
        );
        assert_eq!(a, b);
        let mut sorted = a.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(a, sorted);
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            names(suggest_tags("GITHUB", None, "credential", &[])),
            ["#dev"]
        );
    }
}
