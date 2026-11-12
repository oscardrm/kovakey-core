//! Search, filter and sort over non-secret [`ItemSummary`] rows. Pure; secrets are never searched.

use std::cmp::Reverse;

use crate::models::ItemType;
use crate::ops::ItemSummary;

/// Result ordering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortOrder {
    /// By title (the order [`crate::ops::VaultStore::list_items`] already returns).
    #[default]
    Title,
    /// Highest `use_count` first, then title.
    MostUsed,
    /// Most recently used first; never-used items last.
    RecentlyUsed,
    /// Most recently modified first.
    RecentlyModified,
}

/// Filter criteria; every set criterion must match (AND).
#[derive(Clone, Debug, Default)]
pub struct ItemFilter {
    /// Whitespace-separated terms; each must occur (case-insensitive) in the title, URL or a tag
    /// name. Empty matches everything.
    pub query: String,
    /// Only this item type.
    pub item_type: Option<ItemType>,
    /// Only this category.
    pub category_id: Option<String>,
    /// Only items carrying this tag name.
    pub tag: Option<String>,
    /// Only favorites.
    pub favorites_only: bool,
    /// Ordering.
    pub sort: SortOrder,
}

fn matches(item: &ItemSummary, terms: &[String], f: &ItemFilter) -> bool {
    if f.item_type.is_some_and(|t| t != item.item_type)
        || f.favorites_only && !item.favorite
        || f.category_id
            .as_deref()
            .is_some_and(|c| item.category_id.as_deref() != Some(c))
        || f.tag
            .as_deref()
            .is_some_and(|t| !item.tags.iter().any(|x| x == t))
    {
        return false;
    }
    let title = item.title.to_lowercase();
    let url = item.url.as_deref().unwrap_or("").to_lowercase();
    let tags: Vec<String> = item.tags.iter().map(|t| t.to_lowercase()).collect();
    terms
        .iter()
        .all(|t| title.contains(t) || url.contains(t) || tags.iter().any(|x| x.contains(t)))
}

/// Apply `filter` to `items` (assumed title-sorted) and order the result.
pub fn filter_items(items: Vec<ItemSummary>, filter: &ItemFilter) -> Vec<ItemSummary> {
    let terms: Vec<String> = filter
        .query
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let mut out: Vec<ItemSummary> = items
        .into_iter()
        .filter(|i| matches(i, &terms, filter))
        .collect();
    // `sort_by` is stable, so ties keep the title order.
    match filter.sort {
        SortOrder::Title => {}
        SortOrder::MostUsed => out.sort_by_key(|i| Reverse(i.use_count)),
        SortOrder::RecentlyUsed => out.sort_by_key(|i| Reverse(i.last_used_at)),
        SortOrder::RecentlyModified => out.sort_by_key(|i| Reverse(i.updated_at)),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, title: &str, ty: ItemType) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            item_type: ty,
            title: title.into(),
            url: None,
            category_id: None,
            color: None,
            favorite: false,
            use_count: 0,
            last_used_at: None,
            updated_at: 0,
            tags: vec![],
        }
    }

    fn sample() -> Vec<ItemSummary> {
        let mut a = item("a", "GitHub", ItemType::Credential);
        a.url = Some("https://github.com".into());
        a.tags = vec!["#dev".into()];
        a.use_count = 5;
        a.last_used_at = Some(50);
        a.updated_at = 10;
        let mut b = item("b", "Bank card", ItemType::Card);
        b.favorite = true;
        b.category_id = Some("fin".into());
        b.use_count = 9;
        b.updated_at = 30;
        let mut c = item("c", "Notes", ItemType::Note);
        c.last_used_at = Some(70);
        c.updated_at = 20;
        vec![b, a, c]
    }

    fn ids(v: &[ItemSummary]) -> Vec<&str> {
        v.iter().map(|i| i.id.as_str()).collect()
    }

    #[test]
    fn query_terms_are_anded_and_match_title_url_and_tags_case_insensitively() {
        let q = |s: &str| ItemFilter {
            query: s.into(),
            ..Default::default()
        };
        assert_eq!(ids(&filter_items(sample(), &q("GITHUB"))), ["a"]);
        assert_eq!(ids(&filter_items(sample(), &q("github.com dev"))), ["a"]);
        assert_eq!(
            ids(&filter_items(sample(), &q("github bank"))),
            Vec::<&str>::new()
        );
        assert_eq!(filter_items(sample(), &q("  ")).len(), 3);
    }

    #[test]
    fn structured_filters_combine() {
        let f = ItemFilter {
            favorites_only: true,
            category_id: Some("fin".into()),
            item_type: Some(ItemType::Card),
            ..Default::default()
        };
        assert_eq!(ids(&filter_items(sample(), &f)), ["b"]);
        let f = ItemFilter {
            tag: Some("#dev".into()),
            ..Default::default()
        };
        assert_eq!(ids(&filter_items(sample(), &f)), ["a"]);
    }

    #[test]
    fn sort_orders() {
        let s = |sort| {
            let f = ItemFilter {
                sort,
                ..Default::default()
            };
            filter_items(sample(), &f)
        };
        assert_eq!(ids(&s(SortOrder::MostUsed)), ["b", "a", "c"]);
        assert_eq!(ids(&s(SortOrder::RecentlyUsed)), ["c", "a", "b"]);
        assert_eq!(ids(&s(SortOrder::RecentlyModified)), ["b", "c", "a"]);
        assert_eq!(ids(&s(SortOrder::Title)), ["b", "a", "c"]);
    }
}
