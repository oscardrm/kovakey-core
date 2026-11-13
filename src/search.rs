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

/// Search hits that share a category (see [`group_by_category`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchGroup {
    /// Category of every item in the group; `None` collects uncategorized items.
    pub category_id: Option<String>,
    /// Matching items, in the order they were given.
    pub items: Vec<ItemSummary>,
}

/// Lower-cased whitespace-separated search terms.
pub fn split_terms(query: &str) -> Vec<String> {
    query.split_whitespace().map(str::to_lowercase).collect()
}

/// Whether every term occurs (case-insensitive) in the title, URL, a tag name or one of
/// `values` (the item's non-secret field values). Empty `terms` match nothing here: a global
/// search with no query has no hits.
pub fn matches_global(item: &ItemSummary, values: &[String], terms: &[String]) -> bool {
    if terms.is_empty() {
        return false;
    }
    let mut haystack: Vec<String> = vec![item.title.to_lowercase()];
    haystack.extend(item.url.iter().map(|u| u.to_lowercase()));
    haystack.extend(item.tags.iter().map(|t| t.to_lowercase()));
    haystack.extend(values.iter().map(|v| v.to_lowercase()));
    terms
        .iter()
        .all(|t| haystack.iter().any(|h| h.contains(t.as_str())))
}

/// Group `items` by category. Groups follow `category_order` (ids of live categories in display
/// order); categories missing from it come after, then the uncategorized group last.
pub fn group_by_category(items: Vec<ItemSummary>, category_order: &[String]) -> Vec<SearchGroup> {
    let mut groups: Vec<SearchGroup> = Vec::new();
    for item in items {
        match groups
            .iter_mut()
            .find(|g| g.category_id == item.category_id)
        {
            Some(g) => g.items.push(item),
            None => groups.push(SearchGroup {
                category_id: item.category_id.clone(),
                items: vec![item],
            }),
        }
    }
    let rank = |g: &SearchGroup| match &g.category_id {
        Some(id) => category_order
            .iter()
            .position(|c| c == id)
            .unwrap_or(category_order.len()),
        None => usize::MAX,
    };
    groups.sort_by_key(rank); // stable
    groups
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
            trashed_at: None,
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

    #[test]
    fn global_match_covers_field_values_and_requires_all_terms() {
        let it = item("a", "Work mail", ItemType::Credential);
        let vals = vec!["Oscardario.Roman@gmail.com".to_string()];
        let t = |q: &str| split_terms(q);
        assert!(matches_global(&it, &vals, &t("oscardario.roman@gmail")));
        assert!(matches_global(&it, &vals, &t("WORK gmail")));
        assert!(!matches_global(&it, &vals, &t("gmail bank")));
        assert!(!matches_global(&it, &vals, &t("   ")));
        assert!(!matches_global(&it, &[], &t("gmail")));
    }

    #[test]
    fn groups_follow_category_order_with_uncategorized_last() {
        let mut a = item("a", "A", ItemType::Credential);
        a.category_id = Some("c2".into());
        let b = item("b", "B", ItemType::Note);
        let mut c = item("c", "C", ItemType::Card);
        c.category_id = Some("c1".into());
        let mut d = item("d", "D", ItemType::Credential);
        d.category_id = Some("c2".into());
        let order = vec!["c1".to_string(), "c2".to_string()];
        let g = group_by_category(vec![a, b, c, d], &order);
        let keys: Vec<Option<&str>> = g.iter().map(|g| g.category_id.as_deref()).collect();
        assert_eq!(keys, [Some("c1"), Some("c2"), None]);
        assert_eq!(ids(&g[1].items), ["a", "d"]);
    }
}
