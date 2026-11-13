//! Device-local registry of the vaults a user keeps (PRD §3 "Multiple Vaults").
//!
//! Each vault is an independent file set with its own Master Password and keys; this registry only lists
//! them (name, color, badge and where they live) so the UI can show a switcher while everything is locked.
//! It holds **no secrets** and is never synced: names are chosen by the user and stay on the device.
//! The serialized form is versioned JSON; an empty input is an empty registry.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const FORMAT_VERSION: u32 = 1;
const MAX_NAME_CHARS: usize = 64;
const MAX_BADGE_CHARS: usize = 4;
const MAX_VAULTS: usize = 64;

/// One vault known to this device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Stable id (UUIDv7, or `default` for the vault that predates the registry).
    pub id: String,
    /// Display name, unique (case-insensitive) within the registry.
    pub name: String,
    /// Accent color as `#RRGGBB`.
    pub color: String,
    /// Optional short badge (emoji or letters, at most 4 characters).
    pub badge: Option<String>,
    /// Storage directory relative to the app's vault root (`a-z A-Z 0-9 _ - /`, no `..`).
    pub dir: String,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    version: u32,
    vaults: Vec<VaultEntry>,
}

/// Ordered list of [`VaultEntry`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultRegistry {
    entries: Vec<VaultEntry>,
}

/// A directory must stay inside the vault root: relative, simple segments only.
fn valid_dir(dir: &str) -> bool {
    !dir.is_empty()
        && dir.len() <= 128
        && dir.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn valid_color(color: &str) -> bool {
    color.len() == 7
        && color.starts_with('#')
        && color.chars().skip(1).all(|c| c.is_ascii_hexdigit())
}

fn clean_name(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME_CHARS || n.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(n.to_string())
}

fn clean_badge(badge: &str) -> Result<Option<String>> {
    let b = badge.trim();
    if b.chars().count() > MAX_BADGE_CHARS || b.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok((!b.is_empty()).then(|| b.to_string()))
}

impl VaultRegistry {
    /// Parses a stored registry. Empty input is an empty registry; anything else must be a valid,
    /// current-version document whose entries all satisfy the invariants.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| Error::Corrupted)?;
        if wire.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let mut reg = Self::default();
        for e in wire.vaults {
            let ok = !e.id.is_empty()
                && valid_dir(&e.dir)
                && valid_color(&e.color)
                && clean_name(&e.name).is_ok()
                && !reg.name_taken(e.name.trim(), None)
                && reg.entries.iter().all(|o| o.id != e.id && o.dir != e.dir);
            if !ok {
                return Err(Error::Corrupted);
            }
            reg.entries.push(e);
        }
        Ok(reg)
    }

    /// Serializes to the stored form.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&Wire {
            version: FORMAT_VERSION,
            vaults: self.entries.clone(),
        })
        .map_err(|_| Error::Corrupted)
    }

    /// Vaults in display order.
    pub fn entries(&self) -> &[VaultEntry] {
        &self.entries
    }

    /// Looks a vault up by id.
    pub fn get(&self, id: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    fn name_taken(&self, name: &str, except: Option<&str>) -> bool {
        self.entries
            .iter()
            .any(|e| Some(e.id.as_str()) != except && e.name.to_lowercase() == name.to_lowercase())
    }

    /// Adds a vault. `id`/`dir` are `None` for a brand-new vault (UUIDv7, `Vaults/<id>`); an existing
    /// on-disk vault is adopted by passing its id and directory.
    pub fn add(
        &mut self,
        name: &str,
        color: &str,
        badge: Option<&str>,
        existing: Option<(&str, &str)>,
        now_ms: i64,
    ) -> Result<VaultEntry> {
        let name = clean_name(name)?;
        if !valid_color(color) || self.entries.len() >= MAX_VAULTS || self.name_taken(&name, None) {
            return Err(Error::InvalidInput);
        }
        let badge = match badge {
            Some(b) => clean_badge(b)?,
            None => None,
        };
        let (id, dir) = match existing {
            Some((id, dir)) => (id.to_string(), dir.to_string()),
            None => {
                let id = uuid::Uuid::now_v7().to_string();
                let dir = format!("Vaults/{id}");
                (id, dir)
            }
        };
        if id.is_empty()
            || !valid_dir(&dir)
            || self.entries.iter().any(|e| e.id == id || e.dir == dir)
        {
            return Err(Error::InvalidInput);
        }
        let entry = VaultEntry {
            id,
            name,
            color: color.to_string(),
            badge,
            dir,
            created_at: now_ms,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Renames/recolors/re-badges a vault. `badge`: `None` keeps it, `Some("")` clears it.
    pub fn update(
        &mut self,
        id: &str,
        name: Option<&str>,
        color: Option<&str>,
        badge: Option<&str>,
    ) -> Result<VaultEntry> {
        let name = name.map(clean_name).transpose()?;
        if let Some(n) = &name {
            if self.name_taken(n, Some(id)) {
                return Err(Error::InvalidInput);
            }
        }
        if color.is_some_and(|c| !valid_color(c)) {
            return Err(Error::InvalidInput);
        }
        let badge = badge.map(clean_badge).transpose()?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        if let Some(n) = name {
            entry.name = n;
        }
        if let Some(c) = color {
            entry.color = c.to_string();
        }
        if let Some(b) = badge {
            entry.badge = b;
        }
        Ok(entry.clone())
    }

    /// Forgets a vault (the caller deletes its files). Returns the removed entry.
    pub fn remove(&mut self, id: &str) -> Result<VaultEntry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        Ok(self.entries.remove(pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_update_remove_round_trip() {
        let mut r = VaultRegistry::default();
        let a = r.add("Personal", "#2563EB", None, None, 1).unwrap();
        assert_eq!(a.dir, format!("Vaults/{}", a.id));
        let b = r.add("Work", "#10B981", Some("💼"), None, 2).unwrap();
        let r2 = VaultRegistry::from_bytes(&r.to_bytes().unwrap()).unwrap();
        assert_eq!(r2, r);
        assert_eq!(r2.entries().len(), 2);

        let u = r
            .update(&b.id, Some("Clients"), Some("#ff0000"), Some(""))
            .unwrap();
        assert_eq!(
            (u.name.as_str(), u.color.as_str(), u.badge.clone()),
            ("Clients", "#ff0000", None)
        );
        assert_eq!(r.update(&b.id, None, None, None).unwrap(), u);
        assert_eq!(r.remove(&a.id).unwrap().name, "Personal");
        assert_eq!(r.remove(&a.id).err(), Some(Error::NotFound));
        assert_eq!(r.entries().len(), 1);
    }

    #[test]
    fn adopts_a_legacy_vault_in_place() {
        let mut r = VaultRegistry::default();
        let e = r
            .add("Personal", "#2563EB", None, Some(("default", "Vault")), 0)
            .unwrap();
        assert_eq!((e.id.as_str(), e.dir.as_str()), ("default", "Vault"));
        assert!(r.get("default").is_some());
    }

    #[test]
    fn rejects_invalid_input() {
        let mut r = VaultRegistry::default();
        r.add("Personal", "#2563EB", None, None, 0).unwrap();
        for (name, color) in [
            ("", "#2563EB"),
            ("   ", "#2563EB"),
            ("personal", "#2563EB"), // duplicate, case-insensitive
            ("Bad\nname", "#2563EB"),
            ("X", "blue"),
            ("X", "#12345"),
            ("X", "#GGGGGG"),
        ] {
            assert_eq!(
                r.add(name, color, None, None, 0).err(),
                Some(Error::InvalidInput),
                "{name}/{color}"
            );
        }
        assert!(r.add("X", "#000000", Some("12345"), None, 0).is_err());
        for dir in [
            "", "/abs", "../x", "a/../b", "a//b", "a b", "a/./b", "Vault\\x",
        ] {
            assert!(
                r.add("Y", "#000000", None, Some(("id", dir)), 0).is_err(),
                "{dir}"
            );
        }
        // Duplicate id / directory.
        let first = r.entries()[0].clone();
        assert!(r
            .add("Z", "#000000", None, Some((&first.id, "Other")), 0)
            .is_err());
        assert!(r
            .add("Z", "#000000", None, Some(("other", &first.dir)), 0)
            .is_err());
        // Renaming onto another vault's name fails; onto its own (case change) works.
        let b = r.add("Work", "#000000", None, None, 0).unwrap();
        assert!(r.update(&b.id, Some("PERSONAL"), None, None).is_err());
        assert!(r.update(&b.id, Some("WORK"), None, None).is_ok());
        assert!(r.update("nope", Some("Q"), None, None).is_err());
        assert_eq!(r.entries().len(), 2);
    }

    #[test]
    fn caps_the_number_of_vaults() {
        let mut r = VaultRegistry::default();
        for i in 0..MAX_VAULTS {
            r.add(&format!("V{i}"), "#000000", None, None, 0).unwrap();
        }
        assert!(r.add("One more", "#000000", None, None, 0).is_err());
    }

    #[test]
    fn parsing_is_strict() {
        assert_eq!(
            VaultRegistry::from_bytes(b"").unwrap(),
            VaultRegistry::default()
        );
        assert_eq!(
            VaultRegistry::from_bytes(b"not json").err(),
            Some(Error::Corrupted)
        );
        assert_eq!(
            VaultRegistry::from_bytes(br#"{"version":2,"vaults":[]}"#).err(),
            Some(Error::UnsupportedVersion)
        );
        // Path traversal smuggled through a tampered file is refused.
        let evil = br##"{"version":1,"vaults":[{"id":"a","name":"A","color":"#000000","badge":null,"dir":"../../x","created_at":0}]}"##;
        assert_eq!(
            VaultRegistry::from_bytes(evil).err(),
            Some(Error::Corrupted)
        );
        let dup = br##"{"version":1,"vaults":[{"id":"a","name":"A","color":"#000000","badge":null,"dir":"a","created_at":0},{"id":"b","name":"a","color":"#000000","badge":null,"dir":"b","created_at":0}]}"##;
        assert_eq!(VaultRegistry::from_bytes(dup).err(), Some(Error::Corrupted));
    }
}
