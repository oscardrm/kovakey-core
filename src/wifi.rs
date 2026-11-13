//! Wi-Fi QR payload (the de-facto `WIFI:` format read by the iOS and Android camera apps).
//!
//! The payload contains the network password, so it is returned in a [`Zeroizing`] string and
//! must only be rendered while the vault is unlocked. QR *rendering* is left to each platform
//! (CoreImage, ZXing, a JS library) so `vault-core` stays free of imaging code.
//!
//! Which item fields feed the payload follows the Wi-Fi preset layout (see `presets.rs`):
//! network name = first `text` field, security = second `text` field (optional), password = first
//! `password` field. Users may rename or reorder fields, but keep that shape.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::ops::VaultStore;

/// Authentication type written to the `T:` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiSecurity {
    /// WPA / WPA2 / WPA3 personal.
    Wpa,
    /// Legacy WEP.
    Wep,
    /// Open network (no password).
    Open,
}

impl WifiSecurity {
    /// Interpret the free-text "Security" field. Anything mentioning WPA (WPA2, WPA3, "WPA2/WPA3
    /// PSK", ...) is `Wpa`; `WEP` is `Wep`; `none` / `open` / `nopass` / blank is `Open`; an
    /// unrecognised text is `Wpa` when a password is set (the common case) and `Open` otherwise.
    pub fn parse(text: &str, has_password: bool) -> Self {
        let t = text.trim().to_ascii_lowercase();
        if t.contains("wpa") || t.contains("sae") {
            Self::Wpa
        } else if t.contains("wep") {
            Self::Wep
        } else if t.is_empty() || matches!(t.as_str(), "none" | "open" | "nopass" | "no password") {
            if has_password {
                Self::Wpa
            } else {
                Self::Open
            }
        } else if has_password {
            Self::Wpa
        } else {
            Self::Open
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::Wpa => "WPA",
            Self::Wep => "WEP",
            Self::Open => "nopass",
        }
    }
}

/// Escape the characters that are special in the `WIFI:` format; values made only of hex digits
/// are quoted so scanners do not read them as hex-encoded text.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    if !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit()) {
        format!("\"{out}\"")
    } else {
        out
    }
}

/// Build the `WIFI:` payload. An empty network name is `InvalidInput`; an open network ignores
/// the password.
pub fn wifi_payload(
    ssid: &str,
    password: &str,
    security: WifiSecurity,
    hidden: bool,
) -> Result<Zeroizing<String>> {
    if ssid.trim().is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut out = Zeroizing::new(format!("WIFI:T:{};S:{};", security.token(), escape(ssid)));
    if security != WifiSecurity::Open {
        out.push_str(&format!("P:{};", escape(password)));
    }
    if hidden {
        out.push_str("H:true;");
    }
    out.push(';');
    Ok(out)
}

/// Payload for a stored Wi-Fi item (see the module docs for the field layout).
pub fn item_wifi_payload<S: VaultStore>(store: &S, item_id: &str) -> Result<Zeroizing<String>> {
    let detail = store.get_item(item_id)?;
    let mut texts = detail.fields.iter().filter(|f| f.kind == "text");
    let ssid = texts
        .next()
        .map(|f| f.value.clone().unwrap_or_default())
        .unwrap_or_default();
    let security_text = texts
        .next()
        .map(|f| f.value.clone().unwrap_or_default())
        .unwrap_or_default();
    let password = match detail.fields.iter().find(|f| f.kind == "password") {
        Some(f) => store.reveal_field(item_id, &f.id)?,
        None => Zeroizing::new(String::new()),
    };
    let security = WifiSecurity::parse(&security_text, !password.is_empty());
    wifi_payload(&ssid, &password, security, false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mem_store::MemStore;
    use crate::models::ItemType;
    use crate::ops::{FieldInput, NewItem, WriteCtx};

    #[test]
    fn known_payloads() {
        let p = wifi_payload("Home", "hunter22x", WifiSecurity::Wpa, false).unwrap();
        assert_eq!(p.as_str(), "WIFI:T:WPA;S:Home;P:hunter22x;;");
        let p = wifi_payload("Coffee", "ignored", WifiSecurity::Open, false).unwrap();
        assert_eq!(p.as_str(), "WIFI:T:nopass;S:Coffee;;");
        let p = wifi_payload("Old", "wepky", WifiSecurity::Wep, true).unwrap();
        assert_eq!(p.as_str(), "WIFI:T:WEP;S:Old;P:wepky;H:true;;");
    }

    #[test]
    fn special_characters_are_escaped() {
        let p = wifi_payload(r#"a;b,c:d"e\f"#, r#"p;w"#, WifiSecurity::Wpa, false).unwrap();
        assert_eq!(p.as_str(), r#"WIFI:T:WPA;S:a\;b\,c\:d\"e\\f;P:p\;w;;"#);
    }

    #[test]
    fn hex_only_values_are_quoted() {
        let p = wifi_payload("deadbeef", "12345678", WifiSecurity::Wpa, false).unwrap();
        assert_eq!(p.as_str(), r#"WIFI:T:WPA;S:"deadbeef";P:"12345678";;"#);
    }

    #[test]
    fn empty_ssid_is_rejected() {
        assert_eq!(
            wifi_payload("  ", "x", WifiSecurity::Wpa, false).err(),
            Some(Error::InvalidInput)
        );
    }

    #[test]
    fn security_text_is_interpreted_leniently() {
        for (text, pw, want) in [
            ("WPA2", true, WifiSecurity::Wpa),
            ("WPA3 Personal", true, WifiSecurity::Wpa),
            ("wpa2/wpa3 psk", true, WifiSecurity::Wpa),
            ("WEP", true, WifiSecurity::Wep),
            ("None", false, WifiSecurity::Open),
            ("Open", false, WifiSecurity::Open),
            ("", false, WifiSecurity::Open),
            ("", true, WifiSecurity::Wpa),
            ("something else", true, WifiSecurity::Wpa),
            ("something else", false, WifiSecurity::Open),
        ] {
            assert_eq!(WifiSecurity::parse(text, pw), want, "{text:?} pw={pw}");
        }
    }

    #[test]
    fn payload_for_a_stored_item_uses_the_preset_layout() {
        let mut store = MemStore::new();
        let ctx = WriteCtx {
            now_ms: 1,
            device_id: "dev",
        };
        let mut item = NewItem::new(ItemType::Credential, "Home Wi-Fi");
        item.fields = vec![
            FieldInput::new("Network name", "text", "Casa 5G", false),
            FieldInput::new("Password", "password", "fake-wifi-pass", true),
            FieldInput::new("Security", "text", "WPA3", false),
        ];
        let id = store.create_item(&ctx, &item).unwrap();
        let p = item_wifi_payload(&store, &id).unwrap();
        assert_eq!(p.as_str(), "WIFI:T:WPA;S:Casa 5G;P:fake-wifi-pass;;");
        assert_eq!(
            item_wifi_payload(&store, "missing").err(),
            Some(Error::NotFound)
        );
    }
}
