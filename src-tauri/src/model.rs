//! Shared data model for accounts, drafts, and settings.
//!
//! Secrets are wrapped in [`Zeroizing`] so they are wiped from memory on drop —
//! the vault keeps them decrypted only inside the Rust core, never in the UI.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::SHA1
    }
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Self::SHA1),
            "SHA256" => Some(Self::SHA256),
            "SHA512" => Some(Self::SHA512),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA1 => "SHA1",
            Self::SHA256 => "SHA256",
            Self::SHA512 => "SHA512",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Kind {
    Totp,
    Hotp { #[serde(default)] counter: u64 },
}

impl Kind {
    pub fn is_hotp(&self) -> bool {
        matches!(self, Kind::Hotp { .. })
    }
}

fn six() -> u32 {
    6
}
fn thirty() -> u32 {
    30
}
fn totp_kind() -> Kind {
    Kind::Totp
}

/// A stored account. Serialized only inside the encrypted vault payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub issuer: String,
    pub name: String,
    #[serde(default)]
    pub group: String, // free-form group label; "" = ungrouped
    #[serde(default)]
    pub flavor: Flavor,
    pub secret: Zeroizing<Vec<u8>>,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "six")]
    pub digits: u32,
    #[serde(default = "thirty")]
    pub period: u32,
    #[serde(default = "totp_kind")]
    pub kind: Kind,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub sort: u64,
    #[serde(default)]
    pub created_at: u64,
}

impl Account {
    pub fn matches_dup(&self, d: &Draft) -> bool {
        self.secret.as_slice() == d.secret.as_slice()
            || (self.issuer.eq_ignore_ascii_case(&d.issuer) && self.name.eq_ignore_ascii_case(&d.name))
    }
}

/// An incoming account (manual entry, QR, import) before it is stored.
/// Code flavor for issuers with non-standard token rendering.
/// `Standard` follows RFC 6238 digit output; `Steam` renders 5 characters
/// from Steam's custom alphabet (same HMAC-SHA1/30s core).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum Flavor {
    #[default]
    Standard,
    Steam,
}

impl Flavor {
    pub fn parse(s: &str) -> Option<Flavor> {
        match s.trim().to_ascii_lowercase().as_str() {
            "standard" | "" => Some(Flavor::Standard),
            "steam" => Some(Flavor::Steam),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Flavor::Standard => "standard",
            Flavor::Steam => "steam",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Draft {
    pub issuer: String,
    pub name: String,
    pub secret: Zeroizing<Vec<u8>>,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "six")]
    pub digits: u32,
    #[serde(default = "thirty")]
    pub period: u32,
    #[serde(default = "totp_kind")]
    pub kind: Kind,
    #[serde(default)]
    pub flavor: Flavor,
    /// Optional group label carried through backups; "" = ungrouped.
    #[serde(default)]
    pub group: String,
}

impl Draft {
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.is_empty() {
            return Err("Secret is empty".into());
        }
        if self.secret.len() < 10 {
            return Err("Secret is too short (minimum 10 bytes / 80 bits)".into());
        }
        if self.issuer.trim().is_empty() && self.name.trim().is_empty() {
            return Err("Account needs at least an issuer or a name".into());
        }
        if !(4..=10).contains(&self.digits) {
            return Err("Digits must be between 4 and 10".into());
        }
        if !self.kind.is_hotp() && !(5..=300).contains(&self.period) {
            return Err("Period must be between 5 and 300 seconds".into());
        }
        Ok(())
    }

    pub fn into_account(self, id: String, sort: u64, created_at: u64) -> Account {
        Account {
            id,
            issuer: self.issuer.trim().to_string(),
            name: self.name.trim().to_string(),
            secret: self.secret,
            algorithm: self.algorithm,
            digits: self.digits,
            period: if self.period == 0 { 30 } else { self.period },
            kind: self.kind,
            flavor: self.flavor,
            group: self.group.trim().to_string(),
            pinned: false,
            sort,
            created_at,
        }
    }
}

/// What the UI sends when adding an account manually.
#[derive(Debug, Deserialize)]
pub struct DraftIn {
    pub issuer: String,
    pub name: String,
    pub secret: String,
    pub group: Option<String>,
    pub flavor: Option<String>, // "standard" (default) | "steam"
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
    pub kind: Option<String>,
    pub counter: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_theme")]
    pub theme: String, // "system" | "light" | "dark"
    #[serde(default = "default_density")]
    pub density: String, // "compact" | "comfortable"
    #[serde(default = "default_font_scale")]
    pub font_scale: u32, // 80..=140 percent
    #[serde(default)]
    pub sort_alpha: bool,
    #[serde(default = "default_true")]
    pub hide_codes: bool,
    #[serde(default = "default_lock_minutes")]
    pub auto_lock_minutes: u64, // 0 = disabled
    #[serde(default = "default_true")]
    pub lock_on_minimize: bool,
    #[serde(default = "default_view_mode")]
    pub view_mode: String, // "rows" | "tiles"
    #[serde(default = "default_true")]
    pub show_timer_number: bool,
    #[serde(default)]
    pub grouped_view: bool,
    #[serde(default = "default_true")]
    pub tray: bool,
    #[serde(default)]
    pub window: Option<WindowGeo>,
}

fn default_view_mode() -> String {
    "rows".into()
}

fn default_theme() -> String {
    "system".into()
}
fn default_density() -> String {
    "compact".into()
}
fn default_font_scale() -> u32 {
    100
}
fn default_true() -> bool {
    true
}
fn default_lock_minutes() -> u64 {
    5
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            density: default_density(),
            font_scale: default_font_scale(),
            sort_alpha: false,
            hide_codes: true,
            auto_lock_minutes: default_lock_minutes(),
            lock_on_minimize: true,
            view_mode: default_view_mode(),
            show_timer_number: true,
            grouped_view: false,
            tray: true,
            window: None,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct WindowGeo {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
