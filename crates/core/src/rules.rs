//! Built-in rules (`rules/rules.json`), the strict-only org overlay and user settings.

use crate::model::{Category, Os, Tier};
use crate::platform::{self, KnownDirs};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const ALLOWED_PROGRAMS: &[&str] = &[
    "npm", "pnpm", "yarn", "brew", "docker", "git", "xcrun", "pip3", "uv", "dotnet",
];
#[cfg(test)]
const TOKENS: &[&str] = &[
    "{home}",
    "{localappdata}",
    "{appdata}",
    "{temp}",
    "{npm_cache}",
];

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum OsFilter {
    Any,
    Macos,
    Windows,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TargetMethod {
    Vault,
    /// Non-undoable only.
    Command(Vec<String>),
    PruneOlderThan(u32),
    Report,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Target {
    pub id: String,
    pub os: OsFilter,
    pub title: String,
    pub category: Category,
    /// Tokens: {home} {localappdata} {appdata} {temp} {npm_cache}
    pub path: String,
    pub tier: Tier,
    pub method: TargetMethod,
    pub rebuild: String,
    pub min_idle_days: u32,
    /// Exe stems or argv script stems; while any runs, the move is refused.
    pub owner_processes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Retention {
    pub safe_days: u32,
    pub review_days: u32,
    pub volume_backup_days: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildDirRule {
    pub name: String,
    /// Literal names, or "*.ext" (extension match only).
    pub requires_any: Vec<String>,
    pub lockfiles: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Thresholds {
    pub free_pct: u8,
    pub swap_pct: u8,
    pub growth_gb: u32,
}

#[derive(Clone, Debug)]
pub struct Rules {
    pub targets: Vec<Target>,
    pub build_dirs: Vec<BuildDirRule>,
    pub project_roots: Vec<String>,
    pub safe_idle_days: u32,
    pub recent_days: u32,
    pub known_daemons: Vec<String>,
    pub dev_process_patterns: Vec<String>,
    pub extra_never: Vec<String>,
    pub thresholds: Thresholds,
    pub retention: Retention,
    pub auto_clean: bool,
    /// Some: `actions::execute` refuses everything.
    pub org_overlay_error: Option<String>,
}

/// Shape of rules.json: per-OS project roots, flattened by `builtin`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    targets: Vec<Target>,
    build_dirs: Vec<BuildDirRule>,
    project_roots_macos: Vec<String>,
    project_roots_windows: Vec<String>,
    safe_idle_days: u32,
    recent_days: u32,
    known_daemons: Vec<String>,
    dev_process_patterns: Vec<String>,
    extra_never: Vec<String>,
    thresholds: Thresholds,
    retention: Retention,
    auto_clean: bool,
}

/// Org overlay: `<data_dir>/org-overlay.json`, shipped by IT. Strict-only.
#[derive(Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Overlay {
    pub extra_never: Vec<String>,
    pub project_roots: Vec<String>,
    pub tier_overrides: HashMap<String, Tier>,
    pub safe_idle_days: Option<u32>,
    pub recent_days: Option<u32>,
}

/// `<data_dir>/settings.json`: project roots, retention in range, auto-clean.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct UserSettings {
    pub project_roots: Vec<String>,
    pub retention: Option<Retention>,
    pub auto_clean: bool,
}

/// Rules for the current OS: `project_roots` holds only this OS's defaults.
/// `targets` keeps every OS; filter with `for_os`.
pub fn builtin() -> Rules {
    let raw: RawRules =
        serde_json::from_str(include_str!("../../../rules/rules.json")).expect("rules.json");
    let project_roots = match Os::current() {
        Os::Macos => raw.project_roots_macos,
        Os::Windows => raw.project_roots_windows,
    };
    Rules {
        targets: raw.targets,
        build_dirs: raw.build_dirs,
        project_roots,
        safe_idle_days: raw.safe_idle_days,
        recent_days: raw.recent_days,
        known_daemons: raw.known_daemons,
        dev_process_patterns: raw.dev_process_patterns,
        extra_never: raw.extra_never,
        thresholds: raw.thresholds,
        retention: raw.retention,
        auto_clean: raw.auto_clean,
        org_overlay_error: None,
    }
}

fn union(base: &mut Vec<String>, add: Vec<String>) {
    for s in add {
        if !base.contains(&s) {
            base.push(s);
        }
    }
}

pub fn merge(mut base: Rules, o: Overlay) -> Result<Rules, String> {
    union(&mut base.extra_never, o.extra_never);
    union(&mut base.project_roots, o.project_roots);
    for (id, tier) in o.tier_overrides {
        let t = base
            .targets
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| format!("overlay names unknown target {id}"))?;
        if tier < t.tier {
            return Err(format!("overlay can't loosen {id}"));
        }
        t.tier = tier;
    }
    for (name, new, cur) in [
        ("safe_idle_days", o.safe_idle_days, &mut base.safe_idle_days),
        ("recent_days", o.recent_days, &mut base.recent_days),
    ] {
        if let Some(n) = new {
            if n < *cur {
                return Err(format!("overlay can't loosen {name}"));
            }
            *cur = n;
        }
    }
    Ok(base)
}

pub fn apply_user(mut base: Rules, s: UserSettings) -> Result<Rules, String> {
    if let Some(r) = s.retention {
        for (name, v, lo, hi) in [
            ("safe_days", r.safe_days, 0, 30),
            ("review_days", r.review_days, 7, 90),
            ("volume_backup_days", r.volume_backup_days, 7, 90),
        ] {
            if !(lo..=hi).contains(&v) {
                return Err(format!("{name} must be {lo} to {hi}"));
            }
        }
        base.retention = r;
    }
    union(&mut base.project_roots, s.project_roots);
    base.auto_clean = s.auto_clean;
    Ok(base)
}

fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Result<Option<T>, String> {
    match std::fs::read_to_string(p) {
        Ok(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Returns the rules and user-settings warnings. A bad org overlay sets
/// `org_overlay_error` (built-in rules stay, actions are refused); it never
/// silently falls back.
pub fn load(data_dir: &Path) -> (Rules, Vec<String>) {
    let mut rules = builtin();
    let mut warnings = vec![];
    let org = data_dir.join("org-overlay.json");
    match read_json::<Overlay>(&org).and_then(|o| match o {
        Some(o) => merge(rules.clone(), o),
        None => Ok(rules.clone()),
    }) {
        Ok(r) => rules = r,
        Err(e) => rules.org_overlay_error = Some(format!("org-overlay.json: {e}")),
    }
    let user = data_dir.join("settings.json");
    match read_json::<UserSettings>(&user).and_then(|s| match s {
        Some(s) => apply_user(rules.clone(), s),
        None => Ok(rules.clone()),
    }) {
        Ok(r) => rules = r,
        Err(e) => warnings.push(format!("settings.json ignored: {e}")),
    }
    (rules, warnings)
}

/// Atomic: temp file in the same dir, then rename over the old one.
pub fn save_user(data_dir: &Path, s: &UserSettings) -> Result<(), String> {
    let e = |e: std::io::Error| e.to_string();
    std::fs::create_dir_all(data_dir).map_err(e)?;
    let tmp = data_dir.join("settings.json.tmp");
    let json = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json).map_err(e)?;
    // Replacing the old file is intended here.
    std::fs::rename(&tmp, data_dir.join("settings.json")).map_err(e)
}

pub fn for_os(r: &Rules, os: Os) -> Vec<&Target> {
    r.targets
        .iter()
        .filter(|t| match t.os {
            OsFilter::Any => true,
            OsFilter::Macos => os == Os::Macos,
            OsFilter::Windows => os == Os::Windows,
        })
        .collect()
}

/// Leading token (or an absolute path) plus `/`-separated rest. None if a
/// token is unavailable or unknown.
pub fn expand(path: &str, d: &KnownDirs, npm_cache: Option<&Path>) -> Option<PathBuf> {
    let (head, rest) = match path.split_once('/') {
        Some((h, r)) => (h, r),
        None => (path, ""),
    };
    if rest.contains(['{', '}']) {
        return None;
    }
    let base = if !head.starts_with('{') {
        let p = PathBuf::from(path);
        return p.is_absolute().then_some(p);
    } else {
        match head {
            "{home}" => d.home.clone(),
            "{localappdata}" => d.local_app_data.clone()?,
            "{appdata}" => d.app_data.clone()?,
            "{temp}" => d.temp.clone(),
            "{npm_cache}" => match npm_cache {
                Some(p) => p.to_path_buf(),
                None if platform::CURRENT_OS == Os::Windows => {
                    d.local_app_data.clone()?.join("npm-cache")
                }
                None => d.home.join(".npm"),
            },
            _ => return None,
        }
    };
    Some(
        rest.split('/')
            .filter(|c| !c.is_empty())
            .fold(base, |p, c| p.join(c)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Os, Tier};
    use crate::platform::KnownDirs;
    use std::path::{Path, PathBuf};

    fn dirs() -> KnownDirs {
        let h = PathBuf::from("/h");
        KnownDirs {
            home: h.clone(),
            local_app_data: Some(h.join("L")),
            app_data: Some(h.join("A")),
            temp: h.join("T"),
            personal: vec![],
            cloud_roots: vec![],
        }
    }
    fn write(d: &Path, name: &str, s: &str) {
        std::fs::write(d.join(name), s).unwrap();
    }
    fn target<'a>(r: &'a Rules, id: &str) -> &'a Target {
        r.targets.iter().find(|t| t.id == id).unwrap()
    }

    #[test]
    fn builtin_parses_and_commands_allowlisted() {
        let r = builtin();
        assert!(!r.targets.is_empty() && r.org_overlay_error.is_none());
        let mut n = 0;
        for t in &r.targets {
            if let TargetMethod::Command(argv) = &t.method {
                n += 1;
                assert!(ALLOWED_PROGRAMS.contains(&argv[0].as_str()), "{}", t.id);
            }
        }
        assert_eq!(n, 4); // brew, xcrun, pnpm on each OS
        assert!(ALLOWED_PROGRAMS.contains(&"docker"));
        assert!(r.project_roots.iter().all(|p| p.starts_with("{home}")));
    }

    #[test]
    fn every_target_path_expands_on_its_os() {
        let r = builtin();
        let d = dirs();
        for t in for_os(&r, Os::current()) {
            assert!(expand(&t.path, &d, None).is_some(), "{}", t.id);
        }
        for p in &r.project_roots {
            assert!(expand(p, &d, None).is_some(), "{p}");
        }
    }

    #[test]
    fn windows_targets_use_only_known_tokens() {
        let r = builtin();
        for t in r.targets.iter().filter(|t| t.os != OsFilter::Macos) {
            let mut rest = t.path.as_str();
            let mut toks = 0;
            while let Some(i) = rest.find('{') {
                let j = rest[i..].find('}').unwrap() + i;
                assert!(TOKENS.contains(&&rest[i..=j]), "{}: {}", t.id, t.path);
                rest = &rest[j + 1..];
                toks += 1;
            }
            assert_eq!(toks, 1, "{}", t.id);
            assert!(
                t.path.starts_with('{') && !t.path.contains('\\'),
                "{}",
                t.id
            );
        }
    }

    #[test]
    fn expand_tokens_and_npm_fallback() {
        let d = dirs();
        assert_eq!(
            expand("{home}/a/b", &d, None),
            Some(PathBuf::from("/h").join("a").join("b"))
        );
        assert_eq!(expand("{bogus}/a", &d, None), None);
        assert_eq!(expand("{home}/{temp}", &d, None), None);
        let mut d2 = d.clone();
        d2.local_app_data = None;
        assert_eq!(expand("{localappdata}/x", &d2, None), None);
        let c = Path::new("/c");
        assert_eq!(
            expand("{npm_cache}/_npx", &d, Some(c)),
            Some(c.join("_npx"))
        );
        let def = expand("{npm_cache}", &d, None).unwrap();
        assert_eq!(
            def,
            if Os::current() == Os::Macos {
                PathBuf::from("/h/.npm")
            } else {
                PathBuf::from("/h/L/npm-cache")
            }
        );
    }

    #[test]
    fn no_windows_target_on_macos_and_vice_versa() {
        let r = builtin();
        let m = for_os(&r, Os::Macos);
        let w = for_os(&r, Os::Windows);
        assert!(m.iter().all(|t| t.os != OsFilter::Windows));
        assert!(w.iter().all(|t| t.os != OsFilter::Macos));
        assert!(m.iter().any(|t| t.id == "xcode-deriveddata"));
        assert!(w.iter().any(|t| t.id == "windows-temp"));
        assert!(!w.iter().any(|t| t.id == "xcode-deriveddata"));
        assert!(!m.iter().any(|t| t.id == "windows-temp"));
    }

    #[test]
    fn overlay_can_tighten() {
        let o = Overlay {
            extra_never: vec!["{home}/secret".into()],
            project_roots: vec!["{home}/work".into()],
            tier_overrides: [("chrome-cache-macos".to_string(), Tier::Protected)].into(),
            safe_idle_days: Some(60),
            recent_days: Some(20),
        };
        let base = builtin();
        let r = merge(base, o).unwrap();
        assert_eq!(r.extra_never, vec!["{home}/secret"]);
        assert!(r.project_roots.contains(&"{home}/work".to_string()));
        assert_eq!(target(&r, "chrome-cache-macos").tier, Tier::Protected);
        assert_eq!((r.safe_idle_days, r.recent_days), (60, 20));
    }

    #[test]
    fn overlay_cannot_loosen() {
        let ov = |f: &dyn Fn(&mut Overlay)| {
            let mut o = Overlay::default();
            f(&mut o);
            merge(builtin(), o)
        };
        let e = ov(&|o| {
            o.tier_overrides
                .insert("chrome-cache-macos".into(), Tier::Safe);
        })
        .unwrap_err();
        assert!(e.contains("overlay can't loosen chrome-cache-macos"), "{e}");
        assert!(
            ov(&|o| {
                o.tier_overrides.insert("nope".into(), Tier::Protected);
            })
            .is_err()
        );
        assert!(ov(&|o| o.safe_idle_days = Some(29)).is_err());
        assert!(ov(&|o| o.recent_days = Some(13)).is_err());
        assert!(ov(&|o| o.safe_idle_days = Some(30)).is_ok());
    }

    #[test]
    fn overlay_has_no_command_field() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "org-overlay.json",
            r#"{"commands":[["rm","-rf","/"]]}"#,
        );
        assert!(load(t.path()).0.org_overlay_error.is_some());
        assert!(serde_json::from_str::<Overlay>(r#"{"targets":[]}"#).is_err());
    }

    #[test]
    fn overlay_has_no_retention_field() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "org-overlay.json",
            r#"{"retention":{"safe_days":0,"review_days":7,"volume_backup_days":7}}"#,
        );
        assert!(load(t.path()).0.org_overlay_error.is_some());
    }

    #[test]
    fn bad_org_overlay_blocks_actions_not_scans() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "org-overlay.json", "\u{0}garbage{{");
        let (r, _) = load(t.path());
        assert!(r.org_overlay_error.is_some());
        assert!(!r.targets.is_empty());
        // missing is fine, valid overlay applies
        let t2 = tempfile::tempdir().unwrap();
        assert!(load(t2.path()).0.org_overlay_error.is_none());
        write(
            t2.path(),
            "org-overlay.json",
            r#"{"extra_never":["{home}/x"],"safe_idle_days":45}"#,
        );
        let (r, _) = load(t2.path());
        assert!(
            r.org_overlay_error.is_none() && r.safe_idle_days == 45 && r.extra_never.len() == 1
        );
        // loosening in the file is an error
        write(t2.path(), "org-overlay.json", r#"{"safe_idle_days":1}"#);
        assert!(load(t2.path()).0.org_overlay_error.is_some());
    }

    #[test]
    fn bad_user_settings_is_warning_and_defaults() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "settings.json", "not json");
        let (r, w) = load(t.path());
        assert_eq!(w.len(), 1);
        assert_eq!(r.retention, builtin().retention);
        assert!(!r.auto_clean);
        // out-of-range retention is also a warning, defaults kept
        write(
            t.path(),
            "settings.json",
            r#"{"retention":{"safe_days":99,"review_days":30,"volume_backup_days":30}}"#,
        );
        let (r, w) = load(t.path());
        assert_eq!(w.len(), 1);
        assert_eq!(r.retention.safe_days, 3);
    }

    #[test]
    fn user_settings_round_trip() {
        let t = tempfile::tempdir().unwrap();
        let s = UserSettings {
            project_roots: vec!["D:/work".into()],
            retention: Some(Retention {
                safe_days: 0,
                review_days: 7,
                volume_backup_days: 90,
            }),
            auto_clean: true,
        };
        save_user(t.path(), &s).unwrap();
        save_user(t.path(), &s).unwrap(); // replaces
        let (r, w) = load(t.path());
        assert!(w.is_empty(), "{w:?}");
        assert!(r.auto_clean && r.project_roots.contains(&"D:/work".to_string()));
        assert_eq!(r.retention.volume_backup_days, 90);
        assert!(!t.path().join("settings.json.tmp").exists());
        assert!(serde_json::from_str::<UserSettings>(r#"{"extra_never":[]}"#).is_err());
    }

    #[test]
    fn retention_clamped_to_allowed_ranges() {
        let with = |s, r, v| {
            apply_user(
                builtin(),
                UserSettings {
                    retention: Some(Retention {
                        safe_days: s,
                        review_days: r,
                        volume_backup_days: v,
                    }),
                    ..Default::default()
                },
            )
        };
        assert!(with(99, 30, 30).is_err());
        assert!(with(3, 3, 30).is_err());
        assert!(with(3, 30, 91).is_err());
        assert!(with(3, 30, 6).is_err());
        assert!(with(0, 7, 7).is_ok());
        assert!(with(30, 90, 90).is_ok());
    }

    #[test]
    fn build_dir_names_match_never_list() {
        let mut a: Vec<_> = builtin()
            .build_dirs
            .iter()
            .map(|b| b.name.clone())
            .collect();
        let mut b: Vec<_> = crate::never::BUILD_DIR_NAMES
            .iter()
            .map(|s| s.to_string())
            .collect();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn every_vault_cache_target_except_playwright_has_owner_processes() {
        for t in &builtin().targets {
            if t.method == TargetMethod::Vault && !t.id.starts_with("playwright") {
                assert!(!t.owner_processes.is_empty(), "{}", t.id);
            }
        }
    }

    #[test]
    fn every_command_target_is_marked_non_undoable_in_title_or_reason() {
        for t in &builtin().targets {
            if matches!(t.method, TargetMethod::Command(_)) {
                assert!(t.title.contains("can't be undone"), "{}", t.id);
            }
        }
    }

    #[test]
    fn ctx_expands_extra_never_and_fails_closed() {
        use crate::run::SystemRunner;
        let run = SystemRunner { tool_dirs: vec![] };
        let mut r = builtin();
        r.extra_never = vec!["{home}/s".into()];
        let c = crate::Ctx::new(
            Os::current(),
            dirs(),
            PathBuf::from("/d"),
            &run,
            &r,
            std::time::SystemTime::now(),
            1,
        );
        assert_eq!(c.extra_never, vec![PathBuf::from("/h/s")]);
        assert!(c.ctx_error.is_none());
        assert_eq!(c.never_cfg(&[]).extra_never.len(), 1);
        r.extra_never = vec!["{bogus}/s".into()];
        let c = crate::Ctx::new(
            Os::current(),
            dirs(),
            PathBuf::from("/d"),
            &run,
            &r,
            std::time::SystemTime::now(),
            1,
        );
        assert_eq!(
            c.ctx_error.as_deref(),
            Some("can't resolve org never-path {bogus}/s")
        );
    }
}
