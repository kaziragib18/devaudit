//! Never-touch checks. `forbidden()` is the single gate every action asks; it
//! fails closed (anything it cannot check is forbidden).

use crate::model::Os;
use crate::platform::{self, KnownDirs};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Spec rule 1. Case-insensitive on the name; one optional `*` wildcard.
pub const NEVER_NAMES: &[&str] = &[
    ".env",
    ".env.*",
    ".envrc",
    ".npmrc",
    ".yarnrc.yml",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".git",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.ppk",
    "*.keychain-db",
    "*.kdbx",
    "credentials",
    "credentials.json",
    "service-account*.json",
    "token",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "login data",
    "cookies",
    "web data",
    "local state",
];

/// Spec rule 2, both OSes. Home-relative prefixes.
pub const NEVER_HOME_COMMON: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config/gh",
    ".config/gcloud",
    ".config/op",
    ".password-store",
    ".terraform.d",
    ".vault-token",
    ".claude.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/.credentials.json",
];

pub const NEVER_HOME_MACOS: &[&str] = &[
    "Library/Keychains",
    "Library/CloudStorage",
    "Library/Mobile Documents",
    "Library/Cookies",
    "Library/Mail",
    "Library/Messages",
    "Library/Group Containers/group.com.docker",
    "Library/Containers/com.docker.docker",
    "Library/Application Support/com.apple.TCC",
];

/// Spec rule 2, Windows. Cloud sync roots come from `KnownDirs.cloud_roots`.
pub const NEVER_WINDOWS: &[&str] = &[
    "{appdata}/Microsoft/Credentials",
    "{localappdata}/Microsoft/Credentials",
    "{appdata}/Microsoft/Protect",
    "{localappdata}/Microsoft/Vault",
    "{appdata}/Microsoft/SystemCertificates",
    "{appdata}/gnupg",
    "{appdata}/GitHub CLI",
    "{localappdata}/Microsoft/OneDrive",
    "{localappdata}/Docker/wsl",
    "{localappdata}/Packages",
];

/// Must equal the names in rules.json `build_dirs` (tested in Task 4).
pub const BUILD_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".next",
    ".turbo",
    ".nuxt",
    ".svelte-kit",
    ".parcel-cache",
    "dist",
    "build",
    ".venv",
    "venv",
    "target",
    ".gradle",
    "bin",
    "obj",
];

/// A large node_modules is ~100-300k entries; scan and validate both use this.
pub const SECRET_WALK_LIMIT: usize = 500_000;

pub struct NeverCfg<'a> {
    pub dirs: &'a KnownDirs,
    pub data_dir: &'a Path,
    pub project_roots: &'a [PathBuf],
    /// Expanded org-overlay paths.
    pub extra_never: &'a [PathBuf],
}

/// One optional `*`: `.env.*`, `id_rsa*`, `*.pem`, `service-account*.json`.
fn matches(pat: &str, name: &str) -> bool {
    match pat.split_once('*') {
        None => pat == name,
        Some((pre, post)) => {
            name.len() >= pre.len() + post.len() && name.starts_with(pre) && name.ends_with(post)
        }
    }
}

pub fn name_is_secret(name: &OsStr) -> bool {
    let n = name.to_string_lossy().to_lowercase();
    NEVER_NAMES.iter().any(|p| matches(p, &n))
}

/// Canonical form of `p`, resolving only its deepest existing ancestor. None
/// (fail closed) if an existing part cannot be resolved or `..` remains.
fn resolved(p: &Path) -> Option<PathBuf> {
    let p = std::path::absolute(p).ok()?;
    if p.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    match platform::canon(&p) {
        Ok(c) => Some(c),
        Err(_) if std::fs::symlink_metadata(&p).is_err() => {
            let mut c = resolved(p.parent()?)?;
            c.push(p.file_name()?);
            Some(c)
        }
        Err(_) => None,
    }
}

const UNRESOLVED: &str = "can't resolve protected folders";

/// None if a Windows `{appdata}` / `{localappdata}` token can't be expanded.
fn never_prefixes(d: &KnownDirs) -> Option<Vec<(String, PathBuf)>> {
    let mut v: Vec<(String, PathBuf)> = NEVER_HOME_COMMON
        .iter()
        .map(|r| (r.to_string(), d.home.join(r)))
        .collect();
    match platform::CURRENT_OS {
        Os::Macos => v.extend(
            NEVER_HOME_MACOS
                .iter()
                .map(|r| (r.to_string(), d.home.join(r))),
        ),
        Os::Windows => {
            for r in NEVER_WINDOWS {
                let (base, rest) = if let Some(x) = r.strip_prefix("{appdata}/") {
                    (d.app_data.as_ref(), x)
                } else if let Some(x) = r.strip_prefix("{localappdata}/") {
                    (d.local_app_data.as_ref(), x)
                } else {
                    (Some(&d.home), *r)
                };
                v.push((r.to_string(), base?.join(rest)));
            }
        }
    }
    Some(v)
}

/// `p` is inside, or contains, a never-touch home path, overlay entry, cloud
/// sync root or DevAudit data (`own`: data dir, existing project vaults).
fn never_path_hit(p: &Path, d: &KnownDirs, extra: &[PathBuf], own: &[PathBuf]) -> Option<String> {
    let Some(prefixes) = never_prefixes(d) else {
        return Some(UNRESOLVED.into());
    };
    let named = prefixes
        .iter()
        .map(|(r, q)| (format!("never-touch: {r}"), q))
        .chain(
            extra
                .iter()
                .map(|q| ("never-touch: overlay".to_string(), q)),
        )
        .chain(
            d.cloud_roots
                .iter()
                .map(|q| ("never-touch: cloud sync folder".to_string(), q)),
        );
    for (reason, q) in named {
        if platform::inside(p, q) {
            return Some(reason);
        }
        if platform::inside(q, p) {
            return Some("contains a protected folder".into());
        }
    }
    own.iter()
        .any(|q| platform::inside(q, p))
        .then(|| "contains DevAudit's own data".into())
}

/// First secret-named component of `p` below `skip` components.
fn secret_component(p: &Path, skip: usize) -> bool {
    p.components()
        .skip(skip)
        .any(|c| name_is_secret(c.as_os_str()))
}

pub fn forbidden(path: &Path, cfg: &NeverCfg) -> Option<String> {
    let own = "DevAudit's own data".to_string();
    let vault = |p: &Path| {
        p.components().any(|c| {
            c.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(".devaudit-vault")
        })
    };
    if vault(path) || platform::inside(path, cfg.data_dir) {
        return Some(own);
    }
    let Some(rp) = resolved(path) else {
        return Some("cannot resolve path".into());
    };
    if vault(&rp) {
        return Some(own);
    }

    // 1-2: deepest allowed root containing the path.
    let d = cfg.dirs;
    let roots: Vec<&PathBuf> = cfg
        .project_roots
        .iter()
        .filter(|r| valid_project_root(r, d).is_ok())
        .collect();
    let root = std::iter::once(&d.home)
        .chain(roots.iter().copied())
        .filter(|r| platform::inside(path, r))
        .filter_map(|r| Some((r, resolved(r)?)))
        .max_by_key(|(_, c)| c.components().count());
    let Some((root, rroot)) = root else {
        return Some("outside home and project roots".into());
    };
    if rp.components().count() < rroot.components().count() + 2 {
        return Some("too shallow".into());
    }

    // 3: secret name anywhere below home; outside home, anywhere at all.
    let Some(rhome) = resolved(&d.home) else {
        return Some("cannot resolve path".into());
    };
    let skip = if platform::inside(path, &d.home) {
        rhome.components().count()
    } else {
        0
    };
    if secret_component(&rp, skip) {
        return Some("contains a secret file name".into());
    }

    // 4
    let mut owned = vec![cfg.data_dir.to_path_buf()];
    for r in &roots {
        let v = r.join(".devaudit-vault");
        if std::fs::symlink_metadata(&v).is_ok() {
            owned.push(v);
        }
    }
    if let Some(r) = never_path_hit(path, d, cfg.extra_never, &owned) {
        return Some(r);
    }

    // 5
    if d.personal.iter().any(|q| platform::inside(path, q)) {
        let in_project = roots.iter().any(|r| platform::inside(path, r));
        let build = rp.file_name().is_some_and(|n| {
            let n = n.to_string_lossy();
            BUILD_DIR_NAMES.iter().any(|b| b.eq_ignore_ascii_case(&n))
        });
        if !(in_project && build) {
            return Some("personal folder".into());
        }
    }

    // 6
    match std::fs::symlink_metadata(path) {
        Ok(md) if platform::is_link(&md) => return Some("is a link".into()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Some("cannot inspect path".into()),
    }

    // 7
    match (platform::volume_of(path), platform::volume_of(root)) {
        (Ok(a), Ok(b)) if a == b => {}
        (Ok(_), Ok(_)) => return Some("different drive".into()),
        _ => return Some("cannot check drive".into()),
    }
    if platform::is_mount_point(path) {
        return Some("mount point".into());
    }
    None
}

pub fn valid_project_root(root: &Path, d: &KnownDirs) -> Result<(), String> {
    let Ok(rroot) = platform::canon(root) else {
        return Err("folder not found".into());
    };
    let f = platform::forbidden_roots(d);
    // `inside(e, root)`: the root equals or contains `e`.
    if f.exact.iter().any(|e| platform::inside(e, root)) {
        return Err("drive root, home or system folder".into());
    }
    if f.system
        .iter()
        .any(|s| platform::inside(s, root) || platform::inside(root, s))
    {
        return Err("system folder".into());
    }
    let skip = match resolved(&d.home) {
        Some(h) if platform::inside(root, &d.home) => h.components().count(),
        _ => 0,
    };
    if secret_component(&rroot, skip) {
        return Err("contains a secret file name".into());
    }
    if let Some(r) = never_path_hit(root, d, &[], &[platform::data_dir(d)]) {
        return Err(r);
    }
    if platform::is_mount_point(root) {
        return Err("drive or network share root".into());
    }
    Ok(())
}

/// First secret-named path below `dir`. Never follows links; an unreadable
/// or cloud-placeholder directory, or more than `max_entries` entries, is an
/// error (fail closed).
pub fn find_secret_inside(dir: &Path, max_entries: usize) -> Result<Option<PathBuf>, String> {
    let (mut stack, mut seen) = (vec![dir.to_path_buf()], 0usize);
    while let Some(d) = stack.pop() {
        let err = |e: std::io::Error| format!("cannot read {}: {e}", d.display());
        if platform::is_cloud_placeholder(&std::fs::symlink_metadata(&d).map_err(err)?) {
            return Err(format!("{} is not downloaded", d.display()));
        }
        for ent in std::fs::read_dir(&d).map_err(err)? {
            let ent = ent.map_err(err)?;
            seen += 1;
            if seen > max_entries {
                return Err("too many files to check".into());
            }
            let p = ent.path();
            if name_is_secret(&ent.file_name()) {
                return Ok(Some(p));
            }
            let md = std::fs::symlink_metadata(&p).map_err(err)?;
            if md.is_dir() && !platform::is_link(&md) {
                stack.push(p);
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Env {
        _t: TempDir,
        base: PathBuf,
        dirs: KnownDirs,
        data: PathBuf,
    }

    fn env() -> Env {
        let t = tempfile::tempdir().unwrap();
        let base = t.path().canonicalize().unwrap();
        let home = base.join("home");
        let personal: Vec<PathBuf> = [
            "Desktop",
            "Documents",
            "Downloads",
            "Pictures",
            "Movies",
            "Music",
        ]
        .iter()
        .map(|n| home.join(n))
        .collect();
        fs::create_dir_all(&home).unwrap();
        let dirs = KnownDirs {
            local_app_data: Some(home.join("AppData/Local")),
            app_data: Some(home.join("AppData/Roaming")),
            temp: base.join("tmp"),
            personal,
            cloud_roots: vec![],
            home,
        };
        let data = dirs.home.join(".devaudit");
        Env {
            _t: t,
            base,
            dirs,
            data,
        }
    }

    impl Env {
        fn cfg<'a>(&'a self, roots: &'a [PathBuf], extra: &'a [PathBuf]) -> NeverCfg<'a> {
            NeverCfg {
                dirs: &self.dirs,
                data_dir: &self.data,
                project_roots: roots,
                extra_never: extra,
            }
        }
        fn mk(&self, rel: &str) -> PathBuf {
            let p = self.dirs.home.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
        fn check(&self, p: &Path) -> Option<String> {
            forbidden(p, &self.cfg(&[], &[]))
        }
    }

    fn dir_link(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        let r = std::os::unix::fs::symlink(target, link);
        #[cfg(windows)]
        let r = std::os::windows::fs::symlink_dir(target, link);
        r.is_ok()
    }

    #[test]
    fn secret_names_detected_case_insensitively() {
        for n in [
            ".env",
            ".ENV",
            ".env.production",
            ".npmrc",
            "_netrc",
            "id_ed25519.pub",
            "prod.pem",
            "key.ppk",
            "service-account-x.json",
            "token",
            "app.sqlite3",
            ".git",
            "Login Data",
            "Cookies",
            "Local State",
        ] {
            assert!(name_is_secret(OsStr::new(n)), "{n}");
        }
        for n in [
            "env.ts",
            "tokenizer.json",
            "dist",
            "cookies.ts",
            "keyboard.ts",
            ".envx",
            "service-account.txt",
        ] {
            assert!(!name_is_secret(OsStr::new(n)), "{n}");
        }
    }

    #[test]
    fn forbidden_paths_common() {
        let e = env();
        let h = &e.dirs.home;
        e.mk(".npm/_cacache");
        e.mk(".sshfoo/x");
        e.mk("proj/a");
        for p in [
            h.clone(),
            e.base.join("elsewhere/a/b"),
            h.join("proj"),
            h.join(".ssh/x"),
            h.join(".SSH/x"),
            h.join(".claude/settings.json"),
            h.join("Downloads/x"),
            h.join("proj/.env.local"),
            h.join("proj/a/.git"),
        ] {
            assert!(e.check(&p).is_some(), "{p:?}");
        }
        assert_eq!(e.check(&e.mk("proj/x/y")), None);
        assert_eq!(e.check(&h.join(".npm/_cacache")), None);
        assert_eq!(e.check(&h.join(".sshfoo/x")), None);
    }

    #[test]
    fn reasons_are_short_and_specific() {
        let e = env();
        e.mk("p/q");
        assert_eq!(
            e.check(&e.dirs.home.join(".ssh/x")).unwrap(),
            "never-touch: .ssh"
        );
        assert_eq!(e.check(&e.base).unwrap(), "outside home and project roots");
        assert_eq!(e.check(&e.dirs.home.join("p")).unwrap(), "too shallow");
        assert_eq!(
            e.check(&e.dirs.home.join("p/q/.env")).unwrap(),
            "contains a secret file name"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn forbidden_paths_macos() {
        let e = env();
        e.mk("Library/CloudStorage/x");
        e.mk("Library/Keychains/x");
        e.mk("Library/Caches/x");
        assert!(
            e.check(&e.dirs.home.join("Library/CloudStorage/x"))
                .is_some()
        );
        assert!(e.check(&e.dirs.home.join("Library/Keychains/x")).is_some());
        assert_eq!(e.check(&e.dirs.home.join("Library/Caches/x")), None);
    }

    #[cfg(windows)]
    #[test]
    fn forbidden_paths_windows() {
        let mut e = env();
        e.mk("AppData/Roaming/Microsoft/Protect/x");
        e.mk("AppData/Local/Docker/wsl/x");
        e.mk("OneDrive/x");
        e.dirs.cloud_roots = vec![e.dirs.home.join("OneDrive")];
        for p in [
            "AppData/Roaming/Microsoft/Protect/x",
            "AppData/Local/Docker/wsl/x",
            "OneDrive/x",
        ] {
            assert!(e.check(&e.dirs.home.join(p)).is_some(), "{p}");
        }
    }

    #[test]
    fn cloud_root_forbidden() {
        let mut e = env();
        e.mk("Sync/a/b");
        e.dirs.cloud_roots = vec![e.dirs.home.join("Sync")];
        assert!(e.check(&e.dirs.home.join("Sync/a/b")).is_some());
        assert!(valid_project_root(&e.dirs.home.join("Sync/a"), &e.dirs).is_err());
    }

    #[test]
    fn build_dir_in_project_root_under_documents_is_allowed() {
        let e = env();
        let root = e.mk("Documents/code");
        e.mk("Documents/code/app/node_modules");
        e.mk("Documents/code/app/src");
        e.mk("Documents/other/node_modules");
        let roots = [root];
        let c = e.cfg(&roots, &[]);
        let h = &e.dirs.home;
        assert_eq!(
            forbidden(&h.join("Documents/code/app/node_modules"), &c),
            None
        );
        assert!(forbidden(&h.join("Documents/code/app/src"), &c).is_some());
        assert!(forbidden(&h.join("Documents/other/node_modules"), &c).is_some());
    }

    #[test]
    fn overlay_extra_never_forbidden() {
        let e = env();
        e.mk("company-data/x");
        e.mk("other/x");
        let extra = [e.dirs.home.join("company-data")];
        let c = e.cfg(&[], &extra);
        assert_eq!(
            forbidden(&e.dirs.home.join("company-data/x"), &c).unwrap(),
            "never-touch: overlay"
        );
        assert_eq!(forbidden(&e.dirs.home.join("other/x"), &c), None);
    }

    #[test]
    fn depth_uses_deepest_root() {
        let e = env();
        let dev = e.mk("Dev");
        e.mk("Dev/app/x");
        let roots = [dev];
        let c = e.cfg(&roots, &[]);
        assert_eq!(
            forbidden(&e.dirs.home.join("Dev/app"), &c).unwrap(),
            "too shallow"
        );
        assert_eq!(forbidden(&e.dirs.home.join("Dev/app/x"), &c), None);
    }

    #[test]
    fn project_root_outside_home_is_allowed_but_drive_root_is_not() {
        let e = env();
        let work = e.base.join("work");
        fs::create_dir_all(work.join("a/b")).unwrap();
        assert_eq!(valid_project_root(&work, &e.dirs), Ok(()));
        // a path under such a root is actionable
        let roots = [work.clone()];
        assert_eq!(forbidden(&work.join("a/b"), &e.cfg(&roots, &[])), None);
        assert!(valid_project_root(&e.dirs.home, &e.dirs).is_err());
    }

    #[test]
    fn project_root_rejects_never_paths_and_missing() {
        let e = env();
        let ssh = e.mk(".ssh/keys");
        assert!(valid_project_root(&ssh, &e.dirs).is_err());
        assert!(valid_project_root(&e.base.join("nope"), &e.dirs).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn project_root_rejects_system_and_mount_points() {
        let e = env();
        assert!(valid_project_root(Path::new("/"), &e.dirs).is_err());
        assert!(valid_project_root(Path::new("/Applications/X"), &e.dirs).is_err());
        assert!(valid_project_root(Path::new("/Applications"), &e.dirs).is_err());
        if let Some(v) = fs::read_dir("/Volumes").unwrap().flatten().next() {
            assert!(
                valid_project_root(&v.path(), &e.dirs).is_err(),
                "{:?}",
                v.path()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn invalid_project_root_grants_no_build_dir_exception() {
        let e = env();
        e.mk("Documents/code/app/node_modules");
        let roots = [PathBuf::from("/")];
        let c = e.cfg(&roots, &[]);
        assert!(forbidden(&e.dirs.home.join("Documents/code/app/node_modules"), &c).is_some());
    }

    #[test]
    fn link_is_forbidden() {
        let e = env();
        let t = e.mk("a/b/target");
        if !dir_link(&t, &e.dirs.home.join("a/b/ln")) {
            return;
        }
        assert_eq!(e.check(&e.dirs.home.join("a/b/ln")).unwrap(), "is a link");
        assert_eq!(e.check(&t), None);
    }

    #[test]
    fn different_drive_forbidden() {
        let e = env();
        let p = e.mk("a/b");
        assert_eq!(e.check(&p), None);
        let v = platform::volume_of(&e.dirs.home).unwrap();
        platform::fake_volume(&p, v ^ 1);
        assert_eq!(e.check(&p).unwrap(), "different drive");
    }

    #[test]
    fn own_data_forbidden() {
        let e = env();
        let v = e.mk(".devaudit/vault.noindex/x");
        assert_eq!(e.check(&v).unwrap(), "DevAudit's own data");
        let work = e.base.join("work");
        fs::create_dir_all(work.join(".devaudit-vault/e/payload")).unwrap();
        let roots = [work.clone()];
        let c = e.cfg(&roots, &[]);
        assert_eq!(
            forbidden(&work.join(".devaudit-vault/e/payload"), &c).unwrap(),
            "DevAudit's own data"
        );
        assert_eq!(
            forbidden(&work.join(".DevAudit-Vault/e"), &c).unwrap(),
            "DevAudit's own data"
        );
    }

    #[test]
    fn secret_inside_cache_found() {
        let e = env();
        let c = e.mk("cache");
        fs::create_dir_all(c.join("huggingface")).unwrap();
        fs::create_dir_all(c.join("hub/models")).unwrap();
        fs::write(c.join("huggingface/token"), "t").unwrap();
        fs::write(c.join("hub/models/weights.bin"), "w").unwrap();
        assert_eq!(
            find_secret_inside(&c, 100).unwrap(),
            Some(c.join("huggingface/token"))
        );
        assert_eq!(find_secret_inside(&c.join("hub"), 100).unwrap(), None);
    }

    #[test]
    fn secret_walk_fails_closed_on_limit() {
        let e = env();
        let c = e.mk("cache");
        for i in 0..5 {
            fs::write(c.join(format!("f{i}")), "x").unwrap();
        }
        assert_eq!(find_secret_inside(&c, 5).unwrap(), None);
        assert_eq!(
            find_secret_inside(&c, 4).unwrap_err(),
            "too many files to check"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_walk_fails_closed_on_unreadable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let e = env();
        let locked = e.mk("cache/locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let r = find_secret_inside(&e.dirs.home.join("cache"), 100);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(r.is_err());
    }

    #[test]
    fn secret_walk_does_not_follow_links() {
        let e = env();
        let outside = e.mk("outside");
        fs::write(outside.join(".env"), "s").unwrap();
        let c = e.mk("cache");
        if !dir_link(&outside, &c.join("link")) {
            return;
        }
        assert_eq!(find_secret_inside(&c, 100).unwrap(), None);
    }

    #[test]
    fn secret_named_root_components_are_rejected() {
        let e = env();
        let git_root = e.mk("code/.git");
        assert!(valid_project_root(&git_root, &e.dirs).is_err());
        let outside = e.base.join("w/.env/proj");
        fs::create_dir_all(&outside).unwrap();
        assert!(valid_project_root(&outside, &e.dirs).is_err());
        // below home even a secret-named dir above the chosen root is caught
        e.mk("Dev/.git/objects/pack");
        let roots = [e.dirs.home.join("Dev/.git")];
        let c = e.cfg(&roots, &[]);
        assert!(forbidden(&e.dirs.home.join("Dev/.git/objects/pack"), &c).is_some());
        // outside home: every component counts
        let ok = e.base.join("w2/proj/a/b");
        fs::create_dir_all(&ok).unwrap();
        let roots = [e.base.join("w2/proj")];
        assert_eq!(forbidden(&ok, &e.cfg(&roots, &[])), None);
        let bad = e.base.join("w3/token/proj/a/b");
        fs::create_dir_all(&bad).unwrap();
        let roots = [e.base.join("w3/token/proj")];
        assert!(forbidden(&bad, &e.cfg(&roots, &[])).is_some());
    }

    #[test]
    fn ancestors_of_protected_locations_are_forbidden() {
        let mut e = env();
        e.mk("a/b/c");
        e.mk("Sync/deep");
        e.mk("proj/inner/x");
        e.mk("Library/Containers/com.docker.docker");
        e.mk("Library/Application Support/com.apple.TCC");
        e.mk(".config/gh");
        e.mk(".devaudit/vault.noindex");
        e.mk("AppData/Local/Packages");
        e.mk("AppData/Roaming/Microsoft/Protect");
        e.dirs.cloud_roots = vec![e.dirs.home.join("proj/inner")];
        let h = e.dirs.home.clone();
        for p in ["proj/inner/..", ".config/gh"] {
            assert!(e.check(&h.join(p)).is_some(), "{p}");
        }
        // an ancestor of a cloud root
        assert!(e.check(&h.join("proj")).is_some());
        let extra = [h.join("a/b/c")];
        assert!(forbidden(&h.join("a/b"), &e.cfg(&[], &extra)).is_some());
        // a dir containing the data dir
        let mut e2 = env();
        e2.data = e2.dirs.home.join("hold/data/.devaudit");
        fs::create_dir_all(&e2.data).unwrap();
        assert!(e2.check(&e2.dirs.home.join("hold/data")).is_some());
        // a project root containing a cloud root or the data dir is invalid
        assert!(valid_project_root(&h.join("proj"), &e.dirs).is_err());
        assert!(valid_project_root(&h.join("a"), &e.dirs).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn library_containers_ancestor_forbidden_on_macos() {
        let e = env();
        e.mk("Library/Containers/com.docker.docker/x");
        e.mk("Library/Group Containers/group.com.docker");
        e.mk("Library/Application Support/com.apple.TCC");
        for p in [
            "Library/Containers",
            "Library/Group Containers",
            "Library/Application Support",
        ] {
            assert!(e.check(&e.dirs.home.join(p)).is_some(), "{p}");
        }
        assert!(valid_project_root(&e.dirs.home.join("Library/Containers"), &e.dirs).is_err());
        let v = e.base.join("work");
        fs::create_dir_all(v.join(".devaudit-vault/e")).unwrap();
        let roots = [v.clone()];
        assert!(forbidden(&v, &e.cfg(&roots, &[])).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_ancestors_and_roots() {
        let e = env();
        e.mk("AppData/Local/Packages");
        assert!(e.check(&e.dirs.home.join("AppData/Local")).is_some());
        assert!(valid_project_root(Path::new("C:\\"), &e.dirs).is_err());
        assert!(valid_project_root(Path::new("C:\\Program Files\\X"), &e.dirs).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mount_point_root_rejected_by_mount_check() {
        let e = env();
        // /dev (devfs) is a mount point in neither forbidden_roots list
        assert_eq!(
            valid_project_root(Path::new("/dev"), &e.dirs).unwrap_err(),
            "drive or network share root"
        );
    }

    #[test]
    fn unexpandable_windows_tokens_fail_closed() {
        let mut e = env();
        e.dirs.app_data = None;
        e.dirs.local_app_data = None;
        e.mk("x/y");
        let r = e.check(&e.dirs.home.join("x/y"));
        if platform::CURRENT_OS == Os::Windows {
            assert_eq!(r.unwrap(), "can't resolve protected folders");
        } else {
            assert_eq!(r, None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn placeholder_check_does_not_break_normal_walk() {
        let e = env();
        let c = e.mk("cache/a");
        assert_eq!(find_secret_inside(c.parent().unwrap(), 10).unwrap(), None);
    }
}
