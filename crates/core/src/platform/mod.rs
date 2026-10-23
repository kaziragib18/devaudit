//! The only place OS-specific (non-test) code lives. `macos.rs` and
//! `windows.rs` expose the same set of items, re-exported from here:
//!
//! - `CURRENT_OS: Os`, `VAULT_DIR_NAME: &str` (macOS `vault.noindex`, Windows `vault`)
//! - `canon(p)`: canonicalise. Windows: resolves 8.3 names; the `\\?\` prefix
//!   is dropped only when the plain form means the same path (short, no
//!   reserved names such as `nul`).
//! - `data_dir(d)`: `~/.devaudit` | `%LOCALAPPDATA%\DevAudit`
//! - `tool_dirs(d)`: existing tool dirs, in lookup order
//! - `rename_no_replace(from, to)`: never overwrites; `Err(AlreadyExists)` if
//!   `to` exists (file or empty dir). Never copies across volumes.
//! - `file_id(p)`: identity of `p` itself, never of a link target
//! - `is_link(md)`: symlink, junction or any reparse point (pass `symlink_metadata`)
//! - `is_cloud_placeholder(md)`: macOS SF_DATALESS; Windows RECALL_ON_* | OFFLINE
//! - `size_on_disk(md)`: macOS `st_blocks * 512`; Windows length rounded up to 4096, dirs 0
//! - `is_mount_point(p)`: true on error (fail closed)
//! - `memory_pressure(available, total, commit_pct)`: macOS reads the kernel
//!   level and ignores the args; Windows derives it from the args
//! - `commit_pct()`, `user_sid()`: Windows only; `None` on macOS
//! - `hide_from_backup_and_index(dir)`, `sync_dir(dir)`
//! - `graceful_stop(pid)`: macOS SIGTERM; Windows `Err`
//! - `forbidden_roots(d)`
//!
//! Shared here: `known_dirs`, `eq_ci`, `inside`, `volume_of`, `volume_space`.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf, Prefix};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[derive(Clone, Debug, PartialEq)]
pub struct KnownDirs {
    pub home: PathBuf,
    pub local_app_data: Option<PathBuf>,
    pub app_data: Option<PathBuf>,
    pub temp: PathBuf,
    /// Desktop, Documents, Downloads, Pictures, Movies/Videos, Music.
    pub personal: Vec<PathBuf>,
    /// OneDrive / Dropbox / Google Drive / iCloud roots that exist.
    pub cloud_roots: Vec<PathBuf>,
}

/// `exact`: a project root may not equal or contain these.
/// `system`: a project root may not equal, contain, or be inside these.
#[derive(Clone, Debug, PartialEq)]
pub struct ForbiddenRoots {
    pub exact: Vec<PathBuf>,
    pub system: Vec<PathBuf>,
}

/// Debug builds honour `DEVAUDIT_TEST_ROOT`: every dir is derived under it
/// (nothing is created).
pub fn known_dirs() -> KnownDirs {
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os("DEVAUDIT_TEST_ROOT") {
        return dirs_under(Path::new(&root));
    }
    real_known_dirs()
}

#[cfg(any(debug_assertions, test))]
fn dirs_under(root: &Path) -> KnownDirs {
    let home = root.join("home");
    let win = CURRENT_OS == crate::model::Os::Windows;
    KnownDirs {
        local_app_data: win.then(|| home.join("AppData").join("Local")),
        app_data: win.then(|| home.join("AppData").join("Roaming")),
        temp: root.join("tmp"),
        personal: PERSONAL.iter().map(|n| home.join(n)).collect(),
        cloud_roots: vec![],
        home,
    }
}

/// Comparison key: Unicode-lowercased; `C:` and `\\?\C:` (and UNC forms)
/// are the same. Non-Unicode names compare exactly.
fn key(c: Component) -> Result<String, OsString> {
    let s: OsString = match c {
        Component::Prefix(p) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => format!("{}:", d as char).into(),
            Prefix::UNC(srv, share) | Prefix::VerbatimUNC(srv, share) => {
                let mut o = OsString::from(r"\\");
                o.push(srv);
                o.push(r"\");
                o.push(share);
                o
            }
            _ => p.as_os_str().into(),
        },
        c => c.as_os_str().into(),
    };
    s.into_string().map(|s| s.to_lowercase())
}

fn starts_with_ci(child: &Path, parent: &Path) -> bool {
    let (c, p): (Vec<_>, Vec<_>) = (child.components().collect(), parent.components().collect());
    p.len() <= c.len() && p.iter().zip(&c).all(|(a, b)| key(*a) == key(*b))
}

/// Component-wise, case-insensitive; does not touch the file system.
pub fn eq_ci(a: &Path, b: &Path) -> bool {
    a.components().count() == b.components().count() && starts_with_ci(a, b)
}

/// Canonicalises the deepest existing ancestor and re-appends the rest.
fn canon_lenient(p: &Path) -> Option<PathBuf> {
    let p = std::path::absolute(p).ok()?;
    let comps: Vec<Component> = p.components().collect();
    for i in (1..=comps.len()).rev() {
        let Ok(mut out) = canon(&comps[..i].iter().collect::<PathBuf>()) else {
            continue;
        };
        let rest = &comps[i..];
        if !rest.contains(&Component::ParentDir) {
            out.extend(rest);
            return Some(out);
        }
        for c in rest {
            match c {
                Component::ParentDir => {
                    out.pop();
                }
                Component::CurDir => {}
                c => out.push(c),
            }
        }
        // `..` may have led back to existing (possibly linked) dirs.
        return canon_lenient(&out);
    }
    None
}

/// `child` equals or is below `parent`, after canonicalising both (a child
/// that doesn't exist yet is resolved through its deepest existing
/// ancestor). Component-wise and case-insensitive. False if either can't be
/// resolved.
pub fn inside(child: &Path, parent: &Path) -> bool {
    match (canon_lenient(child), canon_lenient(parent)) {
        (Some(c), Some(p)) => starts_with_ci(&c, &p),
        _ => false,
    }
}

/// Child dir of `dir` named `<prefix><version>` with the highest version
/// (numeric runs compared as numbers).
fn highest_child(dir: &Path, prefix: &str) -> Option<PathBuf> {
    let version = |n: &str| -> Vec<u64> {
        n[prefix.len()..]
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap_or(u64::MAX))
            .collect()
    };
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefix))
        .max_by_key(|n| (version(n), n.clone()))
        .map(|n| dir.join(n))
}

/// A failed no-replace rename whose target exists is reported as AlreadyExists.
fn no_replace_err(e: io::Error, to: &Path) -> io::Error {
    if e.kind() != io::ErrorKind::AlreadyExists && std::fs::symlink_metadata(to).is_ok() {
        io::Error::new(io::ErrorKind::AlreadyExists, e)
    } else {
        e
    }
}

/// Device (macOS) / volume serial (Windows) of `p` itself; same value as
/// `file_id(p)?.volume`.
pub fn volume_of(p: &Path) -> io::Result<u64> {
    #[cfg(test)]
    if let Some(v) = fake::lookup(&fake::VOLUME, p) {
        return Ok(v);
    }
    file_id(p).map(|id| id.volume)
}

/// (total, free-to-this-user) bytes of the volume holding `p`.
pub fn volume_space(p: &Path) -> io::Result<(u64, u64)> {
    let (total, free) = os_volume_space(p)?;
    #[cfg(test)]
    if let Some(f) = fake::lookup(&fake::FREE, p) {
        return Ok((total, f));
    }
    Ok((total, free))
}

/// Test hook: `volume_of` reports `volume` for `path` and everything below it.
#[cfg(test)]
pub fn fake_volume(path: &Path, volume: u64) {
    fake::VOLUME.with(|v| v.borrow_mut().push((path.to_path_buf(), volume)));
}

/// Test hook: `volume_space` reports `free` for `path` and everything below it.
#[cfg(test)]
pub fn fake_free_space(path: &Path, free: u64) {
    fake::FREE.with(|v| v.borrow_mut().push((path.to_path_buf(), free)));
}

#[cfg(test)]
mod fake {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::thread::LocalKey;

    type Overrides = RefCell<Vec<(PathBuf, u64)>>;
    thread_local! {
        pub static VOLUME: Overrides = const { RefCell::new(Vec::new()) };
        pub static FREE: Overrides = const { RefCell::new(Vec::new()) };
    }

    /// Deepest override at or above `p`.
    pub fn lookup(t: &'static LocalKey<Overrides>, p: &Path) -> Option<u64> {
        t.with(|v| {
            v.borrow()
                .iter()
                .filter(|(q, _)| p.starts_with(q))
                .max_by_key(|(q, _)| q.components().count())
                .map(|(_, x)| *x)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// Directory link: symlink on macOS; on Windows a symlink (needs Developer
    /// Mode) or else a junction. False (with a note) if neither works.
    pub(super) fn dir_link(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).unwrap();
            true
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(target, link).is_ok() {
                return true;
            }
            let ok = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|o| o.status.success());
            if !ok {
                println!("note: cannot create symlink or junction here; skipping");
            }
            ok
        }
    }

    #[test]
    fn inside_is_component_wise_and_case_insensitive() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("Dev/app/src")).unwrap();
        fs::create_dir_all(d.path().join("Dev/app-old")).unwrap();
        assert!(inside(
            &d.path().join("dev/APP/src"),
            &d.path().join("Dev/app")
        ));
        assert!(!inside(
            &d.path().join("Dev/app-old"),
            &d.path().join("Dev/app")
        ));
        // equal counts as inside
        assert!(inside(&d.path().join("Dev/app"), &d.path().join("DEV/App")));
        // child that does not exist yet
        assert!(inside(
            &d.path().join("Dev/app/new/x"),
            &d.path().join("Dev/app")
        ));
        assert!(!inside(
            &d.path().join("Dev/app/../app-old/x"),
            &d.path().join("Dev/app")
        ));
        // parent not inside child
        assert!(!inside(&d.path().join("Dev"), &d.path().join("Dev/app")));
    }

    #[test]
    fn inside_resolves_links() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("real/x")).unwrap();
        if !dir_link(&d.path().join("real"), &d.path().join("ln")) {
            return;
        }
        assert!(inside(&d.path().join("ln/x"), &d.path().join("real")));
        assert!(inside(
            &d.path().join("ln/x/notyet"),
            &d.path().join("real")
        ));
    }

    #[test]
    fn eq_ci_is_component_wise() {
        assert!(eq_ci(Path::new("/a/Café/b"), Path::new("/A/CAFÉ/b/")));
        assert!(!eq_ci(Path::new("/a/b"), Path::new("/a/bc")));
        assert!(!eq_ci(Path::new("/a/b"), Path::new("/a/b/c")));
    }

    #[test]
    fn symlink_is_link() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("t")).unwrap();
        if !dir_link(&d.path().join("t"), &d.path().join("l")) {
            return;
        }
        assert!(is_link(&fs::symlink_metadata(d.path().join("l")).unwrap()));
        assert!(!is_link(&fs::symlink_metadata(d.path().join("t")).unwrap()));
    }

    #[test]
    fn file_id_changes_when_dir_replaced() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir(&a).unwrap();
        let first = file_id(&a).unwrap();
        assert_eq!(file_id(&a).unwrap(), first);
        fs::remove_dir(&a).unwrap();
        fs::create_dir(&a).unwrap();
        assert_ne!(file_id(&a).unwrap(), first);
    }

    #[test]
    fn file_id_does_not_follow_link() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("t")).unwrap();
        if !dir_link(&d.path().join("t"), &d.path().join("l")) {
            return;
        }
        let t = file_id(&d.path().join("t")).unwrap();
        let l = file_id(&d.path().join("l")).unwrap();
        assert_ne!(t, l);
        assert_eq!(t.volume, l.volume);
    }

    #[test]
    fn known_dirs_has_existing_home_and_temp() {
        let k = known_dirs();
        assert!(k.home.is_absolute() && k.home.is_dir(), "{:?}", k.home);
        assert!(k.temp.is_dir(), "{:?}", k.temp);
        assert_eq!(k.personal.len(), 6);
        assert!(k.personal.iter().all(|p| p.is_absolute()));
    }

    #[test]
    fn test_root_derives_everything_under_root() {
        let k = dirs_under(Path::new("/r"));
        assert_eq!(k.home, Path::new("/r/home"));
        assert_eq!(k.temp, Path::new("/r/tmp"));
        assert!(k.cloud_roots.is_empty());
        assert_eq!(k.personal.len(), 6);
        assert!(k.personal.iter().all(|p| p.parent() == Some(&k.home)));
        let under = |p: &Option<PathBuf>| p.as_ref().is_none_or(|p| p.starts_with("/r/home"));
        assert!(under(&k.local_app_data) && under(&k.app_data));
        assert!(data_dir(&k).starts_with("/r/home"));
    }

    #[test]
    fn rename_no_replace_refuses_existing_file_and_empty_dir() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        fs::write(&a, "A").unwrap();
        fs::write(&b, "B").unwrap();
        let e = rename_no_replace(&a, &b).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&a).unwrap(), "A");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B");

        let (src, dst) = (d.path().join("src"), d.path().join("dst"));
        fs::create_dir(&src).unwrap();
        fs::write(src.join("f"), "x").unwrap();
        fs::create_dir(&dst).unwrap();
        let e = rename_no_replace(&src, &dst).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(src.join("f").exists() && dst.is_dir());

        // free target: moves
        let c = d.path().join("c");
        rename_no_replace(&src, &c).unwrap();
        assert!(c.join("f").exists() && !src.exists());
    }

    #[test]
    fn size_on_disk_is_allocation_sized() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        fs::write(&f, "x").unwrap();
        let s = size_on_disk(&fs::metadata(&f).unwrap());
        assert!(s >= 1 && s.is_multiple_of(512), "{s}");
    }

    #[test]
    fn volumes_and_fakes() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("x")).unwrap();
        let v = volume_of(d.path()).unwrap();
        assert_eq!(volume_of(&d.path().join("x")).unwrap(), v);
        let (total, free) = volume_space(d.path()).unwrap();
        assert!(total > 0 && free > 0 && free <= total);

        fake_volume(&d.path().join("x"), v ^ 1);
        assert_eq!(volume_of(&d.path().join("x/deeper")).unwrap(), v ^ 1);
        assert_eq!(volume_of(d.path()).unwrap(), v);
        fake_free_space(d.path(), 7);
        assert_eq!(volume_space(&d.path().join("x")).unwrap(), (total, 7));
    }

    #[test]
    fn mount_points() {
        let d = tempfile::tempdir().unwrap();
        assert!(!is_mount_point(d.path()));
        let root = std::path::absolute("/").unwrap();
        assert!(is_mount_point(&root), "{root:?}");
    }

    #[test]
    fn regular_file_is_not_placeholder_or_link() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        fs::write(&f, "x").unwrap();
        let md = fs::symlink_metadata(&f).unwrap();
        assert!(!is_cloud_placeholder(&md) && !is_link(&md));
    }

    #[test]
    fn sync_dir_works() {
        let d = tempfile::tempdir().unwrap();
        sync_dir(d.path()).unwrap();
    }

    #[test]
    fn highest_child_is_version_ordered() {
        let d = tempfile::tempdir().unwrap();
        for n in ["v9.0.0", "v18.2.0", "v18.10.1", "notes.txt"] {
            fs::create_dir(d.path().join(n)).unwrap();
        }
        fs::write(d.path().join("v99.0.0"), "file, not dir").unwrap();
        assert_eq!(
            highest_child(d.path(), "v"),
            Some(d.path().join("v18.10.1"))
        );
        assert_eq!(highest_child(d.path(), "zzz"), None);
    }

    #[test]
    fn tool_dirs_all_exist() {
        let t = tool_dirs(&known_dirs());
        assert!(!t.is_empty());
        assert!(t.iter().all(|p| p.is_dir()), "{t:?}");
    }

    #[test]
    fn current_os_matches_model() {
        assert_eq!(crate::model::Os::current(), CURRENT_OS);
    }
}
