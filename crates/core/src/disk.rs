//! Folder sizes. Never follows links, never crosses volumes, never opens
//! cloud placeholders, never fails on permission errors (they are reported).

use crate::model::Skipped;
use crate::platform;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

#[derive(Debug, Default)]
pub struct Usage {
    pub bytes: u64,
    pub files: u64,
    /// Newest mtime of regular files outside `skip_for_mtime` dirs.
    pub newest_mtime: Option<SystemTime>,
    pub skipped: Vec<Skipped>,
    pub cancelled: bool,
}

/// Allocated size of `path`. A link, placeholder or missing `path` is not
/// followed: zero bytes and one `Skipped`. Subdirectories on another volume
/// are not entered or counted. Directories named in `skip_for_mtime`
/// (case-insensitive) count toward size but not `newest_mtime`.
pub fn usage(path: &Path, skip_for_mtime: &[&str], cancel: &AtomicBool) -> Usage {
    let mut u = Usage::default();
    let skip = |u: &mut Usage, p: &Path, why: String| {
        u.skipped.push(Skipped {
            path: p.to_path_buf(),
            why,
        })
    };
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            skip(&mut u, path, format!("can't read: {e}"));
            return u;
        }
    };
    if platform::is_link(&md) {
        skip(&mut u, path, "is a link; not followed".into());
        return u;
    }
    if platform::is_cloud_placeholder(&md) {
        skip(&mut u, path, "cloud placeholder; not opened".into());
        return u;
    }
    let vol = match platform::volume_of(path) {
        Ok(v) => v,
        Err(e) => {
            skip(&mut u, path, format!("can't identify volume: {e}"));
            return u;
        }
    };
    let mut seen = HashSet::new();
    let mut count = |u: &mut Usage, md: &fs::Metadata, mtime: bool| {
        if platform::hardlink_key(md).is_some_and(|k| !seen.insert(k)) {
            return;
        }
        u.bytes += platform::size_on_disk(md);
        u.files += 1;
        if mtime && let Ok(t) = md.modified() {
            u.newest_mtime = u.newest_mtime.max(Some(t));
        }
    };
    if !md.is_dir() {
        count(&mut u, &md, true);
        return u;
    }
    let mut stack: Vec<(PathBuf, bool)> = vec![(path.to_path_buf(), false)];
    while let Some((dir, no_mtime)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            u.cancelled = true;
            break;
        }
        if dir != path {
            match platform::volume_of(&dir) {
                Ok(v) if v == vol => {}
                Ok(_) => continue, // other volume / mount point: expected
                Err(e) => {
                    skip(&mut u, &dir, format!("can't identify volume: {e}"));
                    continue;
                }
            }
        }
        let rd = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                skip(&mut u, &dir, format!("can't read directory: {e}"));
                continue;
            }
        };
        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    skip(&mut u, &dir, format!("can't read entry: {e}"));
                    continue;
                }
            };
            let p = entry.path();
            let md = match fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(e) => {
                    skip(&mut u, &p, format!("can't read: {e}"));
                    continue;
                }
            };
            if platform::is_link(&md) || platform::is_cloud_placeholder(&md) {
                continue;
            }
            if md.is_dir() {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                let excl = no_mtime || skip_for_mtime.iter().any(|s| s.to_lowercase() == name);
                stack.push((p, excl));
            } else if md.is_file() {
                count(&mut u, &md, !no_mtime);
            }
        }
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn run(p: &Path, skip: &[&str]) -> Usage {
        usage(p, skip, &AtomicBool::new(false))
    }

    #[cfg(unix)]
    #[test]
    fn sparse_file_counts_allocated() {
        let d = tempfile::tempdir().unwrap();
        fs::File::create(d.path().join("s"))
            .unwrap()
            .set_len(100 << 20)
            .unwrap();
        let u = run(d.path(), &[]);
        assert_eq!(u.files, 1);
        assert!(u.bytes < 10 << 20, "{}", u.bytes);
    }

    #[test]
    fn links_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let big = d.path().join("big");
        fs::create_dir(&big).unwrap();
        fs::write(big.join("f"), vec![1u8; 1 << 20]).unwrap();
        let root = d.path().join("root");
        fs::create_dir(&root).unwrap();
        if !platform::tests::dir_link(&big, &root.join("ln")) {
            return;
        }
        let u = run(&root, &[]);
        assert!(u.bytes < 1 << 20 && u.files == 0, "{u:?}");
        // a link as the root itself: zero bytes, one Skipped
        let u = run(&root.join("ln"), &[]);
        assert_eq!((u.bytes, u.skipped.len()), (0, 1));
    }

    #[test]
    fn missing_root_is_skipped() {
        let d = tempfile::tempdir().unwrap();
        let u = run(&d.path().join("nope"), &[]);
        assert_eq!((u.bytes, u.files, u.skipped.len()), (0, 0, 1));
    }

    #[test]
    fn other_volume_not_counted() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("mnt")).unwrap();
        fs::write(d.path().join("mnt/f"), "x").unwrap();
        fs::write(d.path().join("g"), "x").unwrap();
        platform::fake_volume(
            &d.path().join("mnt"),
            platform::volume_of(d.path()).unwrap() ^ 1,
        );
        let u = run(d.path(), &[]);
        assert_eq!(u.files, 1);
        assert!(u.skipped.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn hardlinks_counted_once() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a"), vec![1u8; 8192]).unwrap();
        fs::hard_link(d.path().join("a"), d.path().join("b")).unwrap();
        let u = run(d.path(), &[]);
        assert_eq!(u.files, 1);
        assert_eq!(
            u.bytes,
            platform::size_on_disk(&fs::metadata(d.path().join("a")).unwrap())
        );
    }

    #[test]
    fn unreadable_dir_is_skipped() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().unwrap();
            let locked = d.path().join("locked");
            fs::create_dir(&locked).unwrap();
            fs::write(locked.join("f"), "x").unwrap();
            fs::write(d.path().join("ok"), "x").unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let readable = fs::read_dir(&locked).is_ok();
            let u = run(d.path(), &[]);
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            if readable {
                println!("note: running as root; skipping assertion");
                return;
            }
            assert_eq!(u.skipped.len(), 1, "{:?}", u.skipped);
            assert_eq!(u.skipped[0].path, locked);
            assert_eq!(u.files, 1);
        }
        #[cfg(windows)]
        {
            let d = tempfile::tempdir().unwrap();
            let locked = d.path().join("locked");
            fs::create_dir(&locked).unwrap();
            let user = std::env::var("USERNAME").unwrap();
            let icacls = |args: &[&str]| {
                std::process::Command::new("icacls")
                    .arg(&locked)
                    .args(args)
                    .output()
                    .is_ok_and(|o| o.status.success())
            };
            if !icacls(&["/deny", &format!("{user}:(OI)(CI)(RD,S)")]) {
                println!("note: icacls failed; skipping");
                return;
            }
            let u = run(d.path(), &[]);
            icacls(&["/remove:d", &user]);
            assert_eq!(u.skipped.len(), 1, "{:?}", u.skipped);
        }
    }

    #[test]
    fn long_paths_and_reserved_names_walk() {
        let d = tempfile::tempdir().unwrap();
        // Windows: the \\?\ form lets us create paths > MAX_PATH and "nul".
        let root = fs::canonicalize(d.path()).unwrap();
        let mut deep = root.clone();
        for _ in 0..10 {
            deep.push("d".repeat(30));
        }
        assert!(deep.as_os_str().len() > 300);
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("f"), "x").unwrap();
        #[cfg(windows)]
        fs::write(deep.join("nul"), "x").unwrap();
        let u = run(&root, &[]);
        assert_eq!(u.files, if cfg!(windows) { 2 } else { 1 });
        assert!(u.skipped.is_empty(), "{:?}", u.skipped);
    }

    #[test]
    fn cancel_stops_walk() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("a")).unwrap();
        fs::write(d.path().join("a/f"), "x").unwrap();
        let u = usage(d.path(), &[], &AtomicBool::new(true));
        assert!(u.cancelled);
        assert_eq!((u.bytes, u.files), (0, 0));
        assert!(!run(d.path(), &[]).cancelled);
    }

    #[test]
    fn skip_for_mtime_excluded() {
        let d = tempfile::tempdir().unwrap();
        let (src, nm) = (d.path().join("src"), d.path().join("a/Node_Modules/x"));
        fs::create_dir(&src).unwrap();
        fs::create_dir_all(&nm).unwrap();
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let f = fs::File::create(src.join("old")).unwrap();
        f.set_modified(old).unwrap();
        fs::write(nm.join("new"), "x").unwrap(); // mtime = now
        let u = run(d.path(), &["node_modules"]);
        assert_eq!(u.files, 2);
        assert_eq!(u.newest_mtime, Some(old));
        assert!(run(d.path(), &[]).newest_mtime > Some(old));
    }
}
