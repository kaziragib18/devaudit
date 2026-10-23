use super::{ForbiddenRoots, KnownDirs, highest_child, no_replace_err};
use crate::model::{FileId, Os, Pressure};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const CURRENT_OS: Os = Os::Macos;
/// Spotlight skips `*.noindex` (`.metadata_never_index` no longer works).
pub const VAULT_DIR_NAME: &str = "vault.noindex";
pub(super) const PERSONAL: [&str; 6] = [
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Movies",
    "Music",
];
/// <sys/stat.h> SF_DATALESS (not in the libc crate).
const SF_DATALESS: u32 = 0x4000_0000;

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

pub(super) fn real_known_dirs() -> KnownDirs {
    // HOME, else getpwuid_r. "/var/empty" (empty, root-owned) fails closed:
    // nothing under it is actionable.
    let home = std::env::home_dir()
        .filter(|h| h.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/var/empty"));
    let lib = home.join("Library");
    let mut cloud_roots: Vec<PathBuf> = fs::read_dir(lib.join("CloudStorage"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    cloud_roots.sort();
    let mobile = lib.join("Mobile Documents");
    if mobile.is_dir() {
        cloud_roots.push(mobile);
    }
    KnownDirs {
        local_app_data: None,
        app_data: None,
        temp: std::env::temp_dir(),
        personal: PERSONAL.iter().map(|n| home.join(n)).collect(),
        cloud_roots,
        apps_dir: PathBuf::from("/Applications"),
        home,
    }
}

pub fn canon(p: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(p)
}

pub fn data_dir(d: &KnownDirs) -> PathBuf {
    d.home.join(".devaudit")
}

pub fn tool_dirs(d: &KnownDirs) -> Vec<PathBuf> {
    let h = &d.home;
    let mut v: Vec<PathBuf> = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
    ]
    .map(PathBuf::from)
    .into();
    v.extend(highest_child(&h.join(".nvm/versions/node"), "v").map(|p| p.join("bin")));
    v.extend([".volta/bin", ".bun/bin", ".local/bin"].map(|s| h.join(s)));
    v.retain(|p| p.is_dir());
    v
}

pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (cpath(from)?, cpath(to)?);
    // SAFETY: both are valid NUL-terminated C strings that outlive the call.
    if unsafe { libc::renamex_np(f.as_ptr(), t.as_ptr(), libc::RENAME_EXCL) } == 0 {
        return Ok(());
    }
    Err(no_replace_err(io::Error::last_os_error(), to))
}

pub fn file_id(p: &Path) -> io::Result<FileId> {
    let m = fs::symlink_metadata(p)?;
    Ok(FileId {
        volume: m.dev(),
        index: u128::from(m.ino()),
    })
}

pub fn is_link(md: &fs::Metadata) -> bool {
    md.file_type().is_symlink()
}

pub fn is_cloud_placeholder(md: &fs::Metadata) -> bool {
    md.st_flags() & SF_DATALESS != 0
}

pub fn size_on_disk(md: &fs::Metadata) -> u64 {
    md.blocks() * 512
}

/// `(dev, ino)` of a file with more than one hard link, else None.
pub fn hardlink_key(md: &fs::Metadata) -> Option<(u64, u64)> {
    (md.nlink() > 1).then(|| (md.dev(), md.ino()))
}

pub(super) fn os_volume_space(p: &Path) -> io::Result<(u64, u64)> {
    let c = cpath(p)?;
    // SAFETY: statfs is plain old data; all-zero is a valid value.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated; s is a valid, writable statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let b = u64::from(s.f_bsize);
    Ok((s.f_blocks * b, s.f_bavail * b))
}

/// `/`, or a different device than its parent. True on error (fail closed).
pub fn is_mount_point(p: &Path) -> bool {
    let Ok(abs) = std::path::absolute(p) else {
        return true;
    };
    let Some(parent) = abs.parent() else {
        return true;
    };
    match (fs::symlink_metadata(&abs), fs::metadata(parent)) {
        (Ok(a), Ok(b)) => a.dev() != b.dev(),
        _ => true,
    }
}

/// `kern.memorystatus_vm_pressure_level`; the arguments are ignored.
pub fn memory_pressure(_available: u64, _total: u64, _commit_pct: Option<u8>) -> Pressure {
    let mut level: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated; level/len describe a writable c_int.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.memorystatus_vm_pressure_level".as_ptr(),
            (&raw mut level).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    match (rc, level) {
        (0, 1) => Pressure::Normal,
        (0, 2) => Pressure::Warn,
        (0, 4) => Pressure::Critical,
        _ => Pressure::Unknown,
    }
}

pub fn commit_pct() -> Option<u8> {
    None
}

pub fn user_sid() -> Option<String> {
    None
}

/// `tmutil addexclusion` (sticky, no root needed). Err carries tmutil's stderr.
pub fn hide_from_backup_and_index(dir: &Path) -> Result<(), String> {
    let o = Command::new("/usr/bin/tmutil")
        .arg("addexclusion")
        .arg(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

/// Read-only files can be removed on macOS (the dir's permissions decide): nothing to clear.
pub fn clear_readonly_tree(_dir: &Path) -> bool {
    false
}

/// Test helper: `tmutil isexcluded` says the dir is excluded.
#[cfg(test)]
pub(crate) fn is_hidden_from_backup_and_index(dir: &Path) -> bool {
    Command::new("/usr/bin/tmutil")
        .arg("isexcluded")
        .arg(dir)
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("[Excluded]"))
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Creates (or truncates) a file readable by the owner only (0600).
pub fn create_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

/// Owner-only directory (0700).
pub fn set_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Windows only: the Recycle Bin is `~/.Trash` here, sized by the caller.
pub fn recycle_bin_bytes(_root: &Path) -> Result<u64, String> {
    Err("not supported on macOS".into())
}

/// SIGTERM to exactly one process (pid 0 or > i32::MAX would address a group).
pub fn graceful_stop(pid: u32) -> Result<(), String> {
    let pid = libc::pid_t::try_from(pid)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| format!("invalid pid {pid}"))?;
    // SAFETY: kill has no memory-safety preconditions; pid > 0 targets one process.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().to_string())
    }
}

pub fn forbidden_roots(d: &KnownDirs) -> ForbiddenRoots {
    ForbiddenRoots {
        // Every mounted volume is a drive root.
        exact: [PathBuf::from("/"), d.home.clone()]
            .into_iter()
            .chain(
                fs::read_dir("/Volumes")
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path()),
            )
            .collect(),
        system: ["/System", "/Library", "/Applications", "/usr", "/opt"]
            .map(PathBuf::from)
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{KnownDirs, data_dir, known_dirs, tool_dirs};
    use std::path::{Path, PathBuf};

    #[test]
    fn hide_from_backup_and_index_marks_dir() {
        let d = tempfile::tempdir().unwrap();
        hide_from_backup_and_index(d.path()).unwrap();
        let o = std::process::Command::new("/usr/bin/tmutil")
            .arg("isexcluded")
            .arg(d.path())
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&o.stdout);
        assert!(s.contains("[Excluded]"), "{s}");
        assert!(hide_from_backup_and_index(&d.path().join("missing")).is_err());
    }

    #[test]
    fn forbidden_roots_contain_home_and_program_files() {
        let k = known_dirs();
        let f = forbidden_roots(&k);
        assert!(f.exact.contains(&PathBuf::from("/")));
        assert!(f.exact.contains(&k.home));
        for s in ["/System", "/Library", "/Applications", "/usr", "/opt"] {
            assert!(f.system.contains(&PathBuf::from(s)), "{s}");
        }
    }

    #[test]
    fn forbidden_exact_includes_every_volume() {
        let f = forbidden_roots(&known_dirs());
        for e in std::fs::read_dir("/Volumes").unwrap().flatten() {
            assert!(f.exact.contains(&e.path()), "{:?}", e.path());
        }
    }

    #[test]
    fn data_dir_and_vault_name() {
        let k = KnownDirs {
            home: "/Users/u".into(),
            local_app_data: None,
            app_data: None,
            temp: "/tmp".into(),
            personal: vec![],
            cloud_roots: vec![],
            apps_dir: "/Applications".into(),
        };
        assert_eq!(data_dir(&k), Path::new("/Users/u/.devaudit"));
        assert_eq!(VAULT_DIR_NAME, "vault.noindex");
    }

    #[test]
    fn tool_dirs_include_system_bins() {
        let t = tool_dirs(&known_dirs());
        assert!(t.contains(&PathBuf::from("/usr/bin")));
        assert!(t.contains(&PathBuf::from("/bin")));
    }

    #[test]
    fn personal_and_home() {
        let k = known_dirs();
        assert!(k.personal.contains(&k.home.join("Movies")));
        assert!(k.local_app_data.is_none() && k.app_data.is_none());
    }

    #[test]
    fn pressure_reads_sysctl_and_no_windows_only_info() {
        assert_ne!(memory_pressure(0, 0, None), crate::model::Pressure::Unknown);
        assert_eq!(commit_pct(), None);
        assert_eq!(user_sid(), None);
    }

    #[test]
    fn graceful_stop_sends_sigterm() {
        use std::os::unix::process::ExitStatusExt;
        let mut c = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        graceful_stop(c.id()).unwrap();
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn graceful_stop_refuses_group_pids() {
        assert!(graceful_stop(0).is_err());
        assert!(graceful_stop(u32::MAX).is_err());
    }
}
