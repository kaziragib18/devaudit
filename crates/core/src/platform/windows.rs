use super::{ForbiddenRoots, KnownDirs, highest_child, no_replace_err};
use crate::model::{FileId, Os, Pressure};
use std::ffi::{OsString, c_void};
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_READ_ATTRIBUTES, FileIdInfo, FindFirstVolumeW, FindNextVolumeW,
    FindVolumeClose, GetDiskFreeSpaceExW, GetFileInformationByHandleEx, GetLogicalDrives,
    GetVolumePathNameW, GetVolumePathNamesForVolumeNameW, MoveFileExW, SetFileAttributesW,
};
use windows_sys::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW,
    RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData,
    FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Profile, FOLDERID_ProgramData,
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_RoamingAppData, FOLDERID_Videos,
    FOLDERID_Windows, SHGetKnownFolderPath, SHQUERYRBINFO, SHQueryRecycleBinW,
};
use windows_sys::core::{GUID, PWSTR};

// Win32_System_Com is not in the approved windows-sys feature list; this is
// the only function needed from it (frees SHGetKnownFolderPath's string).
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(pv: *const c_void);
}

pub const CURRENT_OS: Os = Os::Windows;
pub const VAULT_DIR_NAME: &str = "vault";
pub(super) const PERSONAL: [&str; 6] = [
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Videos",
    "Music",
];
const PERSONAL_IDS: [GUID; 6] = [
    FOLDERID_Desktop,
    FOLDERID_Documents,
    FOLDERID_Downloads,
    FOLDERID_Pictures,
    FOLDERID_Videos,
    FOLDERID_Music,
];
/// Win32 path limit; longer paths get the `\\?\` prefix.
const MAX_PATH: usize = 260;

/// NUL-terminated wide path. Long absolute paths get the `\\?\` prefix.
fn wide(p: &Path) -> Vec<u16> {
    let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
    if v.len() >= MAX_PATH - 12
        && let Ok(abs) = std::path::absolute(p)
        && let Some(Component::Prefix(pre)) = abs.components().next()
    {
        let a: Vec<u16> = abs.as_os_str().encode_wide().collect();
        match pre.kind() {
            Prefix::Disk(_) => v = r"\\?\".encode_utf16().chain(a).collect(),
            Prefix::UNC(..) => {
                v = r"\\?\UNC"
                    .encode_utf16()
                    .chain(a[1..].iter().copied())
                    .collect()
            }
            _ => {}
        }
    }
    v.push(0);
    v
}

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// Up to the first NUL.
fn from_wide(buf: &[u16]) -> PathBuf {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..n]).into()
}

/// # Safety
/// `p` must point to a NUL-terminated UTF-16 string.
unsafe fn from_wide_ptr(p: *const u16) -> PathBuf {
    // SAFETY: the caller guarantees a terminating NUL within the allocation.
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    // SAFETY: the `len` units before the NUL are initialised.
    from_wide(unsafe { std::slice::from_raw_parts(p, len) })
}

/// SHGetKnownFolderPath: follows OneDrive redirection of personal folders.
fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut p: PWSTR = ptr::null_mut();
    // SAFETY: id is a valid GUID; p receives a CoTaskMem string freed below.
    let hr = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut p) };
    // SAFETY: on success p is a NUL-terminated string.
    let out = (hr >= 0 && !p.is_null()).then(|| unsafe { from_wide_ptr(p) });
    // SAFETY: must be freed whether or not the call succeeded; null is allowed.
    unsafe { CoTaskMemFree(p.cast()) };
    out
}

fn env_path(k: &str) -> Option<PathBuf> {
    std::env::var_os(k).map(PathBuf::from)
}

/// Every `HKCU\Software\Microsoft\OneDrive\Accounts\*\UserFolder` that exists.
fn onedrive_roots() -> Vec<PathBuf> {
    let mut out = vec![];
    let mut key: HKEY = ptr::null_mut();
    let sub = wstr(r"Software\Microsoft\OneDrive\Accounts");
    // SAFETY: sub is NUL-terminated; key receives a handle closed below.
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_READ, &mut key) }
        != ERROR_SUCCESS
    {
        return out;
    }
    let value = wstr("UserFolder");
    let mut buf = vec![0u16; 32768];
    for i in 0u32.. {
        // Registry key names are at most 255 chars.
        let mut name = [0u16; 256];
        let mut n = name.len() as u32;
        // SAFETY: name/n describe a writable buffer; optional out-params are null.
        let rc = unsafe {
            RegEnumKeyExW(
                key,
                i,
                name.as_mut_ptr(),
                &mut n,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            break;
        }
        buf.fill(0);
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: name is NUL-terminated by RegEnumKeyExW; buf/size describe a
        // writable buffer of `size` bytes.
        let rc = unsafe {
            RegGetValueW(
                key,
                name.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        let p = from_wide(&buf);
        if rc == ERROR_SUCCESS && p.is_dir() {
            out.push(p);
        }
    }
    // SAFETY: key was opened above and is closed once.
    unsafe { RegCloseKey(key) };
    out
}

pub(super) fn real_known_dirs() -> KnownDirs {
    // Fallback is the default profile: never this user's files (fail closed).
    let home = known_folder(&FOLDERID_Profile)
        .or_else(std::env::home_dir)
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default"));
    let local =
        known_folder(&FOLDERID_LocalAppData).unwrap_or_else(|| home.join("AppData").join("Local"));
    let roaming = known_folder(&FOLDERID_RoamingAppData)
        .unwrap_or_else(|| home.join("AppData").join("Roaming"));
    let personal = PERSONAL_IDS
        .iter()
        .zip(PERSONAL)
        .map(|(id, n)| known_folder(id).unwrap_or_else(|| home.join(n)))
        .collect();
    let mut cloud_roots = onedrive_roots();
    cloud_roots.extend(
        ["Dropbox", "Google Drive", "My Drive"]
            .map(|n| home.join(n))
            .into_iter()
            .filter(|p| p.is_dir()),
    );
    KnownDirs {
        local_app_data: Some(local),
        app_data: Some(roaming),
        // std uses GetTempPath2W when available, else GetTempPathW.
        temp: std::env::temp_dir(),
        personal,
        cloud_roots,
        home,
    }
}

/// Reserved DOS device names, which mean something else without `\\?\`.
fn is_reserved(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit())
}

/// Resolves 8.3 names and links. Drops `\\?\` only when the plain path means
/// the same thing (under MAX_PATH, no reserved names, no trailing dot/space).
pub fn canon(p: &Path) -> io::Result<PathBuf> {
    let c = fs::canonicalize(p)?;
    let w: Vec<u16> = c.as_os_str().encode_wide().collect();
    let skip = match c.components().next() {
        Some(Component::Prefix(pre)) => match pre.kind() {
            Prefix::VerbatimDisk(_) => 4,
            Prefix::VerbatimUNC(..) => 6, // `\\?\UNC\x` -> `\\x` (keep 2 of the 8)
            _ => return Ok(c),
        },
        _ => return Ok(c),
    };
    let plain_ok = w.len() - skip < MAX_PATH
        && c.components().all(|comp| match comp {
            Component::Normal(n) => n
                .to_str()
                .is_some_and(|s| !is_reserved(s) && !s.ends_with(['.', ' '])),
            _ => true,
        });
    if !plain_ok {
        return Ok(c);
    }
    let mut out: Vec<u16> = w[skip..].to_vec();
    if skip == 6 {
        out[0] = u16::from(b'\\');
        out[1] = u16::from(b'\\');
    }
    Ok(OsString::from_wide(&out).into())
}

pub fn data_dir(d: &KnownDirs) -> PathBuf {
    d.local_app_data
        .clone()
        .unwrap_or_else(|| d.home.join("AppData").join("Local"))
        .join("DevAudit")
}

pub fn tool_dirs(d: &KnownDirs) -> Vec<PathBuf> {
    let pf = env_path("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
    let sysroot = env_path("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let local = d
        .local_app_data
        .clone()
        .unwrap_or_else(|| d.home.join(r"AppData\Local"));
    let roaming = d
        .app_data
        .clone()
        .unwrap_or_else(|| d.home.join(r"AppData\Roaming"));
    let mut v = vec![pf.join("nodejs"), roaming.join("npm")];
    v.extend(env_path("NVM_SYMLINK"));
    v.extend([
        local.join("pnpm"),
        local.join(r"Volta\bin"),
        d.home.join(r"scoop\shims"),
        d.home.join(r".local\bin"),
        pf.join(r"Git\cmd"),
    ]);
    v.extend(
        highest_child(&local.join("GitHubDesktop"), "app-")
            .map(|p| p.join(r"resources\app\git\cmd")),
    );
    v.extend([pf.join(r"Docker\Docker\resources\bin"), pf.join("dotnet")]);
    v.extend(highest_child(&local.join(r"Programs\Python"), "Python3").map(|p| p.join("Scripts")));
    v.push(sysroot.join("System32"));
    v.retain(|p| p.is_dir());
    v
}

/// MoveFileExW without flags: never replaces, never copies across volumes.
pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (wide(from), wide(to));
    // SAFETY: both are NUL-terminated wide strings that outlive the call.
    if unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), 0) } != 0 {
        return Ok(());
    }
    Err(no_replace_err(io::Error::last_os_error(), to))
}

pub fn file_id(p: &Path) -> io::Result<FileId> {
    let f = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)?;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is valid while `f` lives; info is a writable
    // FILE_ID_INFO of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileId {
        volume: info.VolumeSerialNumber,
        index: u128::from_le_bytes(info.FileId.Identifier),
    })
}

/// Hard links are not detected on Windows (see the pnpm estimate).
pub fn hardlink_key(_md: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

pub fn is_link(md: &fs::Metadata) -> bool {
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub fn is_cloud_placeholder(md: &fs::Metadata) -> bool {
    md.file_attributes()
        & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_OFFLINE)
        != 0
}

pub fn size_on_disk(md: &fs::Metadata) -> u64 {
    if md.is_dir() {
        0
    } else {
        md.len().div_ceil(4096) * 4096
    }
}

pub(super) fn os_volume_space(p: &Path) -> io::Result<(u64, u64)> {
    // GetDiskFreeSpaceExW wants a directory.
    let dir = if p.is_dir() {
        p
    } else {
        p.parent().unwrap_or(p)
    };
    let w = wide(dir);
    let (mut free, mut total) = (0u64, 0u64);
    // SAFETY: w is NUL-terminated; out-params are valid u64s or null.
    if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, &mut total, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((total, free))
}

/// GetVolumePathNameW(p) == p. True on error (fail closed).
pub fn is_mount_point(p: &Path) -> bool {
    let Ok(abs) = std::path::absolute(p) else {
        return true;
    };
    let w = wide(&abs);
    let mut buf = vec![0u16; 32768];
    // SAFETY: w is NUL-terminated; buf is writable for the length passed.
    if unsafe { GetVolumePathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } == 0 {
        return true;
    }
    super::eq_ci(&from_wide(&buf), &abs)
}

/// Available < 10% or commit > 90% → Critical; available < 20% → Warn.
pub fn memory_pressure(available: u64, total: u64, commit_pct: Option<u8>) -> Pressure {
    if total == 0 {
        return Pressure::Unknown;
    }
    let avail_pct = u128::from(available) * 100 / u128::from(total);
    if avail_pct < 10 || commit_pct.is_some_and(|c| c > 90) {
        Pressure::Critical
    } else if avail_pct < 20 {
        Pressure::Warn
    } else {
        Pressure::Normal
    }
}

/// CommitTotal / CommitLimit, in percent.
pub fn commit_pct() -> Option<u8> {
    let mut pi = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..Default::default()
    };
    // SAFETY: pi is a writable PERFORMANCE_INFORMATION of the size passed.
    if unsafe { GetPerformanceInfo(&mut pi, pi.cb) } == 0 || pi.CommitLimit == 0 {
        return None;
    }
    let pct = pi.CommitTotal as u128 * 100 / pi.CommitLimit as u128;
    Some(pct.min(100) as u8)
}

/// String SID of the user running this process, e.g. `S-1-5-21-…`.
pub fn user_sid() -> Option<String> {
    let mut tok: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; tok receives a real
    // handle that is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return None;
    }
    let mut len = 0u32;
    // SAFETY: size query: null buffer of length 0.
    unsafe { GetTokenInformation(tok, TokenUser, ptr::null_mut(), 0, &mut len) };
    // u64 elements keep TOKEN_USER (pointer-aligned) correctly aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buf is writable for `len` bytes.
    let ok = unsafe { GetTokenInformation(tok, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) };
    // SAFETY: tok was opened above and is closed once.
    unsafe { CloseHandle(tok) };
    if ok == 0 {
        return None;
    }
    // SAFETY: on success buf holds a TOKEN_USER; its Sid points into buf.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut s: PWSTR = ptr::null_mut();
    // SAFETY: sid is valid while buf lives; s receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return None;
    }
    // SAFETY: on success s is a NUL-terminated string.
    let out = unsafe { from_wide_ptr(s) };
    // SAFETY: s was allocated by ConvertSidToStringSidW and is freed once.
    unsafe { LocalFree(s.cast()) };
    out.into_os_string().into_string().ok()
}

/// Sets FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.
pub fn hide_from_backup_and_index(dir: &Path) -> Result<(), String> {
    let attrs = fs::metadata(dir)
        .map_err(|e| e.to_string())?
        .file_attributes();
    let w = wide(dir);
    // SAFETY: w is NUL-terminated.
    if unsafe { SetFileAttributesW(w.as_ptr(), attrs | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// FlushFileBuffers on a directory handle.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?
        .sync_all()
}

/// Creates (or truncates) a file. The user-only ACL is inherited from LocalAppData.
pub fn create_private(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

/// Nothing to do: the ACL is inherited from LocalAppData.
pub fn set_private_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// `%ProgramFiles%`.
pub fn apps_dir() -> PathBuf {
    env_path("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into())
}

/// Recycle Bin size of the drive whose root is `root` (`SHQueryRecycleBinW`).
pub fn recycle_bin_bytes(root: &Path) -> Result<u64, String> {
    let w = wide(root);
    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: w is NUL-terminated; info is a valid, initialised out-struct with cbSize set.
    let hr = unsafe { SHQueryRecycleBinW(w.as_ptr(), &mut info) };
    if hr < 0 {
        return Err(format!("SHQueryRecycleBinW failed: 0x{hr:08x}"));
    }
    Ok(u64::try_from(info.i64Size).unwrap_or(0))
}

/// Console processes have no graceful stop on Windows.
pub fn graceful_stop(_pid: u32) -> Result<(), String> {
    Err("not supported on Windows".into())
}

/// Every mount path (drive letter or folder mount) of every volume.
fn volume_mount_paths() -> Vec<PathBuf> {
    let mut out = vec![];
    let mut name = [0u16; 64]; // `\\?\Volume{GUID}\` is 49 chars
    // SAFETY: name is writable for the length passed.
    let find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if find == INVALID_HANDLE_VALUE {
        return out;
    }
    loop {
        let mut buf = vec![0u16; 1024];
        loop {
            let mut need = 0u32;
            // SAFETY: name is NUL-terminated; buf is writable for the length
            // passed; need is a valid u32.
            let ok = unsafe {
                GetVolumePathNamesForVolumeNameW(
                    name.as_ptr(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut need,
                )
            };
            if ok != 0 {
                // multi-sz: NUL-separated, ends with an empty string
                out.extend(
                    buf.split(|&c| c == 0)
                        .take_while(|s| !s.is_empty())
                        .map(|s| PathBuf::from(OsString::from_wide(s))),
                );
                break;
            }
            // SAFETY: no preconditions.
            if unsafe { GetLastError() } != ERROR_MORE_DATA || need as usize <= buf.len() {
                break;
            }
            buf = vec![0u16; need as usize];
        }
        // SAFETY: find is a valid search handle; name is writable.
        if unsafe { FindNextVolumeW(find, name.as_mut_ptr(), name.len() as u32) } == 0 {
            break;
        }
    }
    // SAFETY: find came from FindFirstVolumeW and is closed once.
    unsafe { FindVolumeClose(find) };
    out
}

pub fn forbidden_roots(d: &KnownDirs) -> ForbiddenRoots {
    // SAFETY: no preconditions.
    let mask = unsafe { GetLogicalDrives() };
    let mut exact: Vec<PathBuf> = (0u8..26)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i) as char).into())
        .collect();
    exact.extend(volume_mount_paths());
    exact.push(d.home.clone());
    let system = [
        (FOLDERID_Windows, "WINDIR"),
        (FOLDERID_ProgramFiles, "ProgramFiles"),
        (FOLDERID_ProgramFilesX86, "ProgramFiles(x86)"),
        (FOLDERID_ProgramData, "ProgramData"),
    ]
    .iter()
    .filter_map(|(id, var)| known_folder(id).or_else(|| env_path(var)))
    .collect();
    ForbiddenRoots { exact, system }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Pressure;
    use crate::platform::known_dirs;
    use std::fs;
    use std::os::windows::fs::MetadataExt;
    use std::path::PathBuf;

    fn short_path(p: &std::path::Path) -> Option<PathBuf> {
        let w = super::wide(p);
        let mut buf = vec![0u16; 32768];
        // SAFETY: w is NUL-terminated; buf is writable for the length passed.
        let n = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
                w.as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        (n != 0).then(|| super::from_wide(&buf))
    }

    #[test]
    fn canon_keeps_verbatim_for_reserved_names() {
        let d = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(d.path()).unwrap(); // \\?\ form
        fs::create_dir(base.join("nul")).unwrap();
        let c = canon(&base.join("nul")).unwrap();
        assert!(c.to_string_lossy().starts_with(r"\\?\"), "{c:?}");
        assert!(c.is_dir());
    }

    #[test]
    fn junction_is_link() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("t")).unwrap();
        let j = d.path().join("j");
        let ok = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&j)
            .arg(d.path().join("t"))
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "mklink /J needs no privileges");
        assert!(is_link(&fs::symlink_metadata(&j).unwrap()));
        assert_ne!(file_id(&j).unwrap(), file_id(&d.path().join("t")).unwrap());
    }

    #[test]
    fn canon_resolves_short_names() {
        let d = tempfile::tempdir().unwrap();
        let long = d.path().join("Long Folder Name");
        fs::create_dir(&long).unwrap();
        let short = short_path(&long).unwrap();
        if short == long {
            println!("note: 8.3 names disabled on this volume; skipping");
            return;
        }
        assert_eq!(canon(&short).unwrap(), canon(&long).unwrap());
    }

    #[test]
    fn canon_strips_verbatim_prefix() {
        let d = tempfile::tempdir().unwrap();
        let c = canon(d.path()).unwrap();
        assert!(!c.to_string_lossy().starts_with(r"\\?\"), "{c:?}");
        assert!(c.is_dir());
    }

    #[test]
    fn commit_pct_is_some() {
        assert!(commit_pct().is_some_and(|p| p <= 100));
    }

    #[test]
    fn pressure_derivation() {
        assert_eq!(memory_pressure(1, 100, Some(50)), Pressure::Critical);
        assert_eq!(memory_pressure(15, 100, Some(50)), Pressure::Warn);
        assert_eq!(memory_pressure(40, 100, Some(95)), Pressure::Critical);
        assert_eq!(memory_pressure(40, 100, Some(50)), Pressure::Normal);
        assert_eq!(memory_pressure(40, 100, None), Pressure::Normal);
        assert_eq!(memory_pressure(0, 0, None), Pressure::Unknown);
    }

    #[test]
    fn hide_from_backup_and_index_marks_dir() {
        let d = tempfile::tempdir().unwrap();
        hide_from_backup_and_index(d.path()).unwrap();
        let a = fs::metadata(d.path()).unwrap().file_attributes();
        assert_ne!(a & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, 0);
        assert!(hide_from_backup_and_index(&d.path().join("missing")).is_err());
    }

    #[test]
    fn forbidden_roots_contain_home_and_program_files() {
        let k = known_dirs();
        let f = forbidden_roots(&k);
        assert!(f.exact.contains(&k.home));
        assert!(f.exact.iter().any(|p| p == &PathBuf::from(r"C:\")));
        let pf = PathBuf::from(std::env::var_os("ProgramFiles").unwrap());
        assert!(
            f.system.iter().any(|p| crate::platform::eq_ci(p, &pf)),
            "{f:?}"
        );
        assert!(f.system.len() >= 4);
    }

    #[test]
    fn forbidden_exact_includes_system_drive_root() {
        let f = forbidden_roots(&known_dirs());
        let sys = PathBuf::from(format!(r"{}\", std::env::var("SystemDrive").unwrap()));
        assert!(
            f.exact.iter().any(|p| crate::platform::eq_ci(p, &sys)),
            "{f:?}"
        );
    }

    #[test]
    fn known_dirs_has_appdata() {
        let k = known_dirs();
        assert!(k.local_app_data.as_ref().is_some_and(|p| p.is_dir()));
        assert!(k.app_data.as_ref().is_some_and(|p| p.is_dir()));
        assert_eq!(VAULT_DIR_NAME, "vault");
    }

    #[test]
    fn user_sid_and_no_signals() {
        assert!(user_sid().is_some_and(|s| s.starts_with("S-1-5-")));
        assert!(graceful_stop(std::process::id()).is_err());
    }

    #[test]
    fn size_on_disk_rounds_to_4096_and_dirs_are_zero() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        fs::write(&f, vec![0u8; 4097]).unwrap();
        assert_eq!(size_on_disk(&fs::metadata(&f).unwrap()), 8192);
        assert_eq!(size_on_disk(&fs::metadata(d.path()).unwrap()), 0);
    }
}
