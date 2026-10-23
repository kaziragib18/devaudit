//! Recovery vault.

use crate::guard::{self, Repo};
use crate::lock::InstanceLock;
use crate::model::{FileId, Tier};
use crate::run::RunError;
use crate::{Ctx, disk, never, platform, projects, report};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, UNIX_EPOCH};

const PROJECT_VAULT_DIR: &str = ".devaudit-vault";

/// Volume of `p`, or of its nearest existing ancestor (the data dir may not exist yet).
fn volume_near(p: &Path) -> Result<u64, String> {
    p.ancestors()
        .find_map(|a| platform::volume_of(a).ok())
        .ok_or_else(|| format!("can't read the drive of {}", p.display()))
}

/// Where the vault for `path` lives, and the project root hosting it (None: the data dir does).
/// Pure: creates nothing.
pub(crate) fn vault_location(path: &Path, ctx: &Ctx) -> Result<(PathBuf, Option<PathBuf>), String> {
    let item = platform::volume_of(path)
        .map_err(|e| format!("can't read the drive of {}: {e}", path.display()))?;
    if volume_near(&ctx.data_dir)? == item {
        return Ok((ctx.data_dir.join(platform::VAULT_DIR_NAME), None));
    }
    let (roots, _) = projects::roots(ctx);
    let root = roots
        .into_iter()
        .filter(|r| platform::inside(path, r))
        .filter(|r| platform::volume_of(r).is_ok_and(|v| v == item))
        .max_by_key(|r| r.components().count())
        .ok_or_else(|| "no Recovery space on this drive".to_string())?;
    let vault = root.join(PROJECT_VAULT_DIR).join(platform::VAULT_DIR_NAME);
    Ok((vault, Some(root)))
}

fn refuse_link(p: &Path) -> Result<(), String> {
    match fs::symlink_metadata(p) {
        Ok(md) if platform::is_link(&md) => Err(format!(
            "{} is a link; not using it for Recovery",
            p.display()
        )),
        Ok(md) if !md.is_dir() => Err(format!("{} is in the way", p.display())),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("can't inspect {}: {e}", p.display())),
    }
}

/// Adds `.devaudit-vault/` to the repo's `info/exclude` (once) so the vault never shows in
/// `git status` and can't be committed. Nothing to do outside a repo.
fn exclude_from_git(root: &Path, ctx: &Ctx) -> Result<(), String> {
    let top = match guard::repo_of(root, ctx.run) {
        Repo::NotARepo => return Ok(()),
        Repo::Git(top) => top,
        Repo::GitMissing => return Err("Install Git so DevAudit can check projects".into()),
        Repo::GitFailed(e) => return Err(format!("git failed: {e}")),
    };
    let dotgit = top.join(".git");
    let exclude = if dotgit.is_dir() {
        dotgit.join("info").join("exclude")
    } else {
        // A linked worktree: ask git where the shared exclude file is.
        let o = guard::git(ctx.run, &top, &["rev-parse", "--git-path", "info/exclude"])
            .map_err(|e| format!("git failed: {e:?}"))?;
        if o.status != 0 {
            return Err(format!("git failed: {}", o.stderr.trim()));
        }
        let p = PathBuf::from(o.stdout.trim());
        if p.is_absolute() { p } else { top.join(p) }
    };
    let line = format!("{PROJECT_VAULT_DIR}/");
    let e = |e: io::Error| format!("{}: {e}", exclude.display());
    let mut text = match fs::read_to_string(&exclude) {
        Ok(t) => t,
        Err(x) if x.kind() == io::ErrorKind::NotFound => String::new(),
        Err(x) => return Err(e(x)),
    };
    if text.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&line);
    text.push('\n');
    if let Some(dir) = exclude.parent() {
        fs::create_dir_all(dir).map_err(e)?;
    }
    fs::write(&exclude, text).map_err(e)
}

/// The vault folder for `path`: on the same drive as the item, never across drives.
/// Creates it (private), hides it from backups and indexing, and, for a project-root
/// vault inside a git repo, keeps it out of `git status`. A vault is marked once (see
/// `HIDDEN_MARK`).
pub fn vault_for(path: &Path, ctx: &Ctx) -> Result<PathBuf, String> {
    let (vault, root) = vault_location(path, ctx)?;
    if let Some(root) = &root {
        refuse_link(&root.join(PROJECT_VAULT_DIR))?;
        exclude_from_git(root, ctx)?;
    }
    refuse_link(&vault)?;
    let e = |e: io::Error| format!("{}: {e}", vault.display());
    let fresh = !vault.exists();
    fs::create_dir_all(&vault).map_err(e)?;
    if let Some(parent) = vault.parent() {
        platform::set_private_dir(parent).map_err(|x| format!("{}: {x}", parent.display()))?;
    }
    platform::set_private_dir(&vault).map_err(e)?;
    // Marking can take seconds (macOS `tmutil`), so a marker file records that it was done. A
    // vault without it (new, or a crash before marking finished) is marked now; `repair` does
    // the same for every indexed vault.
    ensure_hidden(&vault).inspect_err(|_| {
        // Leave nothing half-set-up, so the next call marks it.
        if fresh {
            let _ = fs::remove_dir(&vault);
        }
    })?;
    Ok(vault)
}

// ---------------------------------------------------------------- the vault
//
// Layout: `<vault>/<entry id>/{manifest.json, README.txt, payload}`, plus the marker file
// `<vault>/.hidden-from-backup`, written only after `hide_from_backup_and_index` succeeded
// (marking can take seconds, so an unmarked vault is detected by the missing marker and marked
// by the next `vault_for` or `repair`).
//
// `<data_dir>/vault-index.json` lists every vault dir in use with its entries' id, title, bytes
// and `expires_at`. A vault dir is registered before its first entry is created, so a crash can
// never leave an entry the index doesn't lead to. The data-dir vault is always read, indexed or
// not.
//
// Safety: only `purge` deletes payload data (`platform::remove_dir_all_retry`). Every other
// removal of an entry folder goes through `remove_entry_dir`, which refuses unless nothing but
// DevAudit's own bookkeeping files (and empty folders) is left in it.

const DAY: u64 = 86_400;
const T: Duration = Duration::from_secs(30);
/// Cleanup commands (`docker cp`).
const LONG: Duration = Duration::from_secs(600);
const INDEX_FILE: &str = "vault-index.json";
const MANIFEST: &str = "manifest.json";
const MANIFEST_TMP: &str = "manifest.json.tmp";
const README: &str = "README.txt";
const PAYLOAD: &str = "payload";
const VOLUME_TAR: &str = "volume.tar";
const HIDDEN_MARK: &str = ".hidden-from-backup";
const NOOP: &str = "devaudit-noop";
const IN_USE: &str = "in use — skipped (close apps using this folder)";
const NOT_CONNECTED: &str = "drive not connected";
const UNREADABLE: &str = "unreadable — restore by hand";
const PARTLY_PURGED: &str = "partly purged";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntryState {
    Moving,
    Held,
    Restoring,
    Purging,
    /// The journal couldn't be resolved; never purged automatically.
    Orphaned,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum EntryKind {
    Path,
    TempFiles {
        base: PathBuf,
    },
    DockerVolume {
        name: String,
    },
    DockerStopped {
        ids: Vec<String>,
    },
    /// The payload is the worktree folder.
    Worktree {
        repo: PathBuf,
        branch: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub kind: EntryKind,
    pub title: String,
    pub original: Option<PathBuf>,
    pub bytes: u64,
    pub tier: Tier,
    pub moved_at: u64,
    pub expires_at: Option<u64>,
    pub state: EntryState,
    /// The vault folder holding the entry (`<vault_dir>/<id>`).
    pub vault_dir: PathBuf,
    /// "drive not connected", "unreadable — restore by hand", "partly purged"
    pub note: Option<String>,
}

/// `manifest.json`: the journal of one entry.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Manifest {
    id: String,
    kind: EntryKind,
    title: String,
    original: Option<PathBuf>,
    /// Identity of the moved item (a rename keeps it).
    file_id: Option<FileId>,
    bytes: u64,
    tier: Tier,
    moved_at: u64,
    expires_at: Option<u64>,
    state: EntryState,
    note: Option<String>,
    /// TempFiles: the moved paths, relative to `base` (informational; restore walks the payload).
    #[serde(default)]
    files: Vec<String>,
}

impl Manifest {
    fn entry(&self, vault: &Path) -> Entry {
        Entry {
            id: self.id.clone(),
            kind: self.kind.clone(),
            title: self.title.clone(),
            original: self.original.clone(),
            bytes: self.bytes,
            tier: self.tier,
            moved_at: self.moved_at,
            expires_at: self.expires_at,
            state: self.state,
            vault_dir: vault.to_path_buf(),
            note: self.note.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Index {
    vaults: Vec<IndexVault>,
}

#[derive(Serialize, Deserialize)]
struct IndexVault {
    dir: PathBuf,
    entries: Vec<IndexRow>,
}

#[derive(Serialize, Deserialize, Clone)]
struct IndexRow {
    id: String,
    title: String,
    bytes: u64,
    expires_at: Option<u64>,
}

// ---------------------------------------------------------------- time and ids

fn now_secs(ctx: &Ctx) -> u64 {
    ctx.now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// UTC (year, month, day, hour, minute, second) of Unix seconds.
fn civil(secs: u64) -> (i64, u64, u64, u64, u64, u64) {
    let days = i64::try_from(secs / DAY).unwrap_or(0);
    let rem = secs % DAY;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m.unsigned_abs(),
        d.unsigned_abs(),
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

/// `yyyyMMdd-HHmmss` (UTC).
fn stamp(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// `yyyy-MM-dd HH:mm UTC`, for people.
fn human_date(secs: u64) -> String {
    let (y, mo, d, h, mi, _) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} UTC")
}

/// `{yyyyMMdd-HHmmss}-{8 hex random}`.
fn new_id(ctx: &Ctx) -> Result<String, String> {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness for an entry id: {e}"))?;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{hex}", stamp(now_secs(ctx))))
}

/// Exactly the id shape, so an id can never name another path.
fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 24
        && b[8] == b'-'
        && b[15] == b'-'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
        && b[16..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

// ---------------------------------------------------------------- files

fn io_err(p: &Path) -> impl Fn(io::Error) -> String + '_ {
    move |e| format!("{}: {e}", p.display())
}

fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn read_manifest(dir: &Path) -> Result<Manifest, String> {
    let p = dir.join(MANIFEST);
    let bytes = fs::read(&p).map_err(io_err(&p))?;
    let m: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", p.display()))?;
    // The folder name is the truth; a manifest claiming another id is not trusted.
    if dir.file_name().and_then(|n| n.to_str()) != Some(m.id.as_str()) {
        return Err(format!("{}: id doesn't match its folder", p.display()));
    }
    Ok(m)
}

/// `manifest.json.tmp`, `sync_all`, rename over `manifest.json`, `sync_dir`. Replacing the old
/// manifest is intended here (the one place a replacing rename is used).
fn write_manifest(dir: &Path, m: &Manifest) -> Result<(), String> {
    let tmp = dir.join(MANIFEST_TMP);
    let bytes = serde_json::to_vec_pretty(m).map_err(|e| e.to_string())?;
    let res = (|| {
        let mut f = platform::create_private(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dir.join(MANIFEST))?;
        platform::sync_dir(dir)
    })();
    res.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("can't write {}: {e}", dir.join(MANIFEST).display())
    })
}

fn set_state(dir: &Path, m: &mut Manifest, state: EntryState) -> Result<(), String> {
    m.state = state;
    write_manifest(dir, m)
}

fn write_readme(dir: &Path, m: &Manifest) -> Result<(), String> {
    let original = match (&m.kind, &m.original) {
        (EntryKind::DockerVolume { name }, _) => {
            format!("Docker volume \"{name}\" (payload/volume.tar holds its files)")
        }
        (_, Some(o)) => o.display().to_string(),
        (_, None) => return Ok(()),
    };
    let expiry = m.expires_at.map_or_else(|| "never".to_string(), human_date);
    let text = format!(
        "This folder was moved here by DevAudit on {}.\n\
         To restore it by hand, move the \"payload\" folder back to:\n  {original}\n\
         It is deleted permanently after {expiry} unless you restore it.\n",
        human_date(m.moved_at)
    );
    let p = dir.join(README);
    let mut f = platform::create_private(&p).map_err(io_err(&p))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(io_err(&p))
}

/// Removes an empty folder tree. Refuses (Err) at the first file or link: never deletes data.
fn remove_empty_tree(dir: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(dir)?;
    if !md.is_dir() || platform::is_link(&md) {
        return Err(io::Error::other(format!("{} is not empty", dir.display())));
    }
    for e in fs::read_dir(dir)? {
        remove_empty_tree(&e?.path())?;
    }
    fs::remove_dir(dir)
}

/// True if `dir` holds anything but folders (or can't be read: fail closed).
fn has_files(dir: &Path) -> bool {
    let Ok(rd) = fs::read_dir(dir) else {
        return exists(dir);
    };
    rd.into_iter().any(|e| {
        let Ok(e) = e else { return true };
        match fs::symlink_metadata(e.path()) {
            Ok(md) if md.is_dir() && !platform::is_link(&md) => has_files(&e.path()),
            _ => true,
        }
    })
}

/// Removes an entry folder that holds only DevAudit's bookkeeping (manifest, README, temp
/// manifest) and at most an empty payload tree. Anything else: Err, and nothing is removed.
fn remove_entry_dir(dir: &Path) -> Result<(), String> {
    let e = io_err(dir);
    for ent in fs::read_dir(dir).map_err(&e)? {
        let name = ent.map_err(&e)?.file_name();
        let ok = name == MANIFEST || name == MANIFEST_TMP || name == README;
        if !(ok || name == PAYLOAD && !has_files(&dir.join(PAYLOAD))) {
            return Err(format!(
                "{} still holds {}; left in place",
                dir.display(),
                name.to_string_lossy()
            ));
        }
    }
    if exists(&dir.join(PAYLOAD)) {
        remove_empty_tree(&dir.join(PAYLOAD)).map_err(&e)?;
    }
    for n in [README, MANIFEST_TMP] {
        match fs::remove_file(dir.join(n)) {
            Err(x) if x.kind() != io::ErrorKind::NotFound => return Err(e(x)),
            _ => {}
        }
    }
    // The manifest goes last: a crash before here leaves a readable entry; after it, an empty
    // folder that `repair` removes.
    match fs::remove_file(dir.join(MANIFEST)) {
        Err(x) if x.kind() != io::ErrorKind::NotFound => return Err(e(x)),
        _ => {}
    }
    fs::remove_dir(dir).map_err(&e)?;
    if let Some(v) = dir.parent() {
        let _ = platform::sync_dir(v);
    }
    Ok(())
}

fn sync_parent(p: &Path) {
    if let Some(d) = p.parent() {
        let _ = platform::sync_dir(d);
    }
}

fn usage_of(p: &Path) -> u64 {
    disk::usage(p, &[], &AtomicBool::new(false)).bytes
}

// ---------------------------------------------------------------- index

fn index_path(ctx: &Ctx) -> PathBuf {
    ctx.data_dir.join(INDEX_FILE)
}

fn read_index(ctx: &Ctx) -> Result<Index, String> {
    let p = index_path(ctx);
    match fs::read(&p) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Index::default()),
        Err(e) => Err(io_err(&p)(e)),
    }
}

fn data_vault(ctx: &Ctx) -> PathBuf {
    ctx.data_dir.join(platform::VAULT_DIR_NAME)
}

/// The data-dir vault, then every indexed vault (each once).
fn vault_dirs(index: &Index, ctx: &Ctx) -> Vec<PathBuf> {
    let mut out = vec![data_vault(ctx)];
    for v in &index.vaults {
        if !out.iter().any(|o| platform::eq_ci(o, &v.dir)) {
            out.push(v.dir.clone());
        }
    }
    out
}

/// Entry folders in `vault` (named like an id), sorted.
fn entry_dirs(vault: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(vault)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(valid_id))
        .filter(|e| {
            fs::symlink_metadata(e.path()).is_ok_and(|m| m.is_dir() && !platform::is_link(&m))
        })
        .map(|e| e.path())
        .collect();
    v.sort();
    v
}

/// Re-reads `vault`'s manifests into its index rows (registering the vault if new).
fn update_index(ctx: &Ctx, vault: &Path) -> Result<(), String> {
    let mut idx = read_index(ctx)?;
    let rows: Vec<IndexRow> = entry_dirs(vault)
        .iter()
        .filter_map(|d| read_manifest(d).ok())
        .map(|m| IndexRow {
            id: m.id,
            title: m.title,
            bytes: m.bytes,
            expires_at: m.expires_at,
        })
        .collect();
    match idx
        .vaults
        .iter_mut()
        .find(|v| platform::eq_ci(&v.dir, vault))
    {
        Some(v) => v.entries = rows,
        None => idx.vaults.push(IndexVault {
            dir: vault.to_path_buf(),
            entries: rows,
        }),
    }
    fs::create_dir_all(&ctx.data_dir).map_err(io_err(&ctx.data_dir))?;
    platform::set_private_dir(&ctx.data_dir).map_err(io_err(&ctx.data_dir))?;
    let bytes = serde_json::to_vec_pretty(&idx).map_err(|e| e.to_string())?;
    report::write_atomic(&index_path(ctx), &bytes)
}

/// (vault, entry folder) of `id`.
fn locate(ctx: &Ctx, id: &str) -> Result<(PathBuf, PathBuf), String> {
    if !valid_id(id) {
        return Err("No such Recovery entry".into());
    }
    let idx = read_index(ctx).unwrap_or_default();
    for v in vault_dirs(&idx, ctx) {
        let d = v.join(id);
        if fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir() && !platform::is_link(&m)) {
            return Ok((v, d));
        }
    }
    let unplugged = idx
        .vaults
        .iter()
        .any(|v| !v.dir.is_dir() && v.entries.iter().any(|r| r.id == id));
    Err(if unplugged {
        format!("Can't reach this entry: {NOT_CONNECTED}")
    } else {
        "No such Recovery entry".into()
    })
}

/// Marks the vault hidden unless its marker says that was done.
fn ensure_hidden(vault: &Path) -> Result<(), String> {
    let mark = vault.join(HIDDEN_MARK);
    if exists(&mark) {
        return Ok(());
    }
    platform::hide_from_backup_and_index(vault)
        .map_err(|x| format!("can't hide {} from backups: {x}", vault.display()))?;
    platform::create_private(&mark)
        .and_then(|f| f.sync_all())
        .map_err(io_err(&mark))
}

// ---------------------------------------------------------------- move in

fn same_volume(item: &Path, vault: &Path) -> Result<(), String> {
    match (platform::volume_of(item), platform::volume_of(vault)) {
        (Ok(a), Ok(b)) if a == b => Ok(()),
        (Ok(_), Ok(_)) => Err(format!(
            "{} is on another drive than its Recovery folder; not copied",
            item.display()
        )),
        (Err(e), _) => Err(format!("can't read the drive of {}: {e}", item.display())),
        (_, Err(e)) => Err(format!("can't read the drive of {}: {e}", vault.display())),
    }
}

/// Vault for `item`, on its drive, not inside it and not containing it.
fn vault_checked(ctx: &Ctx, item: &Path) -> Result<PathBuf, String> {
    // Checked before anything is created, then again on the real folder.
    let (planned, _) = vault_location(item, ctx)?;
    let item_volume = platform::volume_of(item)
        .map_err(|e| format!("can't read the drive of {}: {e}", item.display()))?;
    if volume_near(&planned)? != item_volume {
        return Err(format!(
            "{} is on another drive than its Recovery folder; not copied",
            item.display()
        ));
    }
    let vault = vault_for(item, ctx)?;
    same_volume(item, &vault)?;
    if platform::inside(item, &vault) || platform::inside(&vault, item) {
        return Err(format!("{} holds Recovery data", item.display()));
    }
    Ok(vault)
}

fn new_manifest(
    ctx: &Ctx,
    kind: EntryKind,
    title: &str,
    original: Option<&Path>,
    tier: Tier,
    keep_days: Option<u32>,
) -> Result<Manifest, String> {
    let now = now_secs(ctx);
    Ok(Manifest {
        id: new_id(ctx)?,
        kind,
        title: title.to_string(),
        original: original.map(Path::to_path_buf),
        file_id: original.and_then(|p| platform::file_id(p).ok()),
        bytes: 0,
        tier,
        moved_at: now,
        expires_at: keep_days.map(|k| now.saturating_add(u64::from(k) * DAY)),
        state: EntryState::Moving,
        note: None,
        files: vec![],
    })
}

/// Registers the vault in the index, then creates `<vault>/<id>/` with its manifest (state as
/// given) and README.
fn begin_entry(ctx: &Ctx, vault: &Path, m: &Manifest) -> Result<PathBuf, String> {
    update_index(ctx, vault)?;
    let dir = vault.join(&m.id);
    fs::create_dir(&dir).map_err(io_err(&dir))?;
    let res = platform::set_private_dir(&dir)
        .map_err(io_err(&dir))
        .and_then(|()| write_manifest(&dir, m))
        .and_then(|()| write_readme(&dir, m));
    if let Err(e) = res {
        let _ = remove_entry_dir(&dir);
        return Err(e);
    }
    Ok(dir)
}

/// Finishes a move: state `Held` (if that write fails, `repair` rolls it forward), index.
fn finish(ctx: &Ctx, vault: &Path, dir: &Path, mut m: Manifest) -> Entry {
    if set_state(dir, &mut m, EntryState::Held).is_err() {
        m.state = EntryState::Moving;
    }
    let _ = update_index(ctx, vault);
    m.entry(vault)
}

/// Same-volume rename of `path` into a new vault entry. Never copies, never deletes; with
/// `keep_days == 0` the caller purges right after.
pub fn move_in(
    ctx: &Ctx,
    _l: &InstanceLock,
    path: &Path,
    kind: EntryKind,
    title: &str,
    tier: Tier,
    keep_days: u32,
) -> Result<Entry, String> {
    if !matches!(kind, EntryKind::Path | EntryKind::Worktree { .. }) {
        return Err("move_in takes a folder or a worktree".into());
    }
    let vault = vault_checked(ctx, path)?;
    let mut m = new_manifest(ctx, kind, title, Some(path), tier, Some(keep_days))?;
    let dir = begin_entry(ctx, &vault, &m)?;
    let payload = dir.join(PAYLOAD);
    if platform::rename_no_replace(path, &payload).is_err() {
        let _ = remove_entry_dir(&dir);
        let _ = update_index(ctx, &vault);
        return Err(IN_USE.into());
    }
    let _ = platform::sync_dir(&dir);
    sync_parent(path);
    m.bytes = usage_of(&payload);
    Ok(finish(ctx, &vault, &dir, m))
}

/// Temp prune: each file is renamed to `payload/<path relative to base>`; files that can't be
/// moved are skipped and listed.
pub fn move_files_in(
    ctx: &Ctx,
    _l: &InstanceLock,
    files: &[PathBuf],
    base: &Path,
    title: &str,
    keep_days: u32,
) -> Result<(Entry, Vec<String>), String> {
    if files.is_empty() {
        return Err("No files to move".into());
    }
    let vault = vault_checked(ctx, base)?;
    let kind = EntryKind::TempFiles {
        base: base.to_path_buf(),
    };
    let mut m = new_manifest(ctx, kind, title, Some(base), Tier::Safe, Some(keep_days))?;
    m.file_id = None;
    let dir = begin_entry(ctx, &vault, &m)?;
    let payload = dir.join(PAYLOAD);
    if let Err(e) = fs::create_dir(&payload) {
        let _ = remove_entry_dir(&dir);
        return Err(io_err(&payload)(e));
    }
    let mut skipped = vec![];
    for f in files {
        let rel = match f.strip_prefix(base) {
            Ok(r)
                if r.components().count() > 0
                    && r.components().all(|c| matches!(c, Component::Normal(_))) =>
            {
                r
            }
            _ => {
                skipped.push(f.display().to_string());
                continue;
            }
        };
        let md = match fs::symlink_metadata(f) {
            Ok(md) if md.is_file() => md,
            _ => {
                skipped.push(f.display().to_string());
                continue;
            }
        };
        let to = payload.join(rel);
        let moved = to
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| platform::rename_no_replace(f, &to));
        match moved {
            Ok(()) => {
                m.bytes += platform::size_on_disk(&md);
                m.files.push(rel.to_string_lossy().into_owned());
                sync_parent(f);
                sync_parent(&to);
            }
            Err(_) => skipped.push(f.display().to_string()),
        }
    }
    if m.files.is_empty() {
        let _ = remove_entry_dir(&dir);
        let _ = update_index(ctx, &vault);
        return Err(format!("No file could be moved: {IN_USE}"));
    }
    Ok((finish(ctx, &vault, &dir, m), skipped))
}

// ---------------------------------------------------------------- docker

/// stdout of a docker command that must succeed.
fn docker(ctx: &Ctx, argv: &[&str], timeout: Duration) -> Result<String, String> {
    match ctx.run.run(argv, timeout) {
        Ok(o) if o.status == 0 => Ok(o.stdout),
        Ok(o) => Err(format!(
            "{} failed: {}",
            argv[..2].join(" "),
            o.stderr.trim()
        )),
        Err(RunError::NotFound(_)) => Err("Docker isn't installed".into()),
        Err(RunError::Timeout) => Err(format!("{} timed out", argv[..2].join(" "))),
        Err(RunError::Io(e)) => Err(format!("{} failed: {e}", argv[..2].join(" "))),
    }
}

fn first_image_id(ctx: &Ctx) -> Result<String, String> {
    docker(ctx, &["docker", "image", "ls", "-q", "--no-trunc"], T)?
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "No local Docker image to run the backup from".into())
}

fn arg_ok(s: &str, what: &str) -> Result<(), String> {
    if s.is_empty() || s.starts_with('-') {
        return Err(format!("Not a valid {what}"));
    }
    Ok(())
}

/// A never-started container with the volume mounted at `/v`. A command is given because images
/// without CMD/ENTRYPOINT refuse `create` otherwise; it never runs.
fn noop_container(ctx: &Ctx, volume: &str, image: &str) -> Result<String, String> {
    let cid = docker(
        ctx,
        &[
            "docker",
            "create",
            "-v",
            &format!("{volume}:/v"),
            image,
            NOOP,
        ],
        T,
    )?
    .trim()
    .to_string();
    arg_ok(&cid, "container id")?;
    Ok(cid)
}

/// The tar reads to its end-of-archive marker (two zero blocks) with valid header checksums.
fn tar_complete(path: &Path) -> Result<(), String> {
    let cut = || "the volume backup is cut short".to_string();
    let mut f = io::BufReader::new(fs::File::open(path).map_err(io_err(path))?);
    let len = fs::metadata(path).map_err(io_err(path))?.len();
    let mut pos = 0u64;
    let mut block = [0u8; 512];
    loop {
        f.read_exact(&mut block).map_err(|_| cut())?;
        pos += 512;
        if block.iter().all(|b| *b == 0) {
            f.read_exact(&mut block).map_err(|_| cut())?;
            return if block.iter().all(|b| *b == 0) {
                Ok(())
            } else {
                Err(cut())
            };
        }
        let octal = |b: &[u8]| -> Option<u64> {
            let s = std::str::from_utf8(b).ok()?;
            let s = s.trim_matches(|c: char| c == '\0' || c == ' ');
            if s.is_empty() {
                Some(0)
            } else {
                u64::from_str_radix(s, 8).ok()
            }
        };
        let sum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if octal(&block[148..156]) != Some(sum) {
            return Err("the volume backup is damaged".into());
        }
        let size = if block[124] & 0x80 != 0 {
            block[125..136].iter().fold(0u64, |a, b| {
                a.saturating_mul(256).saturating_add(u64::from(*b))
            })
        } else {
            octal(&block[124..136]).ok_or("the volume backup is damaged")?
        };
        pos = pos.saturating_add(size.div_ceil(512).saturating_mul(512));
        if pos > len {
            return Err(cut());
        }
        f.seek(SeekFrom::Start(pos)).map_err(io_err(path))?;
    }
}

fn verify_backup(tar: &Path, bytes: u64) -> Result<(), String> {
    tar_complete(tar)?;
    let len = fs::metadata(tar).map_err(io_err(tar))?.len();
    if u128::from(len) * 10 < u128::from(bytes) * 9 {
        return Err(format!(
            "the volume backup is smaller than the volume ({len} of {bytes} bytes)"
        ));
    }
    Ok(())
}

/// Deletes a backup tar DevAudit just wrote (a copy of a volume that still exists), and its entry.
fn drop_backup(ctx: &Ctx, vault: &Path, dir: &Path) {
    let _ = fs::remove_file(dir.join(PAYLOAD).join(VOLUME_TAR));
    let _ = remove_entry_dir(dir);
    let _ = update_index(ctx, vault);
}

/// Copies volume `name` into the vault as `payload/volume.tar`. The volume itself is left alone:
/// only the caller removes it, and only after this returns Ok.
pub fn backup_volume(
    ctx: &Ctx,
    _l: &InstanceLock,
    name: &str,
    bytes: u64,
    keep_days: u32,
) -> Result<Entry, String> {
    arg_ok(name, "volume name")?;
    fs::create_dir_all(&ctx.data_dir).map_err(io_err(&ctx.data_dir))?;
    platform::set_private_dir(&ctx.data_dir).map_err(io_err(&ctx.data_dir))?;
    let vault = vault_for(&ctx.data_dir, ctx)?;
    let image = first_image_id(ctx)?;
    let cid = noop_container(ctx, name, &image)?;
    let copied = (|| {
        let kind = EntryKind::DockerVolume {
            name: name.to_string(),
        };
        let title = format!("Docker volume {name}");
        let m = new_manifest(ctx, kind, &title, None, Tier::Review, Some(keep_days))?;
        let dir = begin_entry(ctx, &vault, &m)?;
        let tar = dir.join(PAYLOAD).join(VOLUME_TAR);
        let res = fs::create_dir(dir.join(PAYLOAD))
            .map_err(io_err(&dir))
            .and_then(|()| {
                let src = format!("{cid}:/v");
                ctx.run
                    .run_to_file(&["docker", "cp", &src, "-"], LONG, &tar)
                    .map_err(|e| format!("docker cp failed: {e:?}"))
            });
        match res {
            Ok(()) => Ok((dir, m, tar)),
            Err(e) => {
                drop_backup(ctx, &vault, &dir);
                Err(e)
            }
        }
    })();
    // Always, even on error.
    let rm = docker(ctx, &["docker", "rm", &cid], T);
    let (dir, mut m, tar) = copied?;
    if let Err(e) = verify_backup(&tar, bytes) {
        drop_backup(ctx, &vault, &dir);
        return Err(e);
    }
    let _ = platform::sync_dir(&dir.join(PAYLOAD));
    m.bytes = fs::symlink_metadata(&tar).map_or(0, |md| platform::size_on_disk(&md));
    if let Err(e) = rm {
        m.note = Some(format!("temporary container {cid} was left behind: {e}"));
    }
    Ok(finish(ctx, &vault, &dir, m))
}

/// Undo metadata without a payload (`DockerStopped` only); never expires.
pub fn record(ctx: &Ctx, _l: &InstanceLock, kind: EntryKind, title: &str) -> Result<Entry, String> {
    let EntryKind::DockerStopped { ids } = &kind else {
        return Err("Only stopped containers are recorded".into());
    };
    if ids.is_empty() {
        return Err("No containers to record".into());
    }
    for id in ids {
        arg_ok(id, "container id")?;
    }
    fs::create_dir_all(&ctx.data_dir).map_err(io_err(&ctx.data_dir))?;
    platform::set_private_dir(&ctx.data_dir).map_err(io_err(&ctx.data_dir))?;
    let vault = vault_for(&ctx.data_dir, ctx)?;
    let mut m = new_manifest(ctx, kind, title, None, Tier::Review, None)?;
    m.state = EntryState::Held;
    begin_entry(ctx, &vault, &m)?;
    let _ = update_index(ctx, &vault);
    Ok(m.entry(&vault))
}

// ---------------------------------------------------------------- list

/// Every entry in every reachable vault; rows of unreachable vaults from the index.
pub fn list(ctx: &Ctx) -> Vec<Entry> {
    let idx = read_index(ctx).unwrap_or_default();
    let mut out = vec![];
    for vault in vault_dirs(&idx, ctx) {
        if !vault.is_dir() {
            let rows = idx
                .vaults
                .iter()
                .filter(|v| platform::eq_ci(&v.dir, &vault))
                .flat_map(|v| v.entries.iter());
            for r in rows {
                out.push(Entry {
                    id: r.id.clone(),
                    kind: EntryKind::Path,
                    title: r.title.clone(),
                    original: None,
                    bytes: r.bytes,
                    tier: Tier::Review,
                    moved_at: 0,
                    expires_at: r.expires_at,
                    state: EntryState::Held,
                    vault_dir: vault.clone(),
                    note: Some(NOT_CONNECTED.into()),
                });
            }
            continue;
        }
        for dir in entry_dirs(&vault) {
            match read_manifest(&dir) {
                Ok(m) => out.push(m.entry(&vault)),
                // An empty folder is a crash leftover (repair removes it), not an entry.
                Err(_) if fs::read_dir(&dir).is_ok_and(|mut r| r.next().is_none()) => {}
                Err(_) => {
                    let id = dir
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    out.push(Entry {
                        title: id.clone(),
                        id,
                        kind: EntryKind::Path,
                        original: None,
                        bytes: 0,
                        tier: Tier::Review,
                        moved_at: 0,
                        expires_at: None,
                        state: EntryState::Orphaned,
                        vault_dir: vault.clone(),
                        note: Some(UNREADABLE.into()),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| b.id.cmp(&a.id));
    out
}

/// Bytes the vaults hold that can be freed now (not orphaned, not on an unplugged drive).
pub fn total_held(ctx: &Ctx) -> u64 {
    list(ctx)
        .iter()
        .filter(|e| e.state != EntryState::Orphaned)
        .filter(|e| e.note.as_deref() != Some(NOT_CONNECTED))
        .map(|e| e.bytes)
        .sum()
}

// ---------------------------------------------------------------- restore

/// Checks a restore target and creates its missing parents. The target must pass `forbidden`
/// (except depth and existence), and every existing ancestor below its allowed root must be a
/// real folder: not a link, not a mount point.
fn prepare_target(ctx: &Ctx, target: &Path) -> Result<(), String> {
    let (roots, _) = projects::roots(ctx);
    if let Some(why) = never::forbidden_restore_target(target, &ctx.never_cfg(&roots)) {
        return Err(format!("Can't restore to {}: {why}", target.display()));
    }
    let root = std::iter::once(ctx.home.clone())
        .chain(roots)
        .filter(|r| platform::inside(target, r))
        .filter_map(|r| Some((platform::canon(&r).ok()?, r)))
        .max_by_key(|(c, _)| c.components().count())
        .ok_or_else(|| {
            format!(
                "Can't restore to {}: outside home and project roots",
                target.display()
            )
        })?;
    let refuse = |a: &Path, why: &str| -> Result<(), String> {
        Err(format!(
            "Can't restore to {}: {} {why}",
            target.display(),
            a.display()
        ))
    };
    let mut missing = vec![];
    let mut reached = false;
    for a in target.ancestors().skip(1) {
        let md = match fs::symlink_metadata(a) {
            Ok(md) => md,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing.push(a);
                continue;
            }
            Err(e) => return Err(format!("can't inspect {}: {e}", a.display())),
        };
        let is_root = platform::eq_ci(a, &root.1);
        if platform::is_link(&md) && !is_root {
            return refuse(a, "became a link");
        }
        if is_root || platform::canon(a).is_ok_and(|c| platform::eq_ci(&c, &root.0)) {
            reached = true;
            break;
        }
        if !md.is_dir() {
            return refuse(a, "is not a folder");
        }
        if platform::is_mount_point(a) {
            return refuse(a, "is a mount point");
        }
    }
    if !reached {
        return refuse(&root.1, "is not above it");
    }
    // One level at a time, re-checking each new folder.
    for a in missing.into_iter().rev() {
        match fs::create_dir(a) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("can't create {}: {e}", a.display())),
        }
        match fs::symlink_metadata(a) {
            Ok(md) if md.is_dir() && !platform::is_link(&md) => {}
            _ => return refuse(a, "is not a plain folder"),
        }
    }
    Ok(())
}

/// `<name>.restored-<yyyyMMdd-HHmmss>`, then `-2`, `-3`…
fn beside(target: &Path, stamp: &str, n: u32) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".restored-{stamp}"));
    if n > 1 {
        name.push(format!("-{n}"));
    }
    target.with_file_name(name)
}

/// Renames `src` to `target`, or beside it if taken. Never overwrites.
fn rename_free(ctx: &Ctx, src: &Path, target: &Path) -> Result<PathBuf, String> {
    let stamp = stamp(now_secs(ctx));
    for n in 0..=1000 {
        let to = if n == 0 {
            target.to_path_buf()
        } else {
            beside(target, &stamp, n)
        };
        match platform::rename_no_replace(src, &to) {
            Ok(()) => {
                sync_parent(&to);
                return Ok(to);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("can't move back to {}: {e}", to.display())),
        }
    }
    Err(format!("no free name next to {}", target.display()))
}

/// Restores entry `id`. Returns where it went.
pub fn restore(ctx: &Ctx, l: &InstanceLock, id: &str) -> Result<PathBuf, String> {
    restore_with_message(ctx, l, id).map(|(p, _)| p)
}

/// `restore`, plus a message for the user (e.g. that a worktree came back beside its old place
/// and `git worktree repair` was skipped).
pub fn restore_with_message(
    ctx: &Ctx,
    _l: &InstanceLock,
    id: &str,
) -> Result<(PathBuf, String), String> {
    let (vault, dir) = locate(ctx, id)?;
    let mut m = read_manifest(&dir).map_err(|_| format!("Can't restore: {UNREADABLE}"))?;
    match m.state {
        EntryState::Held => {}
        EntryState::Purging => {
            return Err("Can't restore: it is being deleted (partly purged)".into());
        }
        EntryState::Orphaned => return Err("Can't restore: the moved item wasn't found".into()),
        EntryState::Moving | EntryState::Restoring => {
            return Err(
                "Can't restore yet: an earlier step didn't finish; run DevAudit again".into(),
            );
        }
    }
    let res = match m.kind.clone() {
        EntryKind::Path | EntryKind::Worktree { .. } => restore_path(ctx, &dir, &mut m),
        EntryKind::TempFiles { base } => restore_temp(ctx, &dir, &mut m, &base),
        EntryKind::DockerVolume { name } => restore_volume(ctx, &dir, &mut m, &name),
        EntryKind::DockerStopped { ids } => restore_stopped(ctx, &dir, &ids),
    };
    let _ = update_index(ctx, &vault);
    res
}

fn restore_path(ctx: &Ctx, dir: &Path, m: &mut Manifest) -> Result<(PathBuf, String), String> {
    let original = m
        .original
        .clone()
        .ok_or("Can't restore: no original place recorded")?;
    prepare_target(ctx, &original)?;
    set_state(dir, m, EntryState::Restoring)?;
    let to = match rename_free(ctx, &dir.join(PAYLOAD), &original) {
        Ok(to) => to,
        Err(e) => {
            let _ = set_state(dir, m, EntryState::Held);
            return Err(e);
        }
    };
    let mut msg = if to == original {
        format!("Restored to {}", to.display())
    } else {
        format!(
            "{} is in use, so it was restored next to it as {}",
            original.display(),
            to.display()
        )
    };
    if let EntryKind::Worktree { repo, .. } = &m.kind {
        if to == original {
            let o = original.to_string_lossy();
            match guard::git(ctx.run, repo, &["worktree", "repair", &o]) {
                Ok(r) if r.status == 0 => {}
                Ok(r) => msg.push_str(&format!(
                    "; `git worktree repair` failed: {}",
                    r.stderr.trim()
                )),
                Err(e) => msg.push_str(&format!("; `git worktree repair` failed: {e:?}")),
            }
        } else {
            msg.push_str("; `git worktree repair` was skipped: move it back, then run it");
        }
    }
    if let Err(e) = remove_entry_dir(dir) {
        msg.push_str(&format!(" (Recovery entry left behind: {e})"));
    }
    Ok((to, msg))
}

/// Files below `dir` (not following links), deepest paths included.
fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            match fs::symlink_metadata(&p) {
                Ok(md) if md.is_dir() && !platform::is_link(&md) => stack.push(p),
                _ => out.push(p),
            }
        }
    }
    out.sort();
    out
}

/// Removes empty folders below (and including) `dir`; stops at anything else.
fn prune_empty_dirs(dir: &Path) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        if fs::symlink_metadata(e.path()).is_ok_and(|m| m.is_dir() && !platform::is_link(&m)) {
            prune_empty_dirs(&e.path());
        }
    }
    let _ = fs::remove_dir(dir);
}

/// Per file back to `base/<rel>` (a taken name: beside it). Files already back are no longer in
/// the payload, so this can run again after a crash. The entry goes once the payload is empty.
fn restore_temp(
    ctx: &Ctx,
    dir: &Path,
    m: &mut Manifest,
    base: &Path,
) -> Result<(PathBuf, String), String> {
    if m.state != EntryState::Restoring {
        set_state(dir, m, EntryState::Restoring)?;
    }
    let payload = dir.join(PAYLOAD);
    let mut failed = vec![];
    let mut beside_count = 0;
    for src in files_below(&payload) {
        let Ok(rel) = src.strip_prefix(&payload) else {
            continue;
        };
        let target = base.join(rel);
        match prepare_target(ctx, &target).and_then(|()| rename_free(ctx, &src, &target)) {
            Ok(to) if to != target => beside_count += 1,
            Ok(_) => {}
            Err(e) => failed.push(e),
        }
    }
    prune_empty_dirs(&payload);
    if !failed.is_empty() || has_files(&payload) {
        m.note = Some(format!(
            "{} file(s) couldn't be restored",
            failed.len().max(1)
        ));
        let _ = set_state(dir, m, EntryState::Held);
        return Err(failed
            .into_iter()
            .next()
            .unwrap_or_else(|| "Some files couldn't be restored".into()));
    }
    let mut msg = format!("Restored to {}", base.display());
    if beside_count > 0 {
        msg.push_str(&format!(
            "; {beside_count} file(s) were restored next to newer files of the same name"
        ));
    }
    if let Err(e) = remove_entry_dir(dir) {
        msg.push_str(&format!(" (Recovery entry left behind: {e})"));
    }
    Ok((base.to_path_buf(), msg))
}

/// Whether volume `name` exists. Err when Docker can't say.
fn volume_exists(ctx: &Ctx, name: &str) -> Result<bool, String> {
    match ctx.run.run(&["docker", "volume", "inspect", name], T) {
        Ok(o) if o.status == 0 => Ok(true),
        Ok(o) if o.stderr.to_ascii_lowercase().contains("no such volume") => Ok(false),
        Ok(o) => Err(format!("docker volume inspect failed: {}", o.stderr.trim())),
        Err(RunError::NotFound(_)) => Err("Docker isn't installed".into()),
        Err(e) => Err(format!("docker volume inspect failed: {e:?}")),
    }
}

/// `name`, or `<name>-restored-<yyyyMMdd>`, `-2`, `-3`… if taken. Never an existing volume.
fn free_volume_name(ctx: &Ctx, name: &str) -> Result<String, String> {
    if !volume_exists(ctx, name)? {
        return Ok(name.to_string());
    }
    let day = &stamp(now_secs(ctx))[..8];
    for n in 1..=100 {
        let cand = if n == 1 {
            format!("{name}-restored-{day}")
        } else {
            format!("{name}-restored-{day}-{n}")
        };
        if !volume_exists(ctx, &cand)? {
            return Ok(cand);
        }
    }
    Err(format!("no free volume name for {name}"))
}

fn restore_volume(
    ctx: &Ctx,
    dir: &Path,
    m: &mut Manifest,
    name: &str,
) -> Result<(PathBuf, String), String> {
    let tar = dir.join(PAYLOAD).join(VOLUME_TAR);
    tar_complete(&tar)?;
    let target = free_volume_name(ctx, name)?;
    let image = first_image_id(ctx)?;
    set_state(dir, m, EntryState::Restoring)?;
    let res = (|| {
        docker(ctx, &["docker", "volume", "create", &target], T)?;
        let cid = noop_container(ctx, &target, &image)?;
        // The tar holds `v/...` (docker cp of `<cid>:/v`), so it is unpacked at `/`.
        let dest = format!("{cid}:/");
        let cp = ctx
            .run
            .run_from_file(&["docker", "cp", "-", &dest], LONG, &tar)
            .map(|_| ())
            .map_err(|e| format!("docker cp failed: {e:?}"));
        let rm = docker(ctx, &["docker", "rm", &cid], T);
        cp.map(|()| rm.err())
    })();
    let rm_note = match res {
        Ok(n) => n,
        Err(e) => {
            let _ = set_state(dir, m, EntryState::Held);
            return Err(format!("{e} (volume {target} may be partly filled)"));
        }
    };
    let mut msg = if target == name {
        format!("Restored Docker volume {name}")
    } else {
        format!("A volume named {name} exists, so it was restored as {target}")
    };
    if let Some(e) = rm_note {
        msg.push_str(&format!("; a temporary container was left behind: {e}"));
    }
    // The tar's content now lives in the volume again.
    let _ = fs::remove_file(&tar);
    if let Err(e) = remove_entry_dir(dir) {
        msg.push_str(&format!(" (Recovery entry left behind: {e})"));
    }
    Ok((PathBuf::from(target), msg))
}

fn restore_stopped(ctx: &Ctx, dir: &Path, ids: &[String]) -> Result<(PathBuf, String), String> {
    for id in ids {
        arg_ok(id, "container id")?;
    }
    let mut argv = vec!["docker", "start"];
    argv.extend(ids.iter().map(String::as_str));
    docker(ctx, &argv, T)?;
    let mut msg = format!("Started {} container(s) again", ids.len());
    if let Err(e) = remove_entry_dir(dir) {
        msg.push_str(&format!(" (Recovery entry left behind: {e})"));
    }
    Ok((PathBuf::from(ids.join(" ")), msg))
}

// ---------------------------------------------------------------- purge

/// The only permanent delete: `Purging` first (restore is then refused), payload, worktree
/// metadata, entry folder. A partial failure stays `Purging` ("partly purged") and the next purge
/// continues.
fn purge_entry(ctx: &Ctx, dir: &Path, mut m: Manifest) -> Result<u64, String> {
    if m.state != EntryState::Purging {
        set_state(dir, &mut m, EntryState::Purging)?;
    }
    if let Err(e) = platform::remove_dir_all_retry(&dir.join(PAYLOAD)) {
        m.note = Some(PARTLY_PURGED.into());
        let _ = write_manifest(dir, &m);
        return Err(format!("{}: {PARTLY_PURGED} ({e})", m.title));
    }
    if let EntryKind::Worktree { repo, .. } = &m.kind {
        // Drops the stale worktree record; the branch is never deleted.
        let _ = guard::git(ctx.run, repo, &["worktree", "prune"]);
    }
    remove_entry_dir(dir)?;
    Ok(m.bytes)
}

/// Deletes entry `id` for good. Returns the bytes freed.
pub fn purge(ctx: &Ctx, _l: &InstanceLock, id: &str) -> Result<u64, String> {
    let (vault, dir) = locate(ctx, id)?;
    let m = read_manifest(&dir).map_err(|_| format!("Can't free it: {UNREADABLE}"))?;
    if matches!(m.state, EntryState::Moving | EntryState::Restoring) {
        return Err("Can't free it yet: an earlier step didn't finish; run DevAudit again".into());
    }
    let res = purge_entry(ctx, &dir, m);
    let _ = update_index(ctx, &vault);
    res
}

/// Purges `Held` entries whose `expires_at` has passed. Unreadable and orphaned entries are
/// never touched.
pub fn purge_expired(ctx: &Ctx, _l: &InstanceLock) -> (u64, Vec<String>) {
    let now = now_secs(ctx);
    let idx = read_index(ctx).unwrap_or_default();
    let (mut freed, mut notes) = (0, vec![]);
    for vault in vault_dirs(&idx, ctx) {
        let mut touched = false;
        for dir in entry_dirs(&vault) {
            let Ok(m) = read_manifest(&dir) else { continue };
            if m.state != EntryState::Held || !m.expires_at.is_some_and(|x| x < now) {
                continue;
            }
            touched = true;
            match purge_entry(ctx, &dir, m) {
                Ok(b) => freed += b,
                Err(e) => notes.push(e),
            }
        }
        if touched {
            let _ = update_index(ctx, &vault);
        }
    }
    (freed, notes)
}

// ---------------------------------------------------------------- repair

/// Whether the moved item is in the payload. TempFiles: at least one file moved.
fn payload_present(m: &Manifest, payload: &Path) -> bool {
    match m.kind {
        EntryKind::TempFiles { .. } => has_files(payload),
        _ => exists(payload),
    }
}

fn repair_entry(ctx: &Ctx, dir: &Path) -> Option<String> {
    use EntryState::*;
    let payload = dir.join(PAYLOAD);
    let Ok(mut m) = read_manifest(dir) else {
        // No manifest and no payload: a folder created just before a crash. Anything else
        // without a readable manifest is left alone ("unreadable — restore by hand").
        if !exists(&dir.join(MANIFEST)) && !exists(&payload) && remove_entry_dir(dir).is_ok() {
            return None;
        }
        return Some(format!("{}: {UNREADABLE}", dir.display()));
    };
    let title = m.title.clone();
    let present = payload_present(&m, &payload);
    let original_present = m.original.as_deref().is_some_and(exists);
    let gone = |r: Result<(), String>| r.err().map(|e| format!("{title}: {e}"));
    let kind = m.kind.clone();
    match (m.state, &kind) {
        (Held | Orphaned, _) => None,
        (Moving | Restoring, EntryKind::DockerStopped { .. }) => gone(set_state(dir, &mut m, Held)),
        // `docker volume rm` runs only after the backup is Held: the volume still exists.
        (Moving, EntryKind::DockerVolume { .. }) => {
            let _ = fs::remove_file(payload.join(VOLUME_TAR));
            gone(remove_entry_dir(dir))
        }
        (Moving, _) if present => {
            if m.bytes == 0 && !matches!(m.kind, EntryKind::TempFiles { .. }) {
                m.bytes = usage_of(&payload);
            }
            gone(set_state(dir, &mut m, Held))
        }
        (Moving, _) if original_present => gone(remove_entry_dir(dir)),
        (Moving, _) => {
            m.note = Some(format!(
                "the moved item is neither here nor at {}; never deleted automatically",
                m.original.as_deref().unwrap_or(Path::new("?")).display()
            ));
            gone(set_state(dir, &mut m, Orphaned))
        }
        (Restoring, EntryKind::TempFiles { base }) => restore_temp(ctx, dir, &mut m, base)
            .err()
            .map(|e| format!("{title}: {e}")),
        (Restoring, _) if present => gone(set_state(dir, &mut m, Held)),
        (Restoring, _) => gone(remove_entry_dir(dir)),
        (Purging, _) => purge_entry(ctx, dir, m).err(),
    }
}

/// Journal recovery: finishes or rolls back every interrupted step, and marks vaults whose
/// hiding didn't finish. Runs at the start of every scan, execute and CLI command.
pub fn repair(ctx: &Ctx, _l: &InstanceLock) -> Vec<String> {
    let mut out = vec![];
    let idx = read_index(ctx).unwrap_or_else(|e| {
        out.push(format!("Recovery index unreadable: {e}"));
        Index::default()
    });
    for vault in vault_dirs(&idx, ctx) {
        if !vault.is_dir() {
            continue;
        }
        if let Err(e) = ensure_hidden(&vault) {
            out.push(e);
        }
        for dir in entry_dirs(&vault) {
            out.extend(repair_entry(ctx, &dir));
        }
        if let Err(e) = update_index(ctx, &vault) {
            out.push(e);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::tests::{old, real, sh};
    use crate::model::Os;
    use crate::platform::KnownDirs;
    use crate::rules;
    use std::fs;
    use std::time::SystemTime;

    struct Env {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        rules: rules::Rules,
        run: crate::run::SystemRunner,
        dirs: KnownDirs,
    }

    impl Env {
        fn new() -> Env {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().canonicalize().unwrap().join("home");
            let root = home.join("code");
            fs::create_dir_all(&root).unwrap();
            let mut rules = rules::builtin();
            rules.project_roots = vec![root.to_string_lossy().into_owned()];
            let dirs = KnownDirs {
                home: home.clone(),
                local_app_data: Some(home.join("AppData/Local")),
                app_data: Some(home.join("AppData/Roaming")),
                temp: home.join("AppData/Local/Temp"),
                personal: vec![],
                cloud_roots: vec![],
                apps_dir: PathBuf::new(),
            };
            Env {
                _tmp: tmp,
                root,
                rules,
                run: real(),
                dirs,
            }
        }
        fn ctx(&self) -> Ctx<'_> {
            Ctx::new(
                Os::current(),
                self.dirs.clone(),
                self.dirs.home.join(".devaudit"),
                &self.run,
                &self.rules,
                SystemTime::now(),
                1,
            )
        }
    }

    #[test]
    fn same_volume_uses_data_dir() {
        let e = Env::new();
        let ctx = e.ctx();
        let item = e.root.join("proj/node_modules");
        fs::create_dir_all(&item).unwrap();
        let v = vault_for(&item, &ctx).unwrap();
        assert_eq!(v, ctx.data_dir.join(platform::VAULT_DIR_NAME));
        assert!(v.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&v).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn other_volume_uses_project_root_vault_and_git_exclude() {
        let e = Env::new();
        let ctx = e.ctx();
        // The root itself is a git repo.
        fs::write(e.root.join("a.txt"), "x").unwrap();
        sh(&e.root, &["init", "-q"]);
        sh(&e.root, &["add", "."]);
        sh(&e.root, &["commit", "-q", "-m", "m"]);
        old(&e.root.join("a.txt"));
        let item = e.root.join("proj/node_modules");
        fs::create_dir_all(&item).unwrap();
        // The data dir is on another volume, the project root is not.
        platform::fake_volume(&ctx.data_dir, 424_242);
        let v = vault_for(&item, &ctx).unwrap();
        let root = platform::canon(&e.root).unwrap();
        assert_eq!(
            v,
            root.join(".devaudit-vault").join(platform::VAULT_DIR_NAME)
        );
        assert!(v.is_dir());
        let ex = fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert!(ex.lines().any(|l| l == ".devaudit-vault/"), "{ex}");
        // Calling again doesn't duplicate the line.
        vault_for(&item, &ctx).unwrap();
        let ex = fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert_eq!(ex.lines().filter(|l| *l == ".devaudit-vault/").count(), 1);
        // The vault never shows in git status.
        fs::write(v.join("payload.txt"), "p").unwrap();
        let o = std::process::Command::new(crate::guard::tests::git_bin())
            .args(["status", "--porcelain"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            o.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&o.stdout)
        );
    }

    #[test]
    fn no_root_on_this_drive_is_refused() {
        let e = Env::new();
        let ctx = e.ctx();
        let outside = e.dirs.home.join(".cache/thing");
        fs::create_dir_all(&outside).unwrap();
        platform::fake_volume(&ctx.data_dir, 424_242);
        let err = vault_for(&outside, &ctx).unwrap_err();
        assert!(err.contains("no Recovery space on this drive"), "{err}");
        assert!(!ctx.data_dir.exists());
    }

    #[test]
    fn root_on_another_volume_than_item_is_not_used() {
        let e = Env::new();
        let ctx = e.ctx();
        let item = e.root.join("proj/node_modules");
        fs::create_dir_all(&item).unwrap();
        platform::fake_volume(&ctx.data_dir, 424_242);
        platform::fake_volume(&item, 515_151);
        let err = vault_for(&item, &ctx).unwrap_err();
        assert!(err.contains("no Recovery space"), "{err}");
        assert!(!e.root.join(".devaudit-vault").exists());
    }

    #[test]
    fn uncreatable_or_linked_vault_is_refused() {
        let e = Env::new();
        let ctx = e.ctx();
        let item = e.root.join("proj/node_modules");
        fs::create_dir_all(&item).unwrap();
        platform::fake_volume(&ctx.data_dir, 424_242);
        fs::write(e.root.join(".devaudit-vault"), "in the way").unwrap();
        assert!(vault_for(&item, &ctx).is_err());
        fs::remove_file(e.root.join(".devaudit-vault")).unwrap();
        // A link standing in for the vault folder is never followed.
        let elsewhere = e.dirs.home.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        if platform::tests::dir_link(&elsewhere, &e.root.join(".devaudit-vault")) {
            assert!(vault_for(&item, &ctx).is_err());
            assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
        }
    }

    // ------------------------------------------------------------- Task 13: the vault

    use crate::lock::{self, InstanceLock};
    use crate::run::{FakeRunner, Output, Runner};
    use std::time::Duration;

    impl Env {
        fn ctx_with<'a>(&'a self, run: &'a dyn Runner, now: SystemTime) -> Ctx<'a> {
            Ctx::new(
                Os::current(),
                self.dirs.clone(),
                self.dirs.home.join(".devaudit"),
                run,
                &self.rules,
                now,
                1,
            )
        }
        fn lock(&self) -> InstanceLock {
            lock::acquire(&self.dirs.home.join("lockdir")).unwrap()
        }
        fn vault(&self) -> PathBuf {
            self.dirs
                .home
                .join(".devaudit")
                .join(platform::VAULT_DIR_NAME)
        }
    }

    /// Writes `files` (relative path, content) under `dir`.
    fn build(dir: &Path, files: &[(&str, &str)]) {
        fs::create_dir_all(dir).unwrap();
        for (rel, text) in files {
            let p = dir.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }
    }

    /// Every file and dir below `dir`, relative, with file contents; sorted.
    type Tree = Vec<(PathBuf, Option<Vec<u8>>)>;

    fn tree(dir: &Path) -> Tree {
        let mut out = vec![];
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                let rel = p.strip_prefix(dir).unwrap().to_path_buf();
                if e.file_type().unwrap().is_dir() {
                    out.push((rel, None));
                    stack.push(p);
                } else {
                    out.push((rel, Some(fs::read(&p).unwrap())));
                }
            }
        }
        out.sort();
        out
    }

    /// Entry folders in a vault (the hidden marker file is not one).
    fn entries_in(vault: &Path) -> Vec<PathBuf> {
        match fs::read_dir(vault) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| e.file_type().unwrap().is_dir())
                .map(|e| e.path())
                .collect(),
            Err(_) => vec![],
        }
    }

    fn sample(e: &Env) -> (PathBuf, Tree) {
        let nm = e.root.join("proj/node_modules");
        build(
            &nm,
            &[("a/b.js", "x"), ("c.txt", "yy"), ("d/e/f.json", "{}")],
        );
        (nm.clone(), tree(&nm))
    }

    fn manifest_of(ent: &Entry) -> Manifest {
        read_manifest(&ent.vault_dir.join(&ent.id)).unwrap()
    }

    #[test]
    fn move_in_then_restore_round_trip() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, before) = sample(&e);
        let ent = move_in(
            &ctx,
            &l,
            &nm,
            EntryKind::Path,
            "node_modules",
            Tier::Safe,
            3,
        )
        .unwrap();
        assert!(!nm.exists());
        assert_eq!(ent.state, EntryState::Held);
        assert_eq!(ent.vault_dir, e.vault());
        assert_eq!(ent.original.as_deref(), Some(nm.as_path()));
        assert_eq!(ent.expires_at, Some(ent.moved_at + 3 * DAY));
        assert!(ent.bytes > 0);
        assert!(valid_id(&ent.id), "{}", ent.id);
        let payload = ent.vault_dir.join(&ent.id).join(PAYLOAD);
        assert_eq!(tree(&payload), before);
        assert_eq!(list(&ctx), vec![ent.clone()]);
        assert_eq!(total_held(&ctx), ent.bytes);
        // The index names the vault and the entry.
        let idx = fs::read_to_string(ctx.data_dir.join(INDEX_FILE)).unwrap();
        assert!(idx.contains(&ent.id), "{idx}");

        assert!(restore(&ctx, &l, "../../etc").is_err());
        let to = restore(&ctx, &l, &ent.id).unwrap();
        assert_eq!(to, nm);
        assert_eq!(tree(&nm), before);
        assert!(!ent.vault_dir.join(&ent.id).exists());
        assert!(list(&ctx).is_empty());
        assert_eq!(total_held(&ctx), 0);
    }

    #[test]
    fn restore_beside_when_original_exists() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, before) = sample(&e);
        let first = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        // The user ran `npm install` meanwhile.
        build(&nm, &[("fresh.txt", "new")]);
        let to = restore(&ctx, &l, &first.id).unwrap();
        let stamp = stamp(now_secs(&ctx));
        assert_eq!(
            to,
            e.root.join(format!("proj/node_modules.restored-{stamp}"))
        );
        assert_eq!(tree(&to), before);
        assert_eq!(tree(&nm), vec![("fresh.txt".into(), Some(b"new".to_vec()))]);

        // Both names taken: "-2".
        let fresh = tree(&nm);
        let second = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        build(&nm, &[("third.txt", "3")]);
        let to2 = restore(&ctx, &l, &second.id).unwrap();
        assert_eq!(
            to2,
            e.root.join(format!("proj/node_modules.restored-{stamp}-2"))
        );
        assert_eq!(tree(&to2), fresh);
        assert_eq!(tree(&to), before);
    }

    #[test]
    fn restore_never_overwrites_empty_dir_created_meanwhile() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, before) = sample(&e);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        fs::create_dir(&nm).unwrap();
        let to = restore(&ctx, &l, &ent.id).unwrap();
        assert_ne!(to, nm);
        assert_eq!(tree(&to), before);
        assert!(nm.is_dir() && tree(&nm).is_empty());
    }

    #[test]
    fn restore_of_depth_two_cache_allowed() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let cache = e.dirs.home.join(".npm/_cacache");
        build(&cache, &[("index-v5/aa", "1"), ("content-v2/bb", "2")]);
        let before = tree(&cache);
        let ent = move_in(&ctx, &l, &cache, EntryKind::Path, "npm", Tier::Safe, 3).unwrap();
        // ~/.npm is only one level below home; it is gone and must be recreated.
        fs::remove_dir(e.dirs.home.join(".npm")).unwrap();
        assert_eq!(restore(&ctx, &l, &ent.id).unwrap(), cache);
        assert_eq!(tree(&cache), before);
    }

    #[test]
    fn restore_refused_when_parent_became_link() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, before) = sample(&e);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        let proj = e.root.join("proj");
        fs::remove_dir(&proj).unwrap();
        let elsewhere = e.dirs.home.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        if !platform::tests::dir_link(&elsewhere, &proj) {
            return;
        }
        let err = restore(&ctx, &l, &ent.id).unwrap_err();
        assert!(err.contains("link"), "{err}");
        assert!(tree(&elsewhere).is_empty());
        let payload = ent.vault_dir.join(&ent.id).join(PAYLOAD);
        assert_eq!(tree(&payload), before);
        assert_eq!(manifest_of(&ent).state, EntryState::Held);
    }

    #[test]
    fn restore_recreates_missing_parent() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let nm = e.root.join("proj/sub/node_modules");
        build(&nm, &[("x.js", "x")]);
        let before = tree(&nm);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        fs::remove_dir_all(e.root.join("proj")).unwrap();
        assert_eq!(restore(&ctx, &l, &ent.id).unwrap(), nm);
        assert_eq!(tree(&nm), before);
    }

    #[test]
    fn restore_refused_while_purging() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, before) = sample(&e);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        let dir = ent.vault_dir.join(&ent.id);
        let mut m = manifest_of(&ent);
        m.state = EntryState::Purging;
        write_manifest(&dir, &m).unwrap();
        assert!(restore(&ctx, &l, &ent.id).is_err());
        m.state = EntryState::Orphaned;
        write_manifest(&dir, &m).unwrap();
        assert!(restore(&ctx, &l, &ent.id).is_err());
        assert!(!nm.exists());
        assert_eq!(tree(&dir.join(PAYLOAD)), before);
    }

    #[test]
    fn cross_volume_move_refused_without_copy() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, before) = sample(&e);
        // The vault reports another drive than the item.
        platform::fake_volume(&e.vault(), 999_999);
        let err = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap_err();
        assert!(err.contains("drive"), "{err}");
        assert_eq!(tree(&nm), before);
        assert!(!e.vault().exists());
        assert!(list(&ctx).is_empty());
    }

    #[test]
    fn failed_rename_leaves_no_entry() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let missing = e.root.join("proj/gone");
        fs::create_dir_all(e.root.join("proj")).unwrap();
        assert!(move_in(&ctx, &l, &missing, EntryKind::Path, "x", Tier::Safe, 3).is_err());
        assert!(entries_in(&e.vault()).is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (nm, before) = sample(&e);
            let proj = e.root.join("proj");
            fs::set_permissions(&proj, fs::Permissions::from_mode(0o555)).unwrap();
            let r = move_in(&ctx, &l, &nm, EntryKind::Path, "x", Tier::Safe, 3);
            fs::set_permissions(&proj, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(r.unwrap_err(), IN_USE);
            assert_eq!(tree(&nm), before);
            assert!(entries_in(&e.vault()).is_empty());
            assert!(list(&ctx).is_empty());
        }
    }

    /// An entry written by hand (as a crash would leave it).
    fn hand_entry(
        vault: &Path,
        n: u32,
        kind: EntryKind,
        original: Option<PathBuf>,
        state: EntryState,
        payload: bool,
    ) -> PathBuf {
        let id = format!("20260101-000000-{n:08x}");
        let dir = vault.join(&id);
        fs::create_dir_all(&dir).unwrap();
        if payload {
            build(&dir.join(PAYLOAD), &[("sub/f.txt", "data")]);
        }
        write_manifest(
            &dir,
            &Manifest {
                id,
                kind,
                title: format!("entry {n}"),
                original,
                file_id: None,
                bytes: 5,
                tier: Tier::Review,
                moved_at: 0,
                expires_at: Some(1),
                state,
                note: None,
                files: vec![],
            },
        )
        .unwrap();
        dir
    }

    #[test]
    fn repair_rolls_forward_and_back() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let v = vault_for(&e.root, &ctx).unwrap();
        let orig = |n: &str| e.root.join("proj").join(n);
        let st = |d: &Path| read_manifest(d).unwrap().state;
        use EntryState::*;

        let moved = hand_entry(&v, 1, EntryKind::Path, Some(orig("a")), Moving, true);
        build(&orig("b"), &[("keep.txt", "k")]);
        let never_moved = hand_entry(&v, 2, EntryKind::Path, Some(orig("b")), Moving, false);
        let lost = hand_entry(&v, 3, EntryKind::Path, Some(orig("c")), Moving, false);
        let back = hand_entry(&v, 4, EntryKind::Path, Some(orig("d")), Restoring, true);
        let restored = hand_entry(&v, 5, EntryKind::Path, Some(orig("e")), Restoring, false);
        let base = e.dirs.temp.clone();
        fs::create_dir_all(&base).unwrap();
        let temp = hand_entry(
            &v,
            6,
            EntryKind::TempFiles { base: base.clone() },
            Some(base.clone()),
            Restoring,
            true,
        );
        let purging = hand_entry(&v, 7, EntryKind::Path, Some(orig("g")), Purging, true);
        let garbage = v.join("20260101-000000-00000008");
        fs::create_dir_all(garbage.join(PAYLOAD)).unwrap();
        fs::write(garbage.join(MANIFEST), "{ not json").unwrap();
        let empty = v.join("20260101-000000-00000009");
        fs::create_dir_all(&empty).unwrap();
        let backup = hand_entry(
            &v,
            10,
            EntryKind::DockerVolume { name: "db".into() },
            None,
            Moving,
            false,
        );
        build(&backup.join(PAYLOAD), &[("volume.tar", "cut short")]);

        repair(&ctx, &l);

        assert_eq!(st(&moved), Held);
        assert!(read_manifest(&moved).unwrap().bytes > 0);
        assert!(!never_moved.exists());
        assert_eq!(
            tree(&orig("b")),
            vec![("keep.txt".into(), Some(b"k".to_vec()))]
        );
        let m = read_manifest(&lost).unwrap();
        assert_eq!(m.state, Orphaned);
        assert!(m.note.is_some());
        assert!(lost.exists());
        assert_eq!(st(&back), Held);
        assert!(!restored.exists());
        assert!(!temp.exists());
        assert_eq!(fs::read_to_string(base.join("sub/f.txt")).unwrap(), "data");
        assert!(!purging.exists());
        assert_eq!(
            fs::read_to_string(garbage.join(MANIFEST)).unwrap(),
            "{ not json"
        );
        assert!(garbage.join(PAYLOAD).exists());
        assert!(!empty.exists());
        assert!(!backup.exists());
        // Running it again changes nothing.
        repair(&ctx, &l);
        assert_eq!(st(&moved), Held);
        assert_eq!(st(&lost), Orphaned);
    }

    #[test]
    fn purge_frees_and_removes_entry() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, _) = sample(&e);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        assert_eq!(purge(&ctx, &l, &ent.id).unwrap(), ent.bytes);
        assert!(!ent.vault_dir.join(&ent.id).exists());
        assert!(!nm.exists());
        assert!(list(&ctx).is_empty());
        assert!(purge(&ctx, &l, &ent.id).is_err());
    }

    #[test]
    fn partial_purge_stays_purging_and_resumes() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let nm = e.root.join("proj/node_modules");
        build(&nm, &[("a.txt", "a"), ("locked/f.txt", "f")]);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        let dir = ent.vault_dir.join(&ent.id);
        let locked = dir.join(PAYLOAD).join("locked");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
        }
        #[cfg(windows)]
        let hold = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(locked.join("f.txt"))
                .unwrap()
        };
        assert!(purge(&ctx, &l, &ent.id).is_err());
        let m = manifest_of(&ent);
        assert_eq!(m.state, EntryState::Purging);
        assert_eq!(m.note.as_deref(), Some(PARTLY_PURGED));
        let shown = list(&ctx);
        assert_eq!(shown[0].state, EntryState::Purging);
        assert_eq!(shown[0].note.as_deref(), Some(PARTLY_PURGED));
        // Never restored half-empty.
        assert!(restore(&ctx, &l, &ent.id).is_err());
        assert!(!nm.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(windows)]
        drop(hold);
        assert_eq!(purge(&ctx, &l, &ent.id).unwrap(), ent.bytes);
        assert!(!dir.exists());
    }

    #[test]
    fn purge_expired_only_touches_expired_held() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let v = vault_for(&e.root, &ctx).unwrap();
        let now = now_secs(&ctx);
        let set_expiry = |d: &Path, at: u64| {
            let mut m = read_manifest(d).unwrap();
            m.expires_at = Some(at);
            write_manifest(d, &m).unwrap();
        };
        use EntryState::*;
        let old = hand_entry(&v, 1, EntryKind::Path, Some(e.root.join("p/a")), Held, true);
        set_expiry(&old, now - DAY);
        let young = hand_entry(&v, 2, EntryKind::Path, Some(e.root.join("p/b")), Held, true);
        set_expiry(&young, now + DAY);
        let orphan = hand_entry(
            &v,
            3,
            EntryKind::Path,
            Some(e.root.join("p/c")),
            Orphaned,
            true,
        );
        set_expiry(&orphan, now - DAY);
        let garbage = v.join("20260101-000000-00000004");
        build(&garbage.join(PAYLOAD), &[("x", "x")]);
        fs::write(garbage.join(MANIFEST), "garbage").unwrap();

        let (freed, notes) = purge_expired(&ctx, &l);
        assert_eq!(freed, 5, "{notes:?}");
        assert!(!old.exists());
        assert!(young.join(PAYLOAD).exists());
        assert!(orphan.join(PAYLOAD).exists());
        assert!(garbage.join(PAYLOAD).join("x").exists());
    }

    #[test]
    fn readme_contains_original_path() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, _) = sample(&e);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        let text = fs::read_to_string(ent.vault_dir.join(&ent.id).join(README)).unwrap();
        assert!(
            text.starts_with("This folder was moved here by DevAudit on "),
            "{text}"
        );
        assert!(
            text.contains("To restore it by hand, move the \"payload\" folder back to:\n"),
            "{text}"
        );
        assert!(text.contains(&format!("  {}\n", nm.display())), "{text}");
        assert!(text.contains("It is deleted permanently after "), "{text}");
        assert!(text.contains(" unless you restore it."), "{text}");
    }

    #[test]
    fn vault_hidden_from_backup_and_index() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let (nm, _) = sample(&e);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        assert!(platform::is_hidden_from_backup_and_index(&ent.vault_dir));
        let mark = ent.vault_dir.join(HIDDEN_MARK);
        assert!(mark.is_file());
        // A crash between creating the vault and marking it: repair marks it.
        fs::remove_file(&mark).unwrap();
        repair(&ctx, &l);
        assert!(mark.is_file());
        assert!(platform::is_hidden_from_backup_and_index(&ent.vault_dir));
    }

    #[test]
    fn project_root_vault_excluded_from_git() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        fs::write(e.root.join(".gitignore"), "node_modules/\n").unwrap();
        sh(&e.root, &["init", "-q"]);
        sh(&e.root, &["add", "."]);
        sh(&e.root, &["commit", "-q", "-m", "m"]);
        let (nm, before) = sample(&e);
        platform::fake_volume(&ctx.data_dir, 424_242);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        let root = platform::canon(&e.root).unwrap();
        assert_eq!(
            ent.vault_dir,
            root.join(".devaudit-vault").join(platform::VAULT_DIR_NAME)
        );
        let ex = fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert!(ex.lines().any(|l| l == ".devaudit-vault/"), "{ex}");
        let o = std::process::Command::new(crate::guard::tests::git_bin())
            .args(["status", "--porcelain"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            o.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&o.stdout)
        );
        // Listed through the index; restores from there.
        assert_eq!(list(&ctx).len(), 1);
        assert_eq!(restore(&ctx, &l, &ent.id).unwrap(), nm);
        assert_eq!(tree(&nm), before);
    }

    #[test]
    fn unreachable_vault_listed_as_drive_not_connected() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        fs::create_dir_all(&ctx.data_dir).unwrap();
        let gone = e.dirs.home.join("unplugged/.devaudit-vault/vault");
        let idx = serde_json::json!({ "vaults": [ { "dir": gone, "entries": [
            { "id": "20260101-000000-0000000a", "title": "old stuff", "bytes": 7, "expires_at": null }
        ] } ] });
        fs::write(ctx.data_dir.join(INDEX_FILE), idx.to_string()).unwrap();
        let shown = list(&ctx);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].title, "old stuff");
        assert_eq!(shown[0].bytes, 7);
        assert_eq!(shown[0].note.as_deref(), Some(NOT_CONNECTED));
        let err = restore(&ctx, &l, "20260101-000000-0000000a").unwrap_err();
        assert!(err.contains(NOT_CONNECTED), "{err}");
        // Repair and a later move-in keep the row.
        repair(&ctx, &l);
        let (nm, _) = sample(&e);
        move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        assert_eq!(list(&ctx).len(), 2);
    }

    #[test]
    fn list_survives_corrupt_manifest() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let v = vault_for(&e.root, &ctx).unwrap();
        let bad = v.join("20260101-000000-0000000b");
        build(&bad.join(PAYLOAD), &[("x", "x")]);
        fs::write(bad.join(MANIFEST), [0xff, 0xfe, 0x00]).unwrap();
        let shown = list(&ctx);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].id, "20260101-000000-0000000b");
        assert_eq!(shown[0].note.as_deref(), Some(UNREADABLE));
        assert!(purge(&ctx, &l, &shown[0].id).is_err());
        assert!(restore(&ctx, &l, &shown[0].id).is_err());
        assert!(bad.join(PAYLOAD).join("x").exists());
    }

    #[test]
    fn long_path_and_unicode_round_trip() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let mut nm = e.root.join("Café ☕ 日本 project");
        for i in 0..6 {
            nm.push(format!("{i}-{}", "deep folder name ü".repeat(3)));
        }
        nm.push("node_modules");
        assert!(nm.as_os_str().len() > 300);
        build(
            &nm,
            &[("Ünïcödé 文件.js", "u"), ("with space/x y.txt", "s")],
        );
        let before = tree(&nm);
        let ent = move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 3).unwrap();
        assert!(!nm.exists());
        fs::remove_dir_all(e.root.join("Café ☕ 日本 project")).unwrap();
        assert_eq!(restore(&ctx, &l, &ent.id).unwrap(), nm);
        assert_eq!(tree(&nm), before);
    }

    #[test]
    fn temp_files_move_and_restore_per_file() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let base = e.dirs.temp.clone();
        build(
            &base,
            &[("a.txt", "A"), ("sub/b.txt", "B"), ("sub/deep/c.txt", "C")],
        );
        let files = vec![
            base.join("a.txt"),
            base.join("sub/b.txt"),
            base.join("sub/deep/c.txt"),
        ];
        #[cfg(unix)]
        fs::remove_file(&files[2]).unwrap();
        #[cfg(windows)]
        let hold = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&files[2])
                .unwrap()
        };
        let (ent, skipped) = move_files_in(&ctx, &l, &files, &base, "Temp files", 3).unwrap();
        #[cfg(windows)]
        drop(hold);
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].contains("c.txt"), "{skipped:?}");
        assert!(!files[0].exists() && !files[1].exists());
        assert_eq!(ent.kind, EntryKind::TempFiles { base: base.clone() });
        let payload = ent.vault_dir.join(&ent.id).join(PAYLOAD);
        assert_eq!(fs::read_to_string(payload.join("a.txt")).unwrap(), "A");
        assert_eq!(fs::read_to_string(payload.join("sub/b.txt")).unwrap(), "B");
        assert_eq!(manifest_of(&ent).files.len(), 2);

        // Something new took a.txt's name meanwhile: restored beside it.
        fs::write(&files[0], "new A").unwrap();
        assert_eq!(restore(&ctx, &l, &ent.id).unwrap(), base);
        assert_eq!(fs::read_to_string(&files[0]).unwrap(), "new A");
        let beside = base.join(format!("a.txt.restored-{}", stamp(now_secs(&ctx))));
        assert_eq!(fs::read_to_string(beside).unwrap(), "A");
        assert_eq!(fs::read_to_string(&files[1]).unwrap(), "B");
        assert!(!ent.vault_dir.join(&ent.id).exists());
    }

    #[test]
    fn worktree_round_trip() {
        let e = Env::new();
        let ctx = e.ctx();
        let l = e.lock();
        let repo = e.root.join("repo");
        build(&repo, &[("a.txt", "x")]);
        sh(&repo, &["init", "-q"]);
        sh(&repo, &["add", "."]);
        sh(&repo, &["commit", "-q", "-m", "m"]);
        let wt = e.root.join("repo-feature");
        sh(
            &repo,
            &["worktree", "add", "-b", "feature", wt.to_str().unwrap()],
        );
        fs::write(wt.join(".env"), "SECRET=1").unwrap();
        let wt_list = || {
            let o = std::process::Command::new(crate::guard::tests::git_bin())
                .args(["worktree", "list", "--porcelain"])
                .current_dir(&repo)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        let kind = EntryKind::Worktree {
            repo: repo.clone(),
            branch: "feature".into(),
        };
        let ent = move_in(&ctx, &l, &wt, kind, "worktree", Tier::Review, 30).unwrap();
        assert!(!wt.exists());
        assert!(wt_list().contains("prunable"), "{}", wt_list());
        assert_eq!(restore(&ctx, &l, &ent.id).unwrap(), wt);
        let listed = wt_list();
        assert!(!listed.contains("prunable"), "{listed}");
        assert!(listed.contains("feature"), "{listed}");
        assert_eq!(fs::read_to_string(wt.join(".env")).unwrap(), "SECRET=1");
    }

    fn ok(stdout: &str) -> Result<Output, crate::run::RunError> {
        Ok(Output {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    fn no_such_volume() -> Result<Output, crate::run::RunError> {
        Ok(Output {
            status: 1,
            stdout: String::new(),
            stderr: "Error response from daemon: get data: no such volume".into(),
        })
    }

    /// A one-file tar (`v/a.txt` = "hello"), with or without its end-of-archive marker.
    fn tar(complete: bool) -> String {
        let mut h = [0u8; 512];
        let put = |h: &mut [u8; 512], at: usize, s: &str| {
            h[at..at + s.len()].copy_from_slice(s.as_bytes())
        };
        put(&mut h, 0, "v/a.txt");
        put(&mut h, 100, "0000644");
        put(&mut h, 108, "0000000");
        put(&mut h, 116, "0000000");
        put(&mut h, 124, "00000000005");
        put(&mut h, 136, "00000000000");
        h[156] = b'0';
        put(&mut h, 257, "ustar");
        put(&mut h, 263, "00");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        put(&mut h, 148, &format!("{sum:06o}\0"));
        let mut out = h.to_vec();
        let mut data = [0u8; 512];
        data[..5].copy_from_slice(b"hello");
        out.extend_from_slice(&data);
        if complete {
            out.extend_from_slice(&[0u8; 1024]);
        }
        String::from_utf8(out).unwrap()
    }

    fn docker_fake(tar_text: String, existing: Option<&str>) -> FakeRunner {
        let mut f = FakeRunner::new();
        if let Some(name) = existing {
            f = f.on(&["docker", "volume", "inspect", name], ok("[{}]"));
        }
        f.on(&["docker", "volume", "inspect"], no_such_volume())
            .on(&["docker", "image", "ls"], ok("sha256:img1\nsha256:img2\n"))
            .on(&["docker", "create"], ok("cid123\n"))
            .on(&["docker", "cp", "cid123:/v", "-"], ok(&tar_text))
            .on(&["docker", "cp", "-"], ok(""))
            .on(&["docker", "rm"], ok("cid123\n"))
            .on(&["docker", "volume", "create"], ok("x\n"))
    }

    fn docker_calls(f: &FakeRunner) -> Vec<String> {
        f.calls()
            .into_iter()
            .filter(|c| c.first().is_some_and(|p| p == "docker"))
            .map(|c| c.join(" "))
            .collect()
    }

    #[test]
    fn docker_volume_backup_and_restore_with_fake_runner() {
        let e = Env::new();
        let f = docker_fake(tar(true), None);
        let ctx = e.ctx_with(&f, SystemTime::now());
        let l = e.lock();
        let ent = backup_volume(&ctx, &l, "data", 1000, 30).unwrap();
        assert_eq!(
            ent.kind,
            EntryKind::DockerVolume {
                name: "data".into()
            }
        );
        assert_eq!(ent.state, EntryState::Held);
        assert_eq!(ent.expires_at, Some(ent.moved_at + 30 * DAY));
        let tar_path = ent.vault_dir.join(&ent.id).join(PAYLOAD).join("volume.tar");
        assert_eq!(fs::read_to_string(&tar_path).unwrap(), tar(true));
        assert_eq!(
            docker_calls(&f),
            vec![
                "docker image ls -q --no-trunc",
                "docker create -v data:/v sha256:img1 devaudit-noop",
                "docker cp cid123:/v -",
                "docker rm cid123",
            ]
        );

        let to = restore(&ctx, &l, &ent.id).unwrap();
        assert_eq!(to, PathBuf::from("data"));
        assert_eq!(
            docker_calls(&f)[4..],
            [
                "docker volume inspect data",
                "docker image ls -q --no-trunc",
                "docker volume create data",
                "docker create -v data:/v sha256:img1 devaudit-noop",
                "docker cp - cid123:/",
                "docker rm cid123",
            ]
        );
        assert!(!ent.vault_dir.join(&ent.id).exists());

        // A volume with that name exists again: never written into.
        let e2 = Env::new();
        let f2 = docker_fake(tar(true), Some("data"));
        let ctx2 = e2.ctx_with(&f2, SystemTime::now());
        let l2 = e2.lock();
        let ent2 = backup_volume(&ctx2, &l2, "data", 1000, 30).unwrap();
        let to2 = restore(&ctx2, &l2, &ent2.id).unwrap();
        let day = &stamp(now_secs(&ctx2))[..8];
        assert_eq!(to2, PathBuf::from(format!("data-restored-{day}")));
        let calls = docker_calls(&f2);
        assert!(calls.contains(&format!("docker volume create data-restored-{day}")));
        assert!(!calls.contains(&"docker volume create data".to_string()));
    }

    #[test]
    fn truncated_volume_backup_rejected() {
        for (text, bytes) in [(tar(false), 1000), (tar(true), 100_000)] {
            let e = Env::new();
            let f = docker_fake(text, None);
            let ctx = e.ctx_with(&f, SystemTime::now());
            let l = e.lock();
            assert!(backup_volume(&ctx, &l, "data", bytes, 30).is_err());
            assert!(entries_in(&e.vault()).is_empty());
            assert!(list(&ctx).is_empty());
            assert_eq!(docker_calls(&f).last().unwrap(), "docker rm cid123");
        }
        // docker cp fails: the container is still removed, nothing is left.
        let e = Env::new();
        let f = FakeRunner::new()
            .on(&["docker", "image", "ls"], ok("sha256:img1\n"))
            .on(&["docker", "create"], ok("cid123\n"))
            .on(&["docker", "rm"], ok(""));
        let ctx = e.ctx_with(&f, SystemTime::now());
        let l = e.lock();
        assert!(backup_volume(&ctx, &l, "data", 1000, 30).is_err());
        assert!(entries_in(&e.vault()).is_empty());
        assert_eq!(docker_calls(&f).last().unwrap(), "docker rm cid123");
    }

    #[test]
    fn docker_stopped_record_and_start_again() {
        let e = Env::new();
        let f = FakeRunner::new().on(&["docker", "start"], ok(""));
        let ctx = e.ctx_with(&f, SystemTime::now());
        let l = e.lock();
        let kind = EntryKind::DockerStopped {
            ids: vec!["c1".into(), "c2".into()],
        };
        assert!(record(&ctx, &l, EntryKind::Path, "x").is_err());
        let ent = record(&ctx, &l, kind, "Stopped shop stack").unwrap();
        assert_eq!(ent.expires_at, None);
        assert_eq!(ent.state, EntryState::Held);
        // Never expires.
        let later = e.ctx_with(&f, SystemTime::now() + Duration::from_secs(400 * DAY));
        assert_eq!(purge_expired(&later, &l).0, 0);
        assert_eq!(list(&ctx).len(), 1);
        restore(&ctx, &l, &ent.id).unwrap();
        assert_eq!(docker_calls(&f), vec!["docker start c1 c2"]);
        assert!(list(&ctx).is_empty());
    }

    #[test]
    fn mutating_fns_require_lock() {
        let e = Env::new();
        let ctx = e.ctx();
        let l: InstanceLock = e.lock();
        let (nm, _) = sample(&e);
        assert!(move_in(&ctx, &l, &nm, EntryKind::Path, "nm", Tier::Safe, 0).is_ok());
        // Retention 0: move_in itself never deletes.
        assert_eq!(list(&ctx)[0].state, EntryState::Held);
    }
}
