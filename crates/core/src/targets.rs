//! Caches and temp (rules targets), Claude transcripts and worktrees, WSL disk images, advice.

use crate::guard::{self, Guard, GuardError};
use crate::model::{Category, Finding, MemInfo, Method, Os, Skipped, Tier, finding_id};
use crate::never::{self, SECRET_WALK_LIMIT, name_is_secret};
use crate::rules::{self, Target, TargetMethod};
use crate::{Ctx, disk, platform, procs, projects};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

const T: Duration = Duration::from_secs(30);
const DAY: u64 = 86_400;
const MAX_DEPTH: usize = 6;

fn days_between(now: SystemTime, then: SystemTime) -> u32 {
    let secs = now.duration_since(then).unwrap_or_default().as_secs();
    u32::try_from(secs / DAY).unwrap_or(u32::MAX)
}

fn raise(t: Tier) -> Tier {
    match t {
        Tier::Safe => Tier::Review,
        _ => Tier::Protected,
    }
}

/// `npm config get cache`, accepted only if it is an absolute path under home (or
/// LocalAppData) that is not forbidden. None means "use the default".
pub fn npm_cache_dir(ctx: &Ctx) -> Option<PathBuf> {
    let o = ctx.run.run(&["npm", "config", "get", "cache"], T).ok()?;
    if o.status != 0 {
        return None;
    }
    let p = PathBuf::from(o.stdout.trim());
    if !p.is_absolute() || p.components().any(|c| c.as_os_str() == "..") {
        return None;
    }
    let under = platform::inside(&p, &ctx.home)
        || ctx
            .dirs
            .local_app_data
            .as_deref()
            .is_some_and(|l| platform::inside(&p, l));
    if !under {
        return None;
    }
    let (roots, _) = projects::roots(ctx);
    let cfg = ctx.never_cfg(&roots);
    // The cache folder itself can be shallow (`~/.npm`); what is vaulted is what is below it.
    let ok = ["_cacache", "_npx"]
        .iter()
        .map(|c| p.join(c))
        .filter(|c| fs::symlink_metadata(c).is_ok())
        .all(|c| never::forbidden(&c, &cfg).is_none());
    ok.then_some(p)
}

/// Regular files below `base` older than `days`: never through links, never a secret-named
/// component below `base`, never a forbidden path.
pub struct Prune {
    pub files: Vec<PathBuf>,
    /// Sum of the collected files only.
    pub bytes: u64,
}

pub fn prune_candidates(ctx: &Ctx, base: &Path, days: u32) -> Prune {
    let (roots, _) = projects::roots(ctx);
    let cfg = ctx.never_cfg(&roots);
    let mut out = Prune {
        files: vec![],
        bytes: 0,
    };
    let Some(cutoff) = ctx
        .now
        .checked_sub(Duration::from_secs(u64::from(days) * DAY))
    else {
        return out;
    };
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if name_is_secret(&e.file_name()) {
                continue;
            }
            let Ok(md) = fs::symlink_metadata(&p) else {
                continue;
            };
            if platform::is_link(&md) || platform::is_cloud_placeholder(&md) {
                continue;
            }
            if md.is_dir() {
                if never::forbidden(&p, &cfg).is_none() {
                    stack.push(p);
                }
            } else if md.is_file()
                && md.modified().is_ok_and(|m| m < cutoff)
                && never::forbidden(&p, &cfg).is_none()
            {
                out.bytes += platform::size_on_disk(&md);
                out.files.push(p);
            }
        }
    }
    out.files.sort();
    out
}

fn finding_for(category: Category, key: &Path, title: String, path: Option<PathBuf>) -> Finding {
    let id_key = platform::canon(key).unwrap_or_else(|_| key.to_path_buf());
    Finding {
        id: finding_id(category, &id_key.to_string_lossy()),
        category,
        title,
        path,
        project: None,
        owner_processes: vec![],
        bytes: 0,
        bytes_estimate: false,
        idle_days: None,
        tier: Tier::Protected,
        reason: String::new(),
        rebuild: None,
        method: Method::None,
    }
}

pub fn target_findings(ctx: &Ctx, cancel: &AtomicBool) -> (Vec<Finding>, Vec<Skipped>) {
    let npm = npm_cache_dir(ctx);
    let (roots, _) = projects::roots(ctx);
    let cfg = ctx.never_cfg(&roots);
    let mut out = vec![];
    let mut skipped = vec![];
    for t in rules::for_os(ctx.rules, ctx.os) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Some(path) = rules::expand(&t.path, &ctx.dirs, npm.as_deref()) else {
            continue;
        };
        if fs::symlink_metadata(&path).is_err() {
            continue;
        }
        let mut f = finding_for(t.category, &path, t.title.clone(), Some(path.clone()));
        f.owner_processes = t.owner_processes.clone();
        f.rebuild = Some(t.rebuild.clone()).filter(|r| !r.is_empty());
        if let TargetMethod::PruneOlderThan(days) = t.method {
            let r = prune_candidates(ctx, &path, days);
            f.bytes = r.bytes;
            (f.tier, f.reason, f.method) = match never::forbidden(&path, &cfg) {
                Some(why) => (Tier::Protected, why, Method::None),
                None => (
                    Tier::Safe,
                    format!("Only files older than {days} days; files in use are skipped"),
                    Method::PruneOlderThan { path, days },
                ),
            };
            out.push(f);
            continue;
        }
        let u = disk::usage(&path, &[], cancel);
        skipped.extend(u.skipped);
        f.bytes = u.bytes;
        f.idle_days = u.newest_mtime.map(|m| days_between(ctx.now, m));
        (f.tier, f.reason, f.method) = match vet_target(ctx, t, &path, f.idle_days, &cfg) {
            Ok(v) => v,
            Err(why) => (Tier::Protected, why, Method::None),
        };
        out.push(f);
    }
    (out, skipped)
}

/// Err is the reason the target is Protected.
fn vet_target(
    ctx: &Ctx,
    t: &Target,
    path: &Path,
    idle: Option<u32>,
    cfg: &never::NeverCfg,
) -> Result<(Tier, String, Method), String> {
    if let Some(why) = never::forbidden(path, cfg) {
        return Err(why);
    }
    let mut tier = t.tier;
    let mut reason = "Rebuilt automatically when needed".to_string();
    if idle.is_some_and(|d| d < t.min_idle_days) {
        tier = raise(tier);
        reason = format!("Used within the last {} days", t.min_idle_days);
    }
    if t.method == TargetMethod::Report {
        return Ok((tier, "Shown for information only".into(), Method::None));
    }
    if t.method == TargetMethod::Vault && t.tier == Tier::Review {
        match never::find_secret_inside(path, SECRET_WALK_LIMIT) {
            Ok(None) => {}
            Ok(Some(hit)) => return Err(format!("Contains {}", hit.display())),
            Err(e) => return Err(format!("Can't check for secrets: {e}")),
        }
    }
    if tier == Tier::Protected {
        return Err(reason);
    }
    let r = &ctx.rules.retention;
    let keep_days = if tier == Tier::Safe {
        r.safe_days
    } else {
        r.review_days
    };
    let method = match &t.method {
        TargetMethod::Command(argv) => Method::Command { argv: argv.clone() },
        _ => Method::Vault {
            path: path.to_path_buf(),
            id: platform::file_id(path).map_err(|e| format!("Can't identify folder: {e}"))?,
            keep_days,
        },
    };
    Ok((tier, reason, method))
}

/// Claude's folder name for a cwd: separators and `.` become `-`. `strict` also maps every
/// other non-alphanumeric character, which newer Claude versions do; matching either way
/// errs towards Protected.
fn encode_cwd(cwd: &Path, strict: bool) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|c| {
            let hit = if strict {
                !c.is_alphanumeric()
            } else {
                matches!(c, '/' | '\\' | '.')
            };
            if hit { '-' } else { c }
        })
        .collect()
}

fn newest_age(ctx: &Ctx, path: &Path) -> (disk::Usage, Option<u32>) {
    let u = disk::usage(path, &[], &AtomicBool::new(false));
    let idle = u.newest_mtime.map(|m| days_between(ctx.now, m));
    (u, idle)
}

pub fn claude_findings(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    roots: &[PathBuf],
) -> Vec<Finding> {
    let mut out = transcript_findings(ctx, guard);
    out.extend(worktree_findings(ctx, guard, roots));
    out
}

fn transcript_findings(ctx: &Ctx, guard: Result<&Guard, &GuardError>) -> Vec<Finding> {
    let base = ctx.home.join(".claude").join("projects");
    let Ok(rd) = fs::read_dir(&base) else {
        return vec![];
    };
    let (roots, _) = projects::roots(ctx);
    let cfg = ctx.never_cfg(&roots);
    let mut dirs: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter(|e| {
            fs::symlink_metadata(e.path()).is_ok_and(|m| m.is_dir() && !platform::is_link(&m))
        })
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    dirs.sort();
    let mut out = vec![];
    for (name, path) in dirs {
        let (u, idle) = newest_age(ctx, &path);
        let verdict: Result<(), String> = (|| {
            if let Some(why) = never::forbidden(&path, &cfg) {
                return Err(why);
            }
            let g = guard.map_err(|_| "Can't check running programs".to_string())?;
            if idle.is_none_or(|d| d < ctx.rules.recent_days) {
                return Err("Used in the last few days".into());
            }
            let live = g.procs.iter().any(|p| {
                procs::is_claude(p)
                    && p.cwd.as_ref().is_some_and(|c| {
                        name.eq_ignore_ascii_case(&encode_cwd(c, false))
                            || name.eq_ignore_ascii_case(&encode_cwd(c, true))
                    })
            });
            if live {
                return Err("A Claude session is open in this project".into());
            }
            Ok(())
        })();
        let mut f = finding_for(
            Category::AiTool,
            &path,
            format!("Claude conversations: {name}"),
            Some(path.clone()),
        );
        f.bytes = u.bytes;
        f.idle_days = idle;
        (f.tier, f.reason, f.method) = match verdict.and_then(|()| {
            platform::file_id(&path).map_err(|e| format!("Can't identify folder: {e}"))
        }) {
            Ok(id) => (
                Tier::Review,
                "Old conversation history; it can't be recreated, so it is kept in Recovery".into(),
                Method::Vault {
                    path: path.clone(),
                    id,
                    keep_days: ctx.rules.retention.review_days,
                },
            ),
            Err(why) => (Tier::Protected, why, Method::None),
        };
        out.push(f);
    }
    out
}

/// Git repos (a `.git` directory) under the roots. Never follows links or enters build dirs.
fn find_repos(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(md) = fs::symlink_metadata(e.path()) else {
                continue;
            };
            if !md.is_dir() || platform::is_link(&md) {
                continue;
            }
            if name == ".git" {
                out.push(dir.clone());
            } else if depth < MAX_DEPTH
                && name != ".claude"
                && !name.eq_ignore_ascii_case(".devaudit-vault")
                && !never::BUILD_DIR_NAMES
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(&name))
            {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    out.sort();
    out
}

/// (path, branch) from `git worktree list --porcelain`; branch None when detached.
fn parse_worktrees(s: &str) -> Vec<(PathBuf, Option<String>)> {
    let mut out: Vec<(PathBuf, Option<String>)> = vec![];
    for line in s.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            out.push((PathBuf::from(p), None));
        } else if let Some(b) = line.strip_prefix("branch ")
            && let Some(last) = out.last_mut()
        {
            last.1 = Some(b.strip_prefix("refs/heads/").unwrap_or(b).to_string());
        }
    }
    out
}

/// A worktree's own top-level `.git` link file is expected; anything else secret-named is not.
fn secret_in_worktree(wt: &Path) -> Result<Option<PathBuf>, String> {
    let rd = fs::read_dir(wt).map_err(|e| format!("cannot read {}: {e}", wt.display()))?;
    for e in rd {
        let e = e.map_err(|e| format!("cannot read {}: {e}", wt.display()))?;
        if e.file_name() == ".git" {
            continue;
        }
        if name_is_secret(&e.file_name()) {
            return Ok(Some(e.path()));
        }
        let md = fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        if md.is_dir()
            && !platform::is_link(&md)
            && let Some(hit) = never::find_secret_inside(&e.path(), SECRET_WALK_LIMIT)?
        {
            return Ok(Some(hit));
        }
    }
    Ok(None)
}

fn worktree_findings(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    roots: &[PathBuf],
) -> Vec<Finding> {
    let cfg = ctx.never_cfg(roots);
    let mut out = vec![];
    for repo in find_repos(roots) {
        let base = repo.join(".claude").join("worktrees");
        if !base.is_dir() {
            continue;
        }
        let Ok(o) = guard::git(ctx.run, &repo, &["worktree", "list", "--porcelain"]) else {
            continue;
        };
        if o.status != 0 {
            continue;
        }
        for (wt, branch) in parse_worktrees(&o.stdout) {
            if platform::eq_ci(&wt, &base) || !platform::inside(&wt, &base) {
                continue;
            }
            out.push(worktree_finding(ctx, guard, &cfg, &repo, wt, branch));
        }
    }
    out
}

fn worktree_finding(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    cfg: &never::NeverCfg,
    repo: &Path,
    wt: PathBuf,
    branch: Option<String>,
) -> Finding {
    let (u, idle) = newest_age(ctx, &wt);
    let verdict: Result<(String, crate::model::FileId), String> = (|| {
        if let Some(why) = never::forbidden(&wt, cfg) {
            return Err(why);
        }
        let g = guard.map_err(|_| "Can't check running programs".to_string())?;
        let a = g.check(&wt, ctx.run);
        if a.locked {
            return Err(a.reasons.join("; "));
        }
        let branch =
            branch.ok_or_else(|| "Detached HEAD: work may not be on any branch".to_string())?;
        match secret_in_worktree(&wt) {
            Ok(None) => {}
            Ok(Some(hit)) => return Err(format!("Contains {}", hit.display())),
            Err(e) => return Err(format!("Can't check for secrets: {e}")),
        }
        let id = platform::file_id(&wt).map_err(|e| format!("Can't identify folder: {e}"))?;
        Ok((branch, id))
    })();
    let name = wt
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let mut f = finding_for(
        Category::AiTool,
        &wt,
        format!("Claude worktree: {name}"),
        Some(wt.clone()),
    );
    f.project = Some(wt.clone());
    f.bytes = u.bytes;
    f.idle_days = idle;
    (f.tier, f.reason, f.method) = match verdict {
        Ok((branch, id)) => (
            Tier::Review,
            format!(
                "Clean worktree on branch {branch}; moved whole to Recovery, never git-removed"
            ),
            Method::WorktreeVault {
                repo: repo.to_path_buf(),
                worktree: wt,
                id,
                branch,
                keep_days: ctx.rules.retention.review_days,
            },
        ),
        Err(why) => (Tier::Protected, why, Method::None),
    };
    f
}

/// `wsl.exe -l -v` prints UTF-16LE (usually with a BOM). Unparseable input gives nothing.
pub fn parse_wsl_list(b: &[u8]) -> Vec<(String, String, u8)> {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let mut out = vec![];
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim().trim_start_matches('*').trim();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let Ok(version) = parts[parts.len() - 1].parse::<u8>() else {
            continue;
        };
        out.push((
            parts[..parts.len() - 2].join(" "),
            parts[parts.len() - 2].to_string(),
            version,
        ));
    }
    out
}

fn squash(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

/// The distro's `ext4.vhdx`: a Store package whose name contains the distro name, or Docker's.
fn find_vhdx(ctx: &Ctx, distro: &str) -> Option<PathBuf> {
    let local = ctx.dirs.local_app_data.as_deref()?;
    let want = squash(distro);
    if want.starts_with("dockerdesktop") {
        let wsl = local.join("Docker").join("wsl");
        return ["main", "data", "distro", "disk"]
            .iter()
            .filter_map(|d| fs::read_dir(wsl.join(d)).ok())
            .flatten()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("vhdx"))
            });
    }
    fs::read_dir(local.join("Packages"))
        .ok()?
        .flatten()
        .filter(|e| squash(&e.file_name().to_string_lossy()).contains(&want))
        .map(|e| e.path().join("LocalState").join("ext4.vhdx"))
        .find(|p| fs::symlink_metadata(p).is_ok_and(|m| m.is_file() && !platform::is_link(&m)))
}

fn advice(key: &str, title: String, bytes: u64, reason: String) -> Finding {
    Finding {
        id: finding_id(Category::Advice, key),
        category: Category::Advice,
        title,
        path: None,
        project: None,
        owner_processes: vec![],
        bytes,
        bytes_estimate: false,
        idle_days: None,
        tier: Tier::Review,
        reason,
        rebuild: None,
        method: Method::None,
    }
}

pub fn wsl_findings(ctx: &Ctx) -> Vec<Finding> {
    if ctx.os != Os::Windows {
        return vec![];
    }
    // The runner returns text; UTF-16 has to be read as bytes, so go through a file.
    let tmp = ctx.dirs.temp.join(format!("devaudit-wsl-{}.tmp", ctx.pid));
    let _ = fs::remove_file(&tmp);
    let bytes = ctx
        .run
        .run_to_file(&["wsl.exe", "-l", "-v"], T, &tmp)
        .ok()
        .and_then(|()| fs::read(&tmp).ok());
    let _ = fs::remove_file(&tmp);
    let distros = bytes.map(|b| parse_wsl_list(&b)).unwrap_or_default();
    let mut out = vec![];
    for (name, state, version) in distros {
        let Some(vhdx) = find_vhdx(ctx, &name) else {
            continue;
        };
        let mut f = finding_for(
            Category::Advice,
            &vhdx,
            format!("WSL {name} disk image"),
            Some(vhdx.clone()),
        );
        f.bytes = fs::symlink_metadata(&vhdx).map_or(0, |m| platform::size_on_disk(&m));
        f.tier = Tier::Review;
        f.reason = format!("{state}, WSL {version}. DevAudit only reports its size");
        out.push(f);
    }
    if !out.is_empty() {
        out.push(advice(
            "wsl-compact",
            "WSL disk images don't shrink by themselves".into(),
            0,
            "Deleting files inside WSL does not return space to Windows. See Settings › Help"
                .into(),
        ));
    }
    out
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeSettings {
    cleanup_period_days: Option<serde_json::Number>,
}

#[derive(Deserialize, Default)]
struct McpServer {
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct McpServers {
    #[serde(default)]
    mcp_servers: BTreeMap<String, McpServer>,
}

#[derive(Deserialize, Default)]
struct McpConfig {
    #[serde(flatten)]
    top: McpServers,
    #[serde(default)]
    projects: BTreeMap<String, McpServers>,
}

/// Count of `pkg@latest` arguments over all servers in the MCP config at `path`.
/// Only `args` is deserialized; every other key is skipped by serde.
fn latest_specs(path: &Path, into: &mut BTreeMap<String, u32>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let Ok(cfg) = serde_json::from_str::<McpConfig>(&text) else {
        return;
    };
    let servers = cfg.top.mcp_servers.into_values().chain(
        cfg.projects
            .into_values()
            .flat_map(|p| p.mcp_servers.into_values()),
    );
    for s in servers {
        for a in s
            .args
            .iter()
            .filter(|a| !a.starts_with('-') && a.ends_with("@latest"))
        {
            *into.entry(a.clone()).or_default() += 1;
        }
    }
}

pub fn advice_findings(ctx: &Ctx, _mem: &MemInfo) -> Vec<Finding> {
    let mut out = vec![];
    let claude = ctx.home.join(".claude");
    if claude.is_dir() {
        let settings = fs::read_to_string(claude.join("settings.json"));
        let missing = match settings {
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            Ok(t) => serde_json::from_str::<ClaudeSettings>(&t)
                .is_ok_and(|s| s.cleanup_period_days.is_none()),
        };
        if missing {
            out.push(advice(
                "claude-cleanup-period",
                "Claude Code cleanupPeriodDays is not set".into(),
                0,
                "Without it Claude keeps old conversation history for a default period. Set cleanupPeriodDays in Claude's settings to the number of days you want to keep.".into(),
            ));
        }
    }
    let mut specs = BTreeMap::new();
    latest_specs(&ctx.home.join(".claude.json"), &mut specs);
    let (roots, _) = projects::roots(ctx);
    for r in &roots {
        latest_specs(&r.join(".mcp.json"), &mut specs);
    }
    for (spec, n) in specs.into_iter().filter(|(_, n)| *n >= 2) {
        out.push(advice(
            &format!("mcp-latest:{spec}"),
            format!("{spec} is set up {n} times"),
            0,
            "@latest makes npx fetch fresh copies, which fill the npm cache. Pin a version in the MCP settings.".into(),
        ));
    }
    match ctx.os {
        Os::Windows => {
            let low = platform::volume_space(&ctx.home).is_ok_and(|(total, free)| {
                total > 0 && u128::from(free) * 100 < u128::from(total) * u128::from(ctx.rules.thresholds.free_pct)
            });
            if low {
                out.push(advice(
                    "windows-os-managed",
                    "Windows Update cleanup and hibernation file".into(),
                    0,
                    "Settings › System › Storage › Cleanup recommendations".into(),
                ));
            }
        }
        Os::Macos => out.push(advice(
            "macos-system-data",
            "About System Data".into(),
            0,
            "macOS counts caches, snapshots and logs as System Data. DevAudit can't clear it; see System Settings › General › Storage.".into(),
        )),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::tests::{elsewhere, old, p, real, sh, snap};
    use crate::model::{Category, Method, Os, Pressure, Tier};
    use crate::platform::KnownDirs;
    use crate::rules::{self, Rules};
    use crate::run::{FakeRunner, Output, SystemRunner};
    use std::fs::{self, File};
    use std::time::{Duration, SystemTime};

    struct Env {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        rules: Rules,
        run: SystemRunner,
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
            };
            Env {
                _tmp: tmp,
                root,
                rules,
                run: real(),
                dirs,
            }
        }
        fn ctx_with<'a>(&'a self, os: Os, run: &'a dyn crate::run::Runner) -> Ctx<'a> {
            Ctx::new(
                os,
                self.dirs.clone(),
                self.dirs.home.join(".devaudit"),
                run,
                &self.rules,
                SystemTime::now(),
                1,
            )
        }
        fn ctx(&self) -> Ctx<'_> {
            self.ctx_with(Os::current(), &self.run)
        }
        /// Directory of the built-in target `id`, created with one old file.
        fn target(&self, id: &str, file: &str) -> PathBuf {
            let t = self.rules.targets.iter().find(|t| t.id == id).unwrap();
            let d = rules::expand(&t.path, &self.dirs, None).unwrap();
            fs::create_dir_all(&d).unwrap();
            write_old(&d.join(file), "1234", 30);
            d
        }
        fn chrome_id(&self) -> &'static str {
            if Os::current() == Os::Macos {
                "chrome-cache-macos"
            } else {
                "chrome-cache-windows"
            }
        }
    }

    fn write_old(path: &Path, s: &str, days: u64) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, s).unwrap();
        let t = SystemTime::now() - Duration::from_secs(days * 86_400);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    fn ok(s: &str) -> Result<Output, crate::run::RunError> {
        Ok(Output {
            status: 0,
            stdout: s.into(),
            stderr: String::new(),
        })
    }

    fn quiet_guard() -> Guard {
        Guard::build(
            &snap(vec![p(1, "zsh", Some(&elsewhere()), &[])]),
            &FakeRunner::new(),
            14,
            SystemTime::now(),
        )
        .unwrap()
    }

    fn mem() -> MemInfo {
        MemInfo {
            total: 0,
            available: 0,
            swap_used: 0,
            swap_total: 0,
            pressure: Pressure::Normal,
            groups: vec![],
        }
    }

    #[test]
    fn npm_cache_from_config_is_validated() {
        let e = Env::new();
        let alt = e.dirs.home.join(".npm-alt");
        fs::create_dir_all(&alt).unwrap();
        let bad = FakeRunner::new().on(&["npm", "config", "get", "cache"], ok("/etc\n"));
        assert_eq!(npm_cache_dir(&e.ctx_with(Os::current(), &bad)), None);
        let good = FakeRunner::new().on(
            &["npm", "config", "get", "cache"],
            ok(&format!("{}\n", alt.display())),
        );
        assert_eq!(npm_cache_dir(&e.ctx_with(Os::current(), &good)), Some(alt));
        // A configured location in never-touch territory is refused once it holds a cache.
        let ssh = e.dirs.home.join(".ssh/npm");
        fs::create_dir_all(ssh.join("_cacache")).unwrap();
        let sneaky = FakeRunner::new().on(
            &["npm", "config", "get", "cache"],
            ok(&format!("{}\n", ssh.display())),
        );
        assert_eq!(npm_cache_dir(&e.ctx_with(Os::current(), &sneaky)), None);
        let none = FakeRunner::new();
        assert_eq!(npm_cache_dir(&e.ctx_with(Os::current(), &none)), None);
    }

    #[test]
    fn missing_targets_produce_nothing() {
        let e = Env::new();
        let (f, s) = target_findings(&e.ctx(), &AtomicBool::new(false));
        assert!(f.is_empty() && s.is_empty(), "{f:?}");
    }

    #[test]
    fn review_vault_target_with_secret_inside_protected() {
        let e = Env::new();
        let d = e.target(e.chrome_id(), "f");
        write_old(&d.join("sub/Login Data"), "x", 30);
        let (f, _) = target_findings(&e.ctx(), &AtomicBool::new(false));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tier, Tier::Protected, "{:?}", f[0]);
        assert_eq!(f[0].method, Method::None);
        assert!(f[0].reason.contains("Login Data"), "{}", f[0].reason);
        assert!(!f[0].owner_processes.is_empty());
    }

    #[test]
    fn browser_cache_target_never_includes_profile_secrets() {
        let e = Env::new();
        let d = e.target(e.chrome_id(), "f");
        // The profile's secret sits beside the cache, not inside it.
        write_old(&d.parent().unwrap().join("Login Data"), "x", 30);
        let (f, _) = target_findings(&e.ctx(), &AtomicBool::new(false));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tier, Tier::Review, "{:?}", f[0]);
        assert_eq!(f[0].path.as_deref(), Some(d.as_path()));
        assert!(matches!(&f[0].method, Method::Vault { path, .. } if *path == d));
        assert!(f[0].owner_processes.iter().any(|n| n == "chrome"));
    }

    #[test]
    fn recently_used_cache_is_raised_one_tier() {
        let e = Env::new();
        let d = e.target(e.chrome_id(), "f");
        write_old(&d.join("fresh"), "x", 0);
        let (f, _) = target_findings(&e.ctx(), &AtomicBool::new(false));
        assert_eq!(f[0].tier, Tier::Protected, "{:?}", f[0]);
        assert_eq!(f[0].method, Method::None);
    }

    #[test]
    fn safe_vault_and_command_targets() {
        let e = Env::new();
        let (vault, cmd) = if Os::current() == Os::Macos {
            ("playwright-macos", "pnpm-prune-macos")
        } else {
            ("playwright-windows", "pnpm-prune-windows")
        };
        e.target(vault, "f");
        e.target(cmd, "f");
        let (f, _) = target_findings(&e.ctx(), &AtomicBool::new(false));
        assert_eq!(f.len(), 2);
        let v = f.iter().find(|x| x.title.contains("Playwright")).unwrap();
        assert_eq!(v.tier, Tier::Safe);
        assert!(matches!(
            &v.method,
            Method::Vault { keep_days, .. } if *keep_days == e.rules.retention.safe_days
        ));
        let c = f.iter().find(|x| x.id != v.id).unwrap();
        assert!(
            matches!(&c.method, Method::Command { argv } if argv[0] == "pnpm"),
            "{c:?}"
        );
    }

    #[test]
    fn temp_prune_counts_only_old_files() {
        let e = Env::new();
        write_old(&e.dirs.temp.join("old.bin"), "0123456789", 10);
        write_old(&e.dirs.temp.join("new.bin"), "0123456789", 0);
        let ctx = e.ctx_with(Os::Windows, &e.run);
        let r = prune_candidates(&ctx, &e.dirs.temp, 7);
        assert_eq!(r.files, vec![e.dirs.temp.join("old.bin")]);
        let md = fs::symlink_metadata(e.dirs.temp.join("old.bin")).unwrap();
        assert_eq!(r.bytes, platform::size_on_disk(&md));
        let (f, _) = target_findings(&ctx, &AtomicBool::new(false));
        let t = f.iter().find(|x| x.category == Category::Temp).unwrap();
        assert_eq!(t.bytes, r.bytes);
        assert_eq!(t.tier, Tier::Safe);
        assert!(matches!(&t.method, Method::PruneOlderThan { days: 7, .. }));
    }

    #[test]
    fn temp_prune_skips_secret_names() {
        let e = Env::new();
        let t = &e.dirs.temp;
        write_old(&t.join("cert.pfx"), "x", 10);
        write_old(&t.join("x/token"), "x", 10);
        write_old(&t.join("a.txt"), "x", 10);
        let r = prune_candidates(&e.ctx(), t, 7);
        assert_eq!(r.files, vec![t.join("a.txt")]);
    }

    #[cfg(unix)]
    #[test]
    fn temp_prune_never_descends_links() {
        let e = Env::new();
        let t = &e.dirs.temp;
        let outside = e.dirs.home.join("outside");
        write_old(&outside.join("keep.txt"), "x", 10);
        fs::create_dir_all(t).unwrap();
        std::os::unix::fs::symlink(&outside, t.join("link")).unwrap();
        let r = prune_candidates(&e.ctx(), t, 7);
        assert!(r.files.is_empty(), "{:?}", r.files);
    }

    /// A repo under the project root with `.claude/worktrees/<name>`; files old, tree clean.
    fn repo_with_worktree(e: &Env, name: &str) -> (PathBuf, PathBuf) {
        let repo = e.root.join("proj");
        fs::create_dir_all(&repo).unwrap();
        write_old(&repo.join("a.txt"), "x", 400);
        sh(&repo, &["init", "-q"]);
        sh(&repo, &["add", "."]);
        sh(&repo, &["commit", "-q", "-m", "m"]);
        let wt = repo.join(".claude/worktrees").join(name);
        fs::create_dir_all(wt.parent().unwrap()).unwrap();
        sh(
            &repo,
            &["worktree", "add", "-q", wt.to_str().unwrap(), "-b", name],
        );
        age_all(&wt);
        (repo, wt)
    }

    fn age_all(dir: &Path) {
        for ent in fs::read_dir(dir).unwrap().flatten() {
            let p = ent.path();
            if ent.file_type().unwrap().is_dir() {
                if ent.file_name() != ".git" {
                    age_all(&p);
                }
            } else {
                old(&p);
            }
        }
    }

    fn worktrees(e: &Env) -> Vec<Finding> {
        let g = quiet_guard();
        claude_findings(&e.ctx(), Ok(&g), std::slice::from_ref(&e.root))
            .into_iter()
            .filter(|f| f.project.is_some())
            .collect()
    }

    #[test]
    fn worktree_with_env_file_protected() {
        let e = Env::new();
        let (_, wt) = repo_with_worktree(&e, "feat");
        // Ignored files are not "dirty", so only the secret check can catch this.
        write_old(&wt.join(".env"), "SECRET=1", 400);
        fs::write(e.root.join("proj/.git/info/exclude"), ".env\n.claude/\n").unwrap();
        let f = worktrees(&e);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].tier, Tier::Protected, "{:?}", f[0]);
        assert_eq!(f[0].method, Method::None);
        assert!(f[0].reason.contains(".env"), "{}", f[0].reason);
    }

    #[test]
    fn dirty_claude_worktree_protected_clean_one_review() {
        let e = Env::new();
        let (repo, clean) = repo_with_worktree(&e, "clean");
        let dirty = repo.join(".claude/worktrees/dirty");
        sh(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                dirty.to_str().unwrap(),
                "-b",
                "dirty",
            ],
        );
        age_all(&dirty);
        fs::write(dirty.join("new.txt"), "uncommitted").unwrap();
        // A worktree outside .claude/worktrees is not ours to list.
        let other = e.root.join("elsewhere-wt");
        sh(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                other.to_str().unwrap(),
                "-b",
                "other",
            ],
        );
        let f = worktrees(&e);
        assert_eq!(f.len(), 2, "{f:?}");
        let by = |p: &Path| f.iter().find(|x| x.project.as_deref() == Some(p)).unwrap();
        let c = by(&clean);
        assert_eq!(c.tier, Tier::Review, "{c:?}");
        assert!(matches!(
            &c.method,
            Method::WorktreeVault { branch, keep_days, .. }
                if branch == "clean" && *keep_days == e.rules.retention.review_days
        ));
        assert_eq!(c.category, Category::AiTool);
        let d = by(&dirty);
        assert_eq!(d.tier, Tier::Protected);
        assert!(d.reason.contains("uncommitted"), "{}", d.reason);
    }

    #[test]
    fn detached_worktree_protected() {
        let e = Env::new();
        let (repo, _) = repo_with_worktree(&e, "feat");
        let det = repo.join(".claude/worktrees/det");
        sh(
            &repo,
            &["worktree", "add", "-q", "--detach", det.to_str().unwrap()],
        );
        age_all(&det);
        let f = worktrees(&e);
        let d = f
            .iter()
            .find(|x| x.project.as_deref() == Some(&*det))
            .unwrap();
        assert_eq!(d.tier, Tier::Protected);
        assert!(d.reason.contains("Detached"), "{}", d.reason);
    }

    fn transcript(e: &Env, name: &str, days: u64) -> PathBuf {
        let d = e.dirs.home.join(".claude/projects").join(name);
        write_old(&d.join("s.jsonl"), "{}", days);
        d
    }

    #[test]
    fn recent_transcript_dir_protected() {
        let e = Env::new();
        let recent = transcript(&e, "-Users-me-recent", 1);
        let oldd = transcript(&e, "-Users-me-old", 90);
        let g = quiet_guard();
        let f = claude_findings(&e.ctx(), Ok(&g), &[]);
        assert_eq!(f.len(), 2);
        let by = |p: &Path| f.iter().find(|x| x.path.as_deref() == Some(p)).unwrap();
        assert_eq!(by(&recent).tier, Tier::Protected);
        assert_eq!(by(&recent).method, Method::None);
        let o = by(&oldd);
        assert_eq!(o.tier, Tier::Review);
        assert_eq!(o.category, Category::AiTool);
        assert!(matches!(
            &o.method,
            Method::Vault { keep_days, .. } if *keep_days == e.rules.retention.review_days
        ));
    }

    #[test]
    fn transcript_of_running_claude_cwd_protected() {
        let e = Env::new();
        let cwd = e.root.join("my.app");
        let enc = cwd.to_string_lossy().replace(['/', '\\', '.', ':'], "-");
        let d = transcript(&e, &enc, 90);
        let other = transcript(&e, "-Users-me-other", 90);
        let g = Guard::build(
            &snap(vec![p(
                2,
                "claude",
                Some(cwd.to_str().unwrap()),
                &["claude"],
            )]),
            &FakeRunner::new(),
            14,
            SystemTime::now(),
        )
        .unwrap();
        let f = claude_findings(&e.ctx(), Ok(&g), &[]);
        let by = |p: &Path| f.iter().find(|x| x.path.as_deref() == Some(p)).unwrap();
        assert_eq!(by(&d).tier, Tier::Protected, "{:?}", by(&d));
        assert_eq!(by(&other).tier, Tier::Review);
        // Without process data every transcript fails closed.
        let f = claude_findings(&e.ctx(), Err(&GuardError::NoProcessData), &[]);
        assert!(f.iter().all(|x| x.tier == Tier::Protected));
    }

    #[test]
    fn parse_wsl_list_utf16() {
        let s = "  NAME            STATE           VERSION\r\n* Ubuntu          Running         2\r\n  docker-desktop  Stopped         2\r\n";
        let mut b = vec![0xFF, 0xFE];
        b.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(
            parse_wsl_list(&b),
            vec![
                ("Ubuntu".into(), "Running".into(), 2),
                ("docker-desktop".into(), "Stopped".into(), 2)
            ]
        );
        assert!(parse_wsl_list(b"garbage").is_empty());
    }

    #[test]
    fn wsl_is_windows_only() {
        let e = Env::new();
        assert!(wsl_findings(&e.ctx_with(Os::Macos, &e.run)).is_empty());
    }

    fn advice_titles(e: &Env, os: Os) -> Vec<String> {
        advice_findings(&e.ctx_with(os, &e.run), &mem())
            .into_iter()
            .map(|f| f.title)
            .collect()
    }

    #[test]
    fn cleanup_period_advice_only_when_missing() {
        let e = Env::new();
        let s = e.dirs.home.join(".claude/settings.json");
        fs::create_dir_all(s.parent().unwrap()).unwrap();
        let has = |e: &Env| {
            advice_titles(e, Os::Macos)
                .iter()
                .any(|t| t.contains("cleanupPeriodDays"))
        };
        assert!(has(&e));
        fs::write(&s, r#"{"cleanupPeriodDays": 30}"#).unwrap();
        assert!(!has(&e));
    }

    #[test]
    fn settings_read_does_not_leak_other_keys() {
        let e = Env::new();
        let dir = e.dirs.home.join(".claude");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_API_KEY":"sk-LEAK-1"},"apiKeyHelper":"sk-LEAK-2"}"#,
        )
        .unwrap();
        fs::write(
            e.dirs.home.join(".claude.json"),
            r#"{"oauthAccount":"sk-LEAK-3","mcpServers":{
                "a":{"command":"npx","args":["-y","pkg@latest"],"env":{"TOKEN":"sk-LEAK-4"}},
                "b":{"command":"npx","args":["-y","pkg@latest"]}}}"#,
        )
        .unwrap();
        let f = advice_findings(&e.ctx_with(Os::Macos, &e.run), &mem());
        let all = serde_json::to_string(&f).unwrap();
        assert!(!all.contains("LEAK"), "{all}");
        assert!(f.iter().any(|x| x.title.contains("pkg@latest")), "{all}");
        assert!(f.iter().any(|x| x.title.contains("cleanupPeriodDays")));
        assert!(
            f.iter()
                .all(|x| x.category == Category::Advice && x.method == Method::None)
        );
    }

    #[test]
    fn os_advice() {
        let e = Env::new();
        assert!(
            advice_titles(&e, Os::Macos)
                .iter()
                .any(|t| t.contains("System Data"))
        );
        assert!(
            !advice_titles(&e, Os::Windows)
                .iter()
                .any(|t| t.contains("System Data"))
        );
        platform::fake_free_space(&e.dirs.home, 1);
        assert!(
            advice_titles(&e, Os::Windows)
                .iter()
                .any(|t| t.contains("Windows Update"))
        );
    }
}
