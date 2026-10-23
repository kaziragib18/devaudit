//! Preview and re-validation. `validate` is the last gate before anything is moved, stopped or deleted.

use crate::guard::{self, Guard, GuardError, Repo};
use crate::model::{FileId, Finding, Method, Os, Report, Tier};
use crate::procs::{self, Proc};
use crate::rules::ALLOWED_PROGRAMS;
use crate::{Ctx, docker, never, platform, projects, recovery, report, targets};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One line of a preview: exactly what will run and whether it can be undone.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PlannedItem {
    pub id: String,
    pub title: String,
    /// The exact action, e.g. `Move to Recovery (kept 3 days): …/node_modules`.
    pub what_runs: String,
    /// "Recoverable for 3 days" or "Can't be undone — …".
    pub undo: String,
    /// Can't be undone: confirming needs the separate checkbox.
    pub permanent: bool,
    pub bytes: u64,
    /// Why it can't run now; the item is then skipped.
    pub blocked: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Plan {
    /// 32 hex characters; `execute` accepts only the plan it was issued for.
    pub token: String,
    pub report_scanned_at: u64,
    pub items: Vec<PlannedItem>,
    pub created: SystemTime,
}

const NOT_RECOVERABLE: &str = "Not recoverable — retention is set to 0 days";
const GUARD_DOWN: &str = "Can't check running programs";

fn days(n: u32) -> String {
    if n == 1 {
        "1 day".into()
    } else {
        format!("{n} days")
    }
}

/// Decimal units, one decimal: "1.2 GB".
fn human(b: u64) -> String {
    let (div, unit) = match b {
        1_000_000_000.. => (1e9, "GB"),
        1_000_000.. => (1e6, "MB"),
        1_000.. => (1e3, "KB"),
        _ => return format!("{b} B"),
    };
    format!("{:.1} {unit}", b as f64 / div)
}

fn token() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// (what_runs, undo, permanent) for a finding's method.
fn describe(ctx: &Ctx, f: &Finding) -> (String, String, bool) {
    let r = &ctx.rules.retention;
    // `keep` days in the vault; 0 means purged right away.
    let kept = |keep: u32| {
        if keep == 0 {
            (NOT_RECOVERABLE.to_string(), true)
        } else {
            (format!("Recoverable for {}", days(keep)), false)
        }
    };
    match &f.method {
        Method::Vault {
            path, keep_days, ..
        } => {
            let (undo, permanent) = kept(*keep_days);
            let when = match keep_days {
                0 => "purged right away".to_string(),
                n => format!("kept {}", days(*n)),
            };
            (
                format!("Move to Recovery ({when}): {}", path.display()),
                undo,
                permanent,
            )
        }
        Method::WorktreeVault {
            worktree,
            keep_days,
            branch,
            ..
        } => {
            let (undo, permanent) = kept(*keep_days);
            let when = match keep_days {
                0 => "purged right away".to_string(),
                n => format!("kept {}", days(*n)),
            };
            (
                format!(
                    "Move worktree (branch {branch}) to Recovery ({when}): {}",
                    worktree.display()
                ),
                undo,
                permanent,
            )
        }
        Method::PruneOlderThan { path, days: d } => {
            let (undo, permanent) = kept(r.safe_days);
            (
                format!(
                    "Move files older than {} in {} to Recovery (kept {})",
                    days(*d),
                    path.display(),
                    days(r.safe_days)
                ),
                undo,
                permanent,
            )
        }
        Method::Command { argv } => (
            format!("Run: {}", argv.join(" ")),
            "Can't be undone — re-downloads when needed".into(),
            true,
        ),
        Method::DockerVolumeBackupRm { name } => {
            let (undo, permanent) = if r.volume_backup_days == 0 {
                (NOT_RECOVERABLE.to_string(), true)
            } else {
                (
                    format!(
                        "Back up {}, then remove — recoverable for {}",
                        human(f.bytes),
                        days(r.volume_backup_days)
                    ),
                    false,
                )
            };
            (
                format!(
                    "Back up Docker volume {name} to Recovery, then run: docker volume rm {name}"
                ),
                undo,
                permanent,
            )
        }
        Method::DockerStop { container_ids } => (
            format!("Run: docker stop {}", container_ids.join(" ")),
            "Start again from History".into(),
            false,
        ),
        Method::Signal { pid, .. } => (
            match ctx.os {
                Os::Macos => format!("Ask {} to quit: send SIGTERM to pid {pid}", f.title),
                Os::Windows => format!("End process {pid} ({})", f.title),
            },
            "Can't be undone — the process ends".into(),
            true,
        ),
        Method::None => ("Nothing to run".into(), "Nothing changes".into(), false),
    }
}

/// Builds the plan for `ids` from a fresh process snapshot. Read-only: creates no vault.
pub fn preview(ctx: &Ctx, report: &Report, ids: &[String]) -> Plan {
    let guard = report::build_guard(ctx, &procs::snapshot());
    preview_with(ctx, report, ids, guard.as_ref())
}

/// `preview` with the guard supplied. Unknown and duplicate ids are blocked / dropped.
pub(crate) fn preview_with(
    ctx: &Ctx,
    report: &Report,
    ids: &[String],
    guard: Result<&Guard, &GuardError>,
) -> Plan {
    let token = token();
    let mut seen: Vec<&String> = vec![];
    let mut items = vec![];
    for id in ids {
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        let Some(f) = report.findings.iter().find(|f| f.id == *id) else {
            items.push(PlannedItem {
                id: id.clone(),
                title: "Unknown item".into(),
                what_runs: "Nothing to run".into(),
                undo: "Nothing changes".into(),
                permanent: false,
                bytes: 0,
                blocked: Some("Not in the last scan — scan again".into()),
            });
            continue;
        };
        let (what_runs, undo, permanent) = describe(ctx, f);
        let blocked = match &token {
            None => Some("Can't create a confirmation code".into()),
            Some(_) => check(ctx, f, guard, false).err(),
        };
        items.push(PlannedItem {
            id: f.id.clone(),
            title: f.title.clone(),
            what_runs,
            undo,
            permanent,
            bytes: f.bytes,
            blocked,
        });
    }
    Plan {
        token: token.unwrap_or_default(),
        report_scanned_at: report.scanned_at,
        items,
        created: ctx.now,
    }
}

/// Re-checks everything about `f` against the machine as it is now. The last gate before
/// anything is moved, stopped or deleted: any doubt is a refusal.
pub fn validate(ctx: &Ctx, f: &Finding, guard: Result<&Guard, &GuardError>) -> Result<(), String> {
    check(ctx, f, guard, true)
}

/// `create`: really set up the vault (validate) instead of only locating it (preview).
fn check(
    ctx: &Ctx,
    f: &Finding,
    guard: Result<&Guard, &GuardError>,
    create: bool,
) -> Result<(), String> {
    if let Some(e) = &ctx.rules.org_overlay_error {
        return Err(format!(
            "Refused: the organisation rules can't be read ({e})"
        ));
    }
    if let Some(e) = &ctx.ctx_error {
        return Err(format!("Refused: {e}"));
    }
    if f.tier == Tier::Protected {
        return Err(format!("Protected: {}", f.reason));
    }
    match &f.method {
        Method::None => Err("Nothing to do for this item".into()),
        Method::Vault { path, id, .. } => path_checks(ctx, f, path, id, false, guard, create),
        Method::WorktreeVault {
            repo,
            worktree,
            id,
            branch,
            ..
        } => {
            path_checks(ctx, f, worktree, id, true, guard, create)?;
            worktree_checks(
                ctx,
                repo,
                worktree,
                branch,
                guard.map_err(|_| GUARD_DOWN.to_string())?,
            )
        }
        Method::PruneOlderThan { path, .. } => {
            match (platform::canon(path), platform::canon(&ctx.dirs.temp)) {
                (Ok(a), Ok(b)) if platform::eq_ci(&a, &b) => {}
                _ => return Err("Only the Temp folder can be pruned".into()),
            }
            vault_available(ctx, path, create)
        }
        Method::Command { argv } => command_checks(argv, guard),
        Method::DockerVolumeBackupRm { name } => volume_checks(ctx, f, name),
        Method::DockerStop { container_ids } => stop_checks(ctx, container_ids),
        Method::Signal { pid, start_time } => signal_checks(ctx, *pid, *start_time, guard),
    }
}

fn vault_available(ctx: &Ctx, path: &Path, create: bool) -> Result<(), String> {
    if create {
        recovery::vault_for(path, ctx).map(|_| ())
    } else {
        recovery::vault_location(path, ctx).map(|_| ())
    }
}

/// Exe, cwd or a command-line argument (also the value of `--flag=value`) is `path` or inside it.
fn proc_uses(p: &Proc, path: &Path) -> bool {
    let inside = |c: &Path| guard::maybe_inside(c, path);
    if p.exe.as_deref().is_some_and(inside) || p.cwd.as_deref().is_some_and(inside) {
        return true;
    }
    p.cmd.iter().any(|a| {
        let value = a.split_once('=').map(|(_, v)| v);
        std::iter::once(a.as_str()).chain(value).any(|c| {
            let c = Path::new(c);
            if c.is_absolute() {
                inside(c)
            } else if c.components().count() > 1 {
                p.cwd.as_ref().is_some_and(|cwd| inside(&cwd.join(c)))
            } else {
                false
            }
        })
    })
}

fn path_checks(
    ctx: &Ctx,
    f: &Finding,
    path: &Path,
    id: &FileId,
    worktree: bool,
    guard: Result<&Guard, &GuardError>,
    create: bool,
) -> Result<(), String> {
    if f.path.as_deref().is_some_and(|p| p != path) {
        return Err("The item no longer matches the scan".into());
    }
    let (roots, _) = projects::roots(ctx);
    if let Some(why) = never::forbidden(path, &ctx.never_cfg(&roots)) {
        return Err(format!("Not allowed: {why}"));
    }
    match platform::file_id(path) {
        Ok(now) if now == *id => {}
        Ok(_) => return Err("The folder changed since scan".into()),
        Err(e) => return Err(format!("Can't check {}: {e}", path.display())),
    }
    // Without a process list nothing below can be checked.
    let g = guard.map_err(|_| GUARD_DOWN.to_string())?;
    if let Some(project) = &f.project {
        let a = g.check(project, ctx.run);
        if a.locked {
            return Err(format!("The project is in use: {}", a.reasons.join("; ")));
        }
        if !worktree {
            match guard::repo_of(project, ctx.run) {
                Repo::Git(_) => match guard::git_ignored(path, ctx.run) {
                    Ok(true) => {}
                    Ok(false) => return Err("Git no longer ignores it".into()),
                    Err(e) => return Err(format!("Can't ask git about it: {e}")),
                },
                Repo::NotARepo => {}
                Repo::GitMissing => return Err("Install Git so DevAudit can check projects".into()),
                Repo::GitFailed(e) => return Err(format!("git failed: {e}")),
            }
        }
    }
    if let Some(p) = g
        .procs
        .iter()
        .find(|p| procs::stem_matches(p, &f.owner_processes))
    {
        return Err(format!("Close {} first", p.name));
    }
    if let Some(p) = g.procs.iter().find(|p| proc_uses(p, path)) {
        return Err(format!("In use by {} (pid {})", p.name, p.pid));
    }
    if f.tier == Tier::Review {
        let found = if worktree {
            // Its own top-level `.git` pointer file is expected.
            targets::secret_in_worktree(path)?
        } else if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            never::find_secret_inside(path, never::SECRET_WALK_LIMIT)?
        } else {
            path.file_name()
                .filter(|n| never::name_is_secret(n))
                .map(|_| path.to_path_buf())
        };
        if let Some(hit) = found {
            return Err(format!("Contains {}", hit.display()));
        }
    }
    vault_available(ctx, path, create)
}

/// `git worktree list --porcelain` blocks as (path, branch ref).
fn parse_worktrees(text: &str) -> Vec<(PathBuf, Option<String>)> {
    text.split("\n\n")
        .filter_map(|block| {
            let mut path = None;
            let mut branch = None;
            for l in block.lines() {
                if let Some(p) = l.strip_prefix("worktree ") {
                    path = Some(PathBuf::from(p));
                } else if let Some(b) = l.strip_prefix("branch ") {
                    branch = Some(b.to_string());
                }
            }
            path.map(|p| (p, branch))
        })
        .collect()
}

fn worktree_checks(
    ctx: &Ctx,
    repo: &Path,
    wt: &Path,
    branch: &str,
    g: &Guard,
) -> Result<(), String> {
    let o = guard::git(ctx.run, repo, &["worktree", "list", "--porcelain"])
        .map_err(|e| format!("Can't list worktrees: {e:?}"))?;
    if o.status != 0 {
        return Err(format!("Can't list worktrees: {}", o.stderr.trim()));
    }
    let want = platform::canon(wt).map_err(|e| format!("Can't resolve the worktree: {e}"))?;
    let listed = parse_worktrees(&o.stdout).into_iter().any(|(p, b)| {
        platform::canon(&p).is_ok_and(|p| platform::eq_ci(&p, &want))
            && b.as_deref() == Some(format!("refs/heads/{branch}").as_str())
    });
    if !listed {
        return Err("The worktree is no longer on the same branch".into());
    }
    let o = guard::git(ctx.run, wt, &["status", "--porcelain"])
        .map_err(|e| format!("Can't read git status: {e:?}"))?;
    if o.status != 0 {
        return Err(format!("Can't read git status: {}", o.stderr.trim()));
    }
    if !o.stdout.trim().is_empty() {
        return Err("The worktree has uncommitted changes".into());
    }
    if g.cwds.iter().any(|(_, c)| guard::maybe_inside(c, wt)) {
        return Err("A program is working inside the worktree".into());
    }
    Ok(())
}

fn command_checks(argv: &[String], guard: Result<&Guard, &GuardError>) -> Result<(), String> {
    let Some(prog) = argv.first() else {
        return Err("Empty command".into());
    };
    if !ALLOWED_PROGRAMS.contains(&prog.as_str()) {
        return Err(format!("{prog} is not an allowed program"));
    }
    let g = guard.map_err(|_| GUARD_DOWN.to_string())?;
    let names = [prog.clone(), format!("{prog}-cli")];
    if g.procs.iter().any(|p| procs::stem_matches(p, &names)) {
        return Err(format!("{prog} is running; close it first"));
    }
    Ok(())
}

/// Free bytes where the Recovery vault would live (the data dir may not exist yet).
fn free_near(p: &Path) -> Result<u64, String> {
    p.ancestors()
        .find_map(|a| platform::volume_space(a).ok())
        .map(|(_, free)| free)
        .ok_or_else(|| "Can't read free disk space".to_string())
}

fn volume_checks(ctx: &Ctx, f: &Finding, name: &str) -> Result<(), String> {
    if name.is_empty() || name.starts_with('-') {
        return Err("Not a valid volume name".into());
    }
    let containers = docker::list_containers(ctx.run)?;
    if containers
        .iter()
        .any(|c| c.mounts.iter().any(|m| m == name))
    {
        return Err(format!("A container now uses volume {name}"));
    }
    let v = docker::volume_info(ctx.run, name)?;
    if !v.unreferenced {
        return Err(format!("Docker says something still uses volume {name}"));
    }
    if v.local_images == 0 {
        return Err("No local Docker image to run the backup from".into());
    }
    let size = v.bytes.max(f.bytes);
    let need = (u128::from(size) * 11).div_ceil(10);
    let free = free_near(&ctx.data_dir)?;
    if u128::from(free) < need {
        return Err(format!(
            "Not enough free space for the backup: need {}, have {}",
            human(u64::try_from(need).unwrap_or(u64::MAX)),
            human(free)
        ));
    }
    Ok(())
}

fn stop_checks(ctx: &Ctx, ids: &[String]) -> Result<(), String> {
    let containers = docker::list_containers(ctx.run)?;
    for id in ids {
        if id.is_empty() || id.starts_with('-') {
            return Err("Not a valid container id".into());
        }
        if !containers
            .iter()
            .any(|c| c.running && c.id.starts_with(id.as_str()))
        {
            return Err(format!("Container {id} is no longer running"));
        }
    }
    Ok(())
}

fn signal_checks(
    ctx: &Ctx,
    pid: u32,
    start_time: u64,
    guard: Result<&Guard, &GuardError>,
) -> Result<(), String> {
    if ctx.os == Os::Windows {
        return Err("Ending processes is not supported on Windows".into());
    }
    if pid == ctx.pid {
        return Err("DevAudit never stops itself".into());
    }
    match procs::start_time_of(pid) {
        Some(t) if t == start_time => {}
        Some(_) => return Err("The process was restarted since the scan".into()),
        None => return Err("The process is no longer running".into()),
    }
    let g = guard.map_err(|_| GUARD_DOWN.to_string())?;
    // Never one of the tool's own parents, never another user's process.
    let mut at = Some(ctx.pid);
    for _ in 0..64 {
        let Some(cur) = at else { break };
        if cur == pid {
            return Err("It is a parent of DevAudit".into());
        }
        at = g.procs.iter().find(|p| p.pid == cur).and_then(|p| p.parent);
    }
    if g.procs.iter().any(|p| p.pid == pid && !p.uid_matches_me) {
        return Err("It belongs to another user".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::tests::{elsewhere, guard, old, p, quiet, real, sh};
    use crate::model::{
        AppGroup, Category, DiskInfo, MemInfo, Method, Os, Pressure, Tier, finding_id,
    };
    use crate::platform::{self, KnownDirs};
    use crate::rules::{self, Rules};
    use crate::run::{FakeRunner, Output, RunError, Runner, SystemRunner};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

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
            self.ctx_with(Os::current(), &self.run, 1)
        }
        fn ctx_with<'a>(&'a self, os: Os, run: &'a dyn Runner, pid: u32) -> Ctx<'a> {
            Ctx::new(
                os,
                self.dirs.clone(),
                self.dirs.home.join(".devaudit"),
                run,
                &self.rules,
                SystemTime::now(),
                pid,
            )
        }
        /// An old, plain (not git) project with a `node_modules`; returns (project, node_modules).
        fn project(&self, name: &str) -> (PathBuf, PathBuf) {
            let proj = self.root.join(name);
            let nm = proj.join("node_modules");
            fs::create_dir_all(nm.join("x")).unwrap();
            fs::write(nm.join("x/f.js"), "1234").unwrap();
            fs::write(proj.join("package.json"), "{}").unwrap();
            old(&proj.join("package.json"));
            (proj, nm)
        }
        /// An old, clean git repo ignoring `node_modules`.
        fn git_project(&self, name: &str) -> (PathBuf, PathBuf) {
            let proj = self.root.join(name);
            fs::create_dir_all(&proj).unwrap();
            fs::write(proj.join("package.json"), "{}").unwrap();
            fs::write(proj.join(".gitignore"), "node_modules/\n").unwrap();
            sh(&proj, &["init", "-q"]);
            sh(&proj, &["add", "."]);
            sh(&proj, &["commit", "-q", "-m", "m"]);
            old(&proj.join("package.json"));
            old(&proj.join(".gitignore"));
            let nm = proj.join("node_modules");
            fs::create_dir_all(nm.join("x")).unwrap();
            fs::write(nm.join("x/f.js"), "1234").unwrap();
            (proj, nm)
        }
        /// A cache dir under home, outside any project.
        fn cache(&self, rel: &str) -> PathBuf {
            let d = self.dirs.home.join(rel);
            fs::create_dir_all(d.join("sub")).unwrap();
            fs::write(d.join("sub/blob"), "1234").unwrap();
            d
        }
    }

    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn vault_finding(path: &Path, project: Option<&Path>, tier: Tier) -> Finding {
        Finding {
            id: finding_id(Category::ProjectBuild, &path.to_string_lossy()),
            category: Category::ProjectBuild,
            title: "item".into(),
            path: Some(path.to_path_buf()),
            project: project.map(Path::to_path_buf),
            owner_processes: vec![],
            bytes: 4096,
            bytes_estimate: false,
            idle_days: Some(100),
            tier,
            reason: "because".into(),
            rebuild: None,
            method: Method::Vault {
                path: path.to_path_buf(),
                id: platform::file_id(path).unwrap(),
                keep_days: 3,
            },
        }
    }

    fn with_method(m: Method) -> Finding {
        Finding {
            id: finding_id(Category::PackageCache, &format!("{m:?}")),
            category: Category::PackageCache,
            title: "thing".into(),
            path: None,
            project: None,
            owner_processes: vec![],
            bytes: 2_000_000_000,
            bytes_estimate: true,
            idle_days: None,
            tier: Tier::Safe,
            reason: "because".into(),
            rebuild: None,
            method: m,
        }
    }

    fn cmd(argv: &[&str]) -> Finding {
        with_method(Method::Command {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        })
    }

    fn ok(s: &str) -> Result<Output, RunError> {
        Ok(Output {
            status: 0,
            stdout: s.into(),
            stderr: String::new(),
        })
    }

    fn is_err_with(r: Result<(), String>, needle: &str) {
        let e = r.expect_err("should be refused");
        assert!(e.contains(needle), "{e:?} lacks {needle:?}");
    }

    #[test]
    fn protected_never_validates() {
        let e = Env::new();
        let (proj, nm) = e.project("a");
        let ctx = e.ctx();
        let g = quiet();
        let mut f = vault_finding(&nm, Some(&proj), Tier::Safe);
        validate(&ctx, &f, Ok(&g)).unwrap();
        f.tier = Tier::Protected;
        assert!(validate(&ctx, &f, Ok(&g)).is_err());
        f.tier = Tier::Safe;
        f.method = Method::None;
        assert!(validate(&ctx, &f, Ok(&g)).is_err());
    }

    #[test]
    fn link_swap_after_scan_refused() {
        let e = Env::new();
        let (proj, nm) = e.project("a");
        let ctx = e.ctx();
        let f = vault_finding(&nm, Some(&proj), Tier::Safe);
        let other = e.root.join("a/other");
        fs::create_dir_all(&other).unwrap();
        fs::remove_dir_all(&nm).unwrap();
        if !platform::tests::dir_link(&other, &nm) {
            return;
        }
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
    }

    #[test]
    fn replaced_dir_new_identity_refused() {
        let e = Env::new();
        let (proj, nm) = e.project("a");
        let ctx = e.ctx();
        let f = vault_finding(&nm, Some(&proj), Tier::Safe);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        fs::remove_dir_all(&nm).unwrap();
        fs::create_dir_all(nm.join("x")).unwrap();
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "changed since scan");
    }

    #[test]
    fn project_became_active_refused() {
        let e = Env::new();
        let (proj, nm) = e.project("a");
        let ctx = e.ctx();
        let f = vault_finding(&nm, Some(&proj), Tier::Safe);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        let busy = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(7, "node", Some(&proj.join("src").to_string_lossy()), &[]),
        ]);
        is_err_with(validate(&ctx, &f, Ok(&busy)), "in use");
        // The guard failing is a refusal too.
        assert!(validate(&ctx, &f, Err(&GuardError::NoProcessData)).is_err());
    }

    #[test]
    fn git_projects_need_the_path_still_ignored() {
        let e = Env::new();
        let (proj, nm) = e.git_project("g");
        let ctx = e.ctx();
        let f = vault_finding(&nm, Some(&proj), Tier::Safe);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        // Dirty repo: locked.
        fs::write(proj.join(".gitignore"), "").unwrap();
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
        // Clean repo, but the folder isn't ignored (an empty folder doesn't show in status).
        fs::remove_dir_all(&nm).unwrap();
        let dist = proj.join("dist");
        fs::create_dir_all(dist.join("empty")).unwrap();
        sh(&proj, &["commit", "-qam", "unignore"]);
        old(&proj.join(".gitignore"));
        old(&proj.join("package.json"));
        let g = vault_finding(&dist, Some(&proj), Tier::Safe);
        is_err_with(validate(&ctx, &g, Ok(&quiet())), "ignores");
    }

    #[test]
    fn secret_added_after_scan_blocks_review_vault_move() {
        let e = Env::new();
        let dir = e.cache(".cache/thing");
        let ctx = e.ctx();
        let f = vault_finding(&dir, None, Tier::Review);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        fs::write(dir.join("sub/.env"), "KEY=1").unwrap();
        is_err_with(validate(&ctx, &f, Ok(&quiet())), ".env");
        // Safe items skip the content walk.
        let mut safe = f.clone();
        safe.tier = Tier::Safe;
        validate(&ctx, &safe, Ok(&quiet())).unwrap();
    }

    #[test]
    fn bad_org_overlay_refuses_everything() {
        let mut e = Env::new();
        let (proj, nm) = e.project("a");
        let f = vault_finding(&nm, Some(&proj), Tier::Safe);
        let c = cmd(&["brew", "cleanup"]);
        e.rules.org_overlay_error = Some("org-overlay.json is not valid".into());
        let ctx = e.ctx();
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "org-overlay.json");
        is_err_with(validate(&ctx, &c, Ok(&quiet())), "org-overlay.json");
    }

    #[test]
    fn cache_move_refused_while_owner_runs() {
        let e = Env::new();
        let dir = e.cache("Library/Application Support/Code/CachedData");
        let ctx = e.ctx();
        let mut f = vault_finding(&dir, None, Tier::Safe);
        f.owner_processes = vec!["Code Helper".into(), "Code".into()];
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(9, "Code Helper", None, &[]),
        ]);
        is_err_with(validate(&ctx, &f, Ok(&g)), "Close Code Helper first");
    }

    #[test]
    fn cache_move_refused_while_process_runs_from_inside() {
        let e = Env::new();
        let dir = e.dirs.home.join(".npm/_npx");
        fs::create_dir_all(dir.join("abc")).unwrap();
        let ctx = e.ctx();
        let f = vault_finding(&dir, None, Tier::Safe);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        let script = format!("{}/abc/node_modules/x/cli.js", dir.display());
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(9, "node", None, &["node", &script]),
        ]);
        is_err_with(validate(&ctx, &f, Ok(&g)), "In use by node (pid 9)");
        // A flag value naming a file inside counts too.
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(9, "tool", None, &["tool", &format!("--config={script}")]),
        ]);
        is_err_with(validate(&ctx, &f, Ok(&g)), "In use by tool (pid 9)");
        // A sibling with the same prefix doesn't.
        let sibling = format!("{}-old/cli.js", dir.display());
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(9, "node", None, &["node", &sibling]),
        ]);
        validate(&ctx, &f, Ok(&g)).unwrap();
    }

    #[test]
    fn non_project_cache_skips_git_checks() {
        let e = Env::new();
        let dir = e.cache("Library/Caches/thing");
        let fake = FakeRunner::new();
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        let f = vault_finding(&dir, None, Tier::Safe);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        // Without process data there is nothing to check against: refused.
        assert!(validate(&ctx, &f, Err(&GuardError::NoProcessData)).is_err());
    }

    #[test]
    fn command_refused_while_tool_running() {
        let e = Env::new();
        let ctx = e.ctx();
        let f = cmd(&["pnpm", "store", "prune"]);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        let running = |c: &[&str]| {
            guard(vec![
                p(1, "zsh", Some(&elsewhere()), &[]),
                p(5, "node", None, c),
            ])
        };
        is_err_with(
            validate(&ctx, &f, Ok(&running(&["node", "/x/pnpm.cjs", "install"]))),
            "pnpm",
        );
        let npm = cmd(&["npm", "cache", "clean"]);
        is_err_with(
            validate(&ctx, &npm, Ok(&running(&["node", "/x/npm-cli.js", "i"]))),
            "npm",
        );
        let yarn = cmd(&["yarn", "cache", "clean"]);
        is_err_with(
            validate(&ctx, &yarn, Ok(&running(&["node", "/x/yarn.js", "add"]))),
            "yarn",
        );
        let brew = cmd(&["brew", "cleanup", "--prune=30"]);
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(5, "brew", None, &["brew", "install", "x"]),
        ]);
        is_err_with(validate(&ctx, &brew, Ok(&g)), "brew");
        assert!(validate(&ctx, &brew, Err(&GuardError::NoProcessData)).is_err());
    }

    #[test]
    fn non_allowlisted_program_refused() {
        let e = Env::new();
        let ctx = e.ctx();
        for argv in [
            &["rm", "-rf", "/"][..],
            &["bash", "-c", "ls"],
            &["curl", "x"],
            &[],
            &["Docker"],
        ] {
            assert!(
                validate(&ctx, &cmd(argv), Ok(&quiet())).is_err(),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn pid_reuse_refused() {
        if Os::current() != Os::Macos {
            return;
        }
        let e = Env::new();
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let child = KillOnDrop(child);
        let pid = child.0.id();
        let start = crate::procs::start_time_of(pid).unwrap();
        let sig = |s: u64| with_method(Method::Signal { pid, start_time: s });
        let ctx = e.ctx();
        {
            validate(&ctx, &sig(start), Ok(&quiet())).unwrap();
            is_err_with(validate(&ctx, &sig(start + 1000), Ok(&quiet())), "start");
            // Never the tool itself.
            let me = e.ctx_with(Os::Macos, &e.run, pid);
            is_err_with(validate(&me, &sig(start), Ok(&quiet())), "itself");
            // Never one of its parents.
            let mut child_proc = p(pid, "sleep", None, &[]);
            child_proc.parent = Some(1);
            let mut tool = p(55, "devaudit", None, &[]);
            tool.parent = Some(pid);
            let g = guard(vec![p(1, "zsh", Some(&elsewhere()), &[]), tool, child_proc]);
            let mine = e.ctx_with(Os::Macos, &e.run, 55);
            is_err_with(validate(&mine, &sig(start), Ok(&g)), "parent");
            // A pid that isn't running.
            let gone = with_method(Method::Signal {
                pid: u32::MAX - 1,
                start_time: 1,
            });
            assert!(validate(&ctx, &gone, Ok(&quiet())).is_err());
        }
    }

    #[test]
    fn signal_refused_on_windows() {
        let e = Env::new();
        let ctx = e.ctx_with(Os::Windows, &e.run, 1);
        let f = with_method(Method::Signal {
            pid: 4242,
            start_time: 1,
        });
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "not supported on Windows");
    }

    #[test]
    fn no_same_volume_vault_refused() {
        let e = Env::new();
        let (proj, nm) = e.project("a");
        let ctx = e.ctx();
        let f = vault_finding(&nm, Some(&proj), Tier::Safe);
        // The data dir sits on another drive, so the project root must host the vault,
        // and it can't (a file is in the way).
        platform::fake_volume(&ctx.data_dir, 424_242);
        fs::write(e.root.join(".devaudit-vault"), "in the way").unwrap();
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
        fs::remove_file(e.root.join(".devaudit-vault")).unwrap();
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        // The item itself on another drive than its project root: refused too.
        let (proj2, nm2) = e.project("b");
        let f2 = vault_finding(&nm2, Some(&proj2), Tier::Safe);
        platform::fake_volume(&nm2, 2);
        assert!(validate(&ctx, &f2, Ok(&quiet())).is_err());
        // And with no project root around the item at all.
        let c = e.cache(".cache/thing");
        let f3 = vault_finding(&c, None, Tier::Safe);
        is_err_with(
            validate(&ctx, &f3, Ok(&quiet())),
            "no Recovery space on this drive",
        );
    }

    const DF_USED: &str = r#"{"Images":[{"Repository":"alpine","Tag":"3","Size":"7MB","Containers":"0"}],"Volumes":[{"Name":"pgdata","Links":"0","Size":"1GB"}]}"#;

    fn docker_run(ps: &str, df: &str) -> FakeRunner {
        FakeRunner::new()
            .on(&["docker", "ps", "-a"], ok(ps))
            .on(&["docker", "system", "df"], ok(df))
    }

    fn volume_finding() -> Finding {
        let mut f = with_method(Method::DockerVolumeBackupRm {
            name: "pgdata".into(),
        });
        f.tier = Tier::Review;
        f.bytes = 1_000_000_000;
        f
    }

    #[test]
    fn volume_now_in_use_refused() {
        let e = Env::new();
        let f = volume_finding();
        platform::fake_free_space(&e.dirs.home.join(".devaudit"), 100_000_000_000);
        let fake = docker_run("", DF_USED);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        // A stopped container now mounts it.
        let ps = r#"{"ID":"abc123","Names":"db","Image":"postgres","State":"exited","Mounts":"other,pgdata","Labels":""}"#;
        let fake = docker_run(ps, DF_USED);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "pgdata");
        // `system df` says something links to it.
        let linked = DF_USED.replace(r#""Links":"0""#, r#""Links":"1""#);
        let fake = docker_run("", &linked);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
        // Docker not answering: refused.
        let fake = FakeRunner::new();
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
        // Names that could be read as options are refused.
        let mut dash = volume_finding();
        dash.method = Method::DockerVolumeBackupRm { name: "-f".into() };
        assert!(validate(&ctx, &dash, Ok(&quiet())).is_err());
    }

    #[test]
    fn volume_backup_without_space_refused() {
        let e = Env::new();
        let f = volume_finding();
        let data = e.dirs.home.join(".devaudit");
        let fake = docker_run("", DF_USED);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        platform::fake_free_space(&data, 1_000_000_000);
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "space");
        platform::fake_free_space(&data, 1_099_999_999);
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
        platform::fake_free_space(&data, 1_100_000_000);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        // No local image to run the backup container from.
        let no_image = DF_USED.replace(
            r#"{"Repository":"alpine","Tag":"3","Size":"7MB","Containers":"0"}"#,
            "",
        );
        let fake = docker_run("", &no_image);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "image");
    }

    #[test]
    fn docker_stop_needs_containers_still_running() {
        let e = Env::new();
        let mut f = with_method(Method::DockerStop {
            container_ids: vec!["abc123".into(), "def456".into()],
        });
        f.tier = Tier::Review;
        let run = |a: &str, b: &str| {
            format!(
                r#"{{"ID":"abc123","Names":"a","Image":"i","State":"{a}","Mounts":"","Labels":""}}
{{"ID":"def456","Names":"b","Image":"i","State":"{b}","Mounts":"","Labels":""}}"#
            )
        };
        let fake = docker_run(&run("running", "running"), DF_USED);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        let fake = docker_run(&run("running", "exited"), DF_USED);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        is_err_with(validate(&ctx, &f, Ok(&quiet())), "def456");
        let fake = docker_run(&run("running", "running").replace("def456", "zzz"), DF_USED);
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
    }

    #[test]
    fn prune_only_for_the_temp_dir() {
        let e = Env::new();
        let ctx = e.ctx();
        fs::create_dir_all(&e.dirs.temp).unwrap();
        let good = with_method(Method::PruneOlderThan {
            path: e.dirs.temp.clone(),
            days: 7,
        });
        validate(&ctx, &good, Ok(&quiet())).unwrap();
        let bad = with_method(Method::PruneOlderThan {
            path: e.dirs.home.clone(),
            days: 7,
        });
        assert!(validate(&ctx, &bad, Ok(&quiet())).is_err());
    }

    #[test]
    fn worktree_must_be_clean_and_still_listed() {
        let e = Env::new();
        let main = e.root.join("repo");
        fs::create_dir_all(&main).unwrap();
        fs::write(main.join("a.txt"), "x").unwrap();
        sh(&main, &["init", "-q", "-b", "main"]);
        sh(&main, &["add", "."]);
        sh(&main, &["commit", "-q", "-m", "m"]);
        old(&main.join("a.txt"));
        let wt = e.root.join("wts/wt1");
        sh(
            &main,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "feature",
                wt.to_str().unwrap(),
            ],
        );
        old(&wt.join("a.txt"));
        old(&wt.join(".git"));
        let ctx = e.ctx();
        let mut f = vault_finding(&wt, Some(&wt), Tier::Review);
        f.method = Method::WorktreeVault {
            repo: main.clone(),
            worktree: wt.clone(),
            id: platform::file_id(&wt).unwrap(),
            branch: "feature".into(),
            keep_days: 30,
        };
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        // Wrong branch.
        let mut wrong = f.clone();
        if let Method::WorktreeVault { branch, .. } = &mut wrong.method {
            *branch = "other".into();
        }
        assert!(validate(&ctx, &wrong, Ok(&quiet())).is_err());
        // A cwd inside it.
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(8, "zsh", Some(&wt.join("sub").to_string_lossy()), &[]),
        ]);
        assert!(validate(&ctx, &f, Ok(&g)).is_err());
        // Uncommitted work.
        fs::write(wt.join("new.txt"), "n").unwrap();
        old(&wt.join("new.txt"));
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
        fs::remove_file(wt.join("new.txt")).unwrap();
        validate(&ctx, &f, Ok(&quiet())).unwrap();
        // No longer a worktree of the repo.
        sh(
            &main,
            &["worktree", "remove", "--force", wt.to_str().unwrap()],
        );
        assert!(validate(&ctx, &f, Ok(&quiet())).is_err());
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            os: Os::current(),
            scanned_at: 1234,
            disk: DiskInfo {
                total: 1000,
                free: 400,
                scanned: 300,
                unseen: 200,
                trash: 10,
            },
            memory: MemInfo {
                total: 16,
                available: 8,
                swap_used: 1,
                swap_total: 2,
                pressure: Pressure::Normal,
                groups: vec![AppGroup {
                    name: "Chrome".into(),
                    mem: 5,
                    procs: 3,
                }],
            },
            findings,
            skipped: vec![],
            notes: vec![],
        }
    }

    fn all_methods(e: &Env) -> (Vec<Finding>, PathBuf) {
        let (proj, nm) = e.project("a");
        let mut v = vec![vault_finding(&nm, Some(&proj), Tier::Safe)];
        let c = e.cache(".cache/rev");
        let mut review = vault_finding(&c, None, Tier::Review);
        if let Method::Vault { keep_days, .. } = &mut review.method {
            *keep_days = 30;
        }
        v.push(review);
        v.push(with_method(Method::PruneOlderThan {
            path: e.dirs.temp.clone(),
            days: 7,
        }));
        v.push(cmd(&["brew", "cleanup", "--prune=30"]));
        let mut vol = volume_finding();
        vol.bytes = 1_200_000_000;
        v.push(vol);
        v.push(with_method(Method::DockerStop {
            container_ids: vec!["abc".into(), "def".into()],
        }));
        v.push(with_method(Method::Signal {
            pid: 4242,
            start_time: 1,
        }));
        v.push(with_method(Method::None));
        for (i, f) in v.iter_mut().enumerate() {
            f.id = format!("id{i}");
        }
        (v, nm)
    }

    #[test]
    fn preview_shows_undo_text_for_every_item() {
        let e = Env::new();
        let (findings, nm) = all_methods(&e);
        let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
        let r = report(findings);
        let ctx = e.ctx();
        let g = quiet();
        let plan = preview_with(&ctx, &r, &ids, Ok(&g));
        assert_eq!(plan.report_scanned_at, 1234);
        assert_eq!(plan.items.len(), ids.len());
        for it in &plan.items {
            assert!(!it.undo.is_empty() && !it.what_runs.is_empty(), "{it:?}");
        }
        let by = |i: usize| &plan.items[i];
        assert_eq!(by(0).undo, "Recoverable for 3 days");
        assert_eq!(
            by(0).what_runs,
            format!("Move to Recovery (kept 3 days): {}", nm.display())
        );
        assert!(!by(0).permanent && by(0).blocked.is_none(), "{:?}", by(0));
        assert_eq!(by(0).bytes, 4096);
        assert_eq!(by(1).undo, "Recoverable for 30 days");
        assert_eq!(by(3).what_runs, "Run: brew cleanup --prune=30");
        assert_eq!(by(3).undo, "Can't be undone — re-downloads when needed");
        assert!(by(3).permanent);
        assert_eq!(
            by(4).undo,
            "Back up 1.2 GB, then remove — recoverable for 30 days"
        );
        assert!(by(4).what_runs.contains("docker volume rm pgdata"));
        assert_eq!(by(5).undo, "Start again from History");
        assert!(by(5).what_runs.contains("docker stop abc def"));
        assert!(by(6).permanent && by(6).undo.contains("Can't be undone"));
        assert!(by(7).blocked.is_some());
        // Anything that can't run is blocked with the reason.
        assert!(by(2).undo.starts_with("Recoverable for 3 days"));
    }

    #[test]
    fn preview_blocks_what_validate_refuses() {
        let e = Env::new();
        let (findings, _) = all_methods(&e);
        let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
        let r = report(findings);
        let ctx = e.ctx();
        let plan = preview_with(&ctx, &r, &ids, Err(&GuardError::NoProcessData));
        assert!(plan.items.iter().all(|i| i.blocked.is_some()));
        // Preview is read-only: no vault was created.
        assert!(!ctx.data_dir.exists());
    }

    #[test]
    fn retention_zero_is_permanent_and_says_so() {
        let mut e = Env::new();
        e.rules.retention.safe_days = 0;
        let (findings, _) = all_methods(&e);
        let mut f0 = findings[0].clone();
        if let Method::Vault { keep_days, .. } = &mut f0.method {
            *keep_days = 0;
        }
        let r = report(vec![f0.clone()]);
        let ctx = e.ctx();
        let plan = preview_with(&ctx, &r, &[f0.id.clone()], Ok(&quiet()));
        let it = &plan.items[0];
        assert_eq!(it.undo, "Not recoverable — retention is set to 0 days");
        assert!(it.permanent);
    }

    #[test]
    fn unknown_id_blocked_in_preview() {
        let e = Env::new();
        let fake = FakeRunner::new();
        let ctx = e.ctx_with(Os::current(), &fake, 1);
        let (findings, _) = all_methods(&e);
        let r = report(findings);
        let plan = preview(
            &ctx,
            &r,
            &["nope".to_string(), "id3".to_string(), "id3".to_string()],
        );
        assert_eq!(plan.items.len(), 2, "duplicates are dropped");
        assert_eq!(plan.items[0].id, "nope");
        assert!(plan.items[0].blocked.is_some());
        assert_eq!(plan.token.len(), 32);
        assert!(
            plan.token
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let again = preview(&ctx, &r, &[]);
        assert_ne!(plan.token, again.token);
    }

    #[test]
    fn preview_wording_per_os() {
        let e = Env::new();
        let sig = with_method(Method::Signal {
            pid: 4242,
            start_time: 1,
        });
        let id = sig.id.clone();
        let r = report(vec![sig]);
        let mac = e.ctx_with(Os::Macos, &e.run, 1);
        let it = &preview_with(&mac, &r, std::slice::from_ref(&id), Ok(&quiet())).items[0];
        assert!(it.what_runs.contains("SIGTERM") && it.what_runs.contains("4242"));
        assert!(it.permanent && it.undo.contains("Can't be undone"));
        let win = e.ctx_with(Os::Windows, &e.run, 1);
        let it = &preview_with(&win, &r, &[id], Ok(&quiet())).items[0];
        assert!(!it.what_runs.contains("SIGTERM"), "{}", it.what_runs);
        is_err_with(Err(it.blocked.clone().unwrap()), "not supported on Windows");
    }
}
