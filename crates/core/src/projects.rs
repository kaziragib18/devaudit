//! Finds build dirs (`node_modules`, `target`, ...) under the user's project roots and tiers them.

use crate::guard::{self, Activity, Guard, GuardError, Repo};
use crate::model::{Category, Finding, Method, Skipped, Tier, finding_id};
use crate::rules::BuildDirRule;
use crate::{Ctx, disk, never, platform, rules};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_DEPTH: usize = 6;

#[derive(Clone, Debug, PartialEq)]
pub struct BuildDir {
    pub project: PathBuf,
    pub dir: PathBuf,
    pub rule: String,
}

/// Valid, existing, de-duplicated project roots (outer root wins) plus a
/// warning for each root that exists but is not allowed.
pub fn roots(ctx: &Ctx) -> (Vec<PathBuf>, Vec<String>) {
    let mut warnings = vec![];
    let mut found: Vec<PathBuf> = vec![];
    for r in &ctx.rules.project_roots {
        let Some(p) = rules::expand(r, &ctx.dirs, None) else {
            continue;
        };
        if !p.exists() {
            continue;
        }
        match never::valid_project_root(&p, &ctx.dirs) {
            Ok(()) => found.push(p),
            Err(e) => warnings.push(format!("Skipped project folder {}: {e}", p.display())),
        }
    }
    found.sort_by_key(|p| p.components().count());
    let mut out: Vec<PathBuf> = vec![];
    for p in found {
        if !out.iter().any(|o| platform::inside(&p, o)) {
            out.push(p);
        }
    }
    (out, warnings)
}

fn has_requirement(entries: &[String], req: &str) -> bool {
    match req.strip_prefix('*') {
        Some(ext) => entries.iter().any(|n| n.to_lowercase().ends_with(ext)),
        None => entries.iter().any(|n| n == req),
    }
}

/// Walks each root `max_depth` levels deep. Never follows links and never
/// enters a build dir, `.git` or `.devaudit-vault`.
pub fn discover(roots: &[PathBuf], rules: &[BuildDirRule], max_depth: usize) -> Vec<BuildDir> {
    let mut out = vec![];
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut names = vec![];
        let mut subdirs = vec![];
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Ok(md) = fs::symlink_metadata(e.path())
                && !platform::is_link(&md)
                && md.is_dir()
            {
                subdirs.push(name.clone());
            }
            names.push(name);
        }
        for name in subdirs {
            if name == ".git" || name.eq_ignore_ascii_case(".devaudit-vault") {
                continue;
            }
            let Some(rule) = rules.iter().find(|r| r.name.eq_ignore_ascii_case(&name)) else {
                if depth < max_depth {
                    stack.push((dir.join(&name), depth + 1));
                }
                continue;
            };
            if rule.requires_any.iter().any(|q| has_requirement(&names, q)) {
                out.push(BuildDir {
                    project: dir.clone(),
                    dir: dir.join(&name),
                    rule: rule.name.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

fn rebuild_hint(rule: &str) -> &'static str {
    match rule {
        "node_modules" => "Run npm install",
        ".venv" | "venv" => "Recreate the virtual environment and reinstall packages",
        "target" => "Run cargo build",
        "bin" | "obj" => "Run dotnet build",
        ".gradle" => "Run the Gradle build again",
        _ => "Run the build again",
    }
}

pub fn findings(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    cancel: &AtomicBool,
) -> (Vec<Finding>, Vec<Skipped>) {
    let (roots, _) = roots(ctx);
    let cfg = ctx.never_cfg(&roots);
    let r = ctx.rules;
    let mut out = vec![];
    let mut skipped = vec![];
    let mut acts: HashMap<PathBuf, Activity> = HashMap::new();
    for b in discover(&roots, &r.build_dirs, MAX_DEPTH) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let u = disk::usage(&b.dir, &[], cancel);
        skipped.extend(u.skipped);
        let act = match guard {
            Ok(g) => Some(
                acts.entry(b.project.clone())
                    .or_insert_with(|| g.check(&b.project, ctx.run))
                    .clone(),
            ),
            Err(_) => None,
        };
        let pnpm = b.project.join("pnpm-lock.yaml").exists();
        let id_key = platform::canon(&b.dir).unwrap_or_else(|_| b.dir.clone());
        // Protected with a reason, or the tier it earned.
        let verdict: Result<(Tier, String), String> = (|| {
            if let Some(why) = never::forbidden(&b.dir, &cfg) {
                return Err(why);
            }
            let act = act
                .as_ref()
                .ok_or_else(|| "Can't check running programs".to_string())?;
            if act.locked {
                return Err(act.reasons.join("; "));
            }
            match guard::repo_of(&b.project, ctx.run) {
                Repo::Git(_) => match guard::git_ignored(&b.dir, ctx.run) {
                    Ok(true) => {
                        let rule = r.build_dirs.iter().find(|x| x.name == b.rule);
                        let lock = rule.is_some_and(|x| {
                            x.lockfiles.iter().any(|l| b.project.join(l).exists())
                        });
                        let idle = act.idle_days.unwrap_or(0);
                        if lock && idle >= r.safe_idle_days {
                            Ok((
                                Tier::Safe,
                                format!("Ignored by git, idle {idle} days, lockfile present"),
                            ))
                        } else {
                            Ok((
                                Tier::Review,
                                "Ignored by git, but recently used or no lockfile".into(),
                            ))
                        }
                    }
                    Ok(false) => Err("Tracked by git".into()),
                    Err(e) => Err(e),
                },
                Repo::NotARepo => Ok((
                    Tier::Review,
                    "Not in a git repository, so DevAudit can't tell what is generated".into(),
                )),
                Repo::GitMissing => Err("Install Git so DevAudit can check projects".into()),
                Repo::GitFailed(d) => Err(format!("git failed: {d}")),
            }
        })();
        let (tier, mut reason, method) = match verdict {
            Err(why) => (Tier::Protected, why, Method::None),
            Ok((tier, why)) => match platform::file_id(&b.dir) {
                Ok(id) => {
                    let keep_days = if tier == Tier::Safe {
                        r.retention.safe_days
                    } else {
                        r.retention.review_days
                    };
                    (
                        tier,
                        why,
                        Method::Vault {
                            path: b.dir.clone(),
                            id,
                            keep_days,
                        },
                    )
                }
                Err(e) => (
                    Tier::Protected,
                    format!("Can't identify folder: {e}"),
                    Method::None,
                ),
            },
        };
        if pnpm {
            reason.push_str(" — shared with pnpm store, may free less");
        }
        let folder = b.project.file_name().unwrap_or_default().to_string_lossy();
        out.push(Finding {
            id: finding_id(Category::ProjectBuild, &id_key.to_string_lossy()),
            category: Category::ProjectBuild,
            title: format!("{} in {folder}", b.rule),
            path: Some(b.dir.clone()),
            project: Some(b.project.clone()),
            owner_processes: vec![],
            bytes: u.bytes,
            bytes_estimate: pnpm,
            idle_days: act.and_then(|a| a.idle_days),
            tier,
            reason,
            rebuild: Some(rebuild_hint(&b.rule).into()),
            method,
        });
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::tests::{elsewhere, old, p, real, sh, snap};
    use crate::model::{Method, Os, Tier};
    use crate::platform::KnownDirs;
    use crate::rules::{self, Rules};
    use crate::run::{FakeRunner, SystemRunner};
    use std::fs;
    use std::time::SystemTime;

    struct Env {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        rules: Rules,
        run: SystemRunner,
        dirs: KnownDirs,
    }

    impl Env {
        fn new() -> Env {
            Env::with_root("my code ü")
        }
        fn with_root(name: &str) -> Env {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().canonicalize().unwrap().join("home");
            let root = home.join(name);
            fs::create_dir_all(&root).unwrap();
            let mut rules = rules::builtin();
            rules.project_roots = vec![root.to_string_lossy().into_owned()];
            let dirs = KnownDirs {
                home: home.clone(),
                local_app_data: None,
                app_data: None,
                temp: home.join("tmp"),
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
        fn run_findings(&self) -> Vec<Finding> {
            let ctx = self.ctx();
            let g = crate::guard::Guard::build(
                &snap(vec![p(1, "zsh", Some(&elsewhere()), &[])]),
                &FakeRunner::new(),
                14,
                SystemTime::now(),
            );
            let (f, _) = findings(&ctx, g.as_ref(), &AtomicBool::new(false));
            f
        }
        /// An old project with package.json, node_modules and optionally git / a lockfile.
        fn project(&self, name: &str, git: bool, lock: bool) -> PathBuf {
            let d = self.root.join(name);
            fs::create_dir_all(d.join("node_modules/x")).unwrap();
            fs::write(d.join("node_modules/x/f.js"), "1234").unwrap();
            let mut files = vec!["package.json"];
            fs::write(d.join("package.json"), "{}").unwrap();
            if lock {
                fs::write(d.join("package-lock.json"), "{}").unwrap();
                files.push("package-lock.json");
            }
            if git {
                fs::write(d.join(".gitignore"), "node_modules\n").unwrap();
                files.push(".gitignore");
                sh(&d, &["init", "-q"]);
                sh(&d, &["add", "."]);
                sh(&d, &["commit", "-q", "-m", "m"]);
            }
            for f in files {
                old(&d.join(f));
            }
            d
        }
    }

    fn rules() -> Vec<BuildDirRule> {
        rules::builtin().build_dirs
    }

    fn names(v: &[BuildDir]) -> Vec<String> {
        v.iter()
            .map(|b| b.dir.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn discovers_in_roots_with_spaces_and_unicode() {
        let e = Env::new();
        let pr = e.root.join("sub dir/pröject");
        fs::create_dir_all(pr.join("node_modules")).unwrap();
        fs::write(pr.join("package.json"), "{}").unwrap();
        let (roots, w) = roots(&e.ctx());
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(roots, vec![e.root.clone()]);
        let d = discover(&roots, &rules(), 6);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].project, pr);
        assert_eq!(d[0].dir, pr.join("node_modules"));
        assert_eq!(d[0].rule, "node_modules");
    }

    #[test]
    fn ignores_node_modules_without_package_json() {
        let e = Env::new();
        fs::create_dir_all(e.root.join("a/node_modules")).unwrap();
        assert!(discover(std::slice::from_ref(&e.root), &rules(), 6).is_empty());
    }

    #[test]
    fn extension_requirement_and_depth_limit() {
        let e = Env::new();
        let net = e.root.join("net");
        fs::create_dir_all(net.join("bin")).unwrap();
        fs::write(net.join("App.csproj"), "").unwrap();
        let deep = e.root.join("1/2/3/4/5/6/7");
        fs::create_dir_all(deep.join("target")).unwrap();
        fs::write(deep.join("Cargo.toml"), "").unwrap();
        let d = discover(std::slice::from_ref(&e.root), &rules(), 6);
        assert_eq!(names(&d), vec![net.join("bin").to_string_lossy()]);
    }

    #[test]
    fn nested_node_modules_reported_once() {
        let e = Env::new();
        let pr = e.root.join("a");
        fs::create_dir_all(pr.join("node_modules/dep/node_modules")).unwrap();
        fs::write(pr.join("package.json"), "{}").unwrap();
        fs::write(pr.join("node_modules/dep/package.json"), "{}").unwrap();
        let d = discover(std::slice::from_ref(&e.root), &rules(), 6);
        assert_eq!(names(&d), vec![pr.join("node_modules").to_string_lossy()]);
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlink_or_junction() {
        let e = Env::new();
        let real_p = e.root.join("real/p");
        fs::create_dir_all(real_p.join("node_modules")).unwrap();
        fs::write(real_p.join("package.json"), "{}").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(outside.path().join("q/node_modules")).unwrap();
        fs::write(outside.path().join("q/package.json"), "{}").unwrap();
        std::os::unix::fs::symlink(outside.path(), e.root.join("link")).unwrap();
        let d = discover(std::slice::from_ref(&e.root), &rules(), 6);
        assert_eq!(
            names(&d),
            vec![real_p.join("node_modules").to_string_lossy()]
        );
    }

    #[test]
    fn devaudit_vault_not_discovered() {
        let e = Env::new();
        let v = e.root.join(".devaudit-vault/entry/p");
        fs::create_dir_all(v.join("node_modules")).unwrap();
        fs::write(v.join("package.json"), "{}").unwrap();
        assert!(discover(std::slice::from_ref(&e.root), &rules(), 6).is_empty());
    }

    #[test]
    fn idle_ignored_with_lockfile_is_safe_vault_3_days() {
        let e = Env::new();
        let pr = e.project("a", true, true);
        let f = e.run_findings();
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!(f.tier, Tier::Safe, "{}", f.reason);
        assert_eq!(f.project.as_deref(), Some(pr.as_path()));
        assert_eq!(f.title, "node_modules in a");
        assert!(f.bytes > 0 && !f.bytes_estimate);
        assert!(f.idle_days.unwrap() >= 30);
        assert_eq!(f.rebuild.as_deref(), Some("Run npm install"));
        match &f.method {
            Method::Vault {
                path, keep_days, ..
            } => {
                assert_eq!(path, &pr.join("node_modules"));
                assert_eq!(*keep_days, 3);
            }
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn missing_lockfile_is_review_vault_30_days() {
        let e = Env::new();
        e.project("a", true, false);
        let f = e.run_findings();
        assert_eq!(f[0].tier, Tier::Review, "{}", f[0].reason);
        assert!(matches!(f[0].method, Method::Vault { keep_days: 30, .. }));
    }

    #[test]
    fn committed_dist_is_protected() {
        let e = Env::new();
        let pr = e.root.join("a");
        fs::create_dir_all(pr.join("dist")).unwrap();
        fs::write(pr.join("dist/o.js"), "1").unwrap();
        fs::write(pr.join("package.json"), "{}").unwrap();
        fs::write(pr.join("package-lock.json"), "{}").unwrap();
        sh(&pr, &["init", "-q"]);
        sh(&pr, &["add", "."]);
        sh(&pr, &["commit", "-q", "-m", "m"]);
        for f in ["dist/o.js", "package.json", "package-lock.json"] {
            old(&pr.join(f));
        }
        let f = e.run_findings();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tier, Tier::Protected);
        assert_eq!(f[0].reason, "Tracked by git");
        assert_eq!(f[0].method, Method::None);
    }

    #[test]
    fn guard_error_protects_everything() {
        let e = Env::new();
        e.project("a", true, true);
        let (f, _) = findings(
            &e.ctx(),
            Err(&crate::guard::GuardError::NoProcessData),
            &AtomicBool::new(false),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tier, Tier::Protected);
        assert_eq!(f[0].method, Method::None);
        assert!(f[0].reason.contains("running programs"), "{}", f[0].reason);
    }

    #[test]
    fn non_git_project_is_review_never_safe() {
        let e = Env::new();
        e.project("a", false, true);
        let f = e.run_findings();
        assert_eq!(f[0].tier, Tier::Review, "{}", f[0].reason);
    }

    #[test]
    fn pnpm_project_marked_estimate() {
        let e = Env::new();
        let pr = e.project("a", false, false);
        fs::write(pr.join("pnpm-lock.yaml"), "").unwrap();
        old(&pr.join("pnpm-lock.yaml"));
        let f = e.run_findings();
        assert!(f[0].bytes_estimate);
        assert!(
            f[0].reason.contains("shared with pnpm store"),
            "{}",
            f[0].reason
        );
    }

    #[test]
    fn locked_project_is_protected() {
        let e = Env::new();
        let pr = e.project("a", true, true);
        let ctx = e.ctx();
        let g = crate::guard::Guard::build(
            &snap(vec![p(1, "node", Some(&pr.to_string_lossy()), &[])]),
            &FakeRunner::new(),
            14,
            SystemTime::now(),
        );
        let (f, _) = findings(&ctx, g.as_ref(), &AtomicBool::new(false));
        assert_eq!(f[0].tier, Tier::Protected);
        assert!(f[0].reason.contains("in use by"), "{}", f[0].reason);
    }

    #[test]
    fn cancel_returns_nothing_more() {
        let e = Env::new();
        e.project("a", true, true);
        let g = crate::guard::Guard::build(
            &snap(vec![p(1, "zsh", Some(&elsewhere()), &[])]),
            &FakeRunner::new(),
            14,
            SystemTime::now(),
        );
        let (f, _) = findings(&e.ctx(), g.as_ref(), &AtomicBool::new(true));
        assert!(f.is_empty());
    }

    #[test]
    fn invalid_project_root_rejected_with_warning() {
        let mut e = Env::new();
        let home = e.dirs.home.clone();
        e.rules.project_roots = vec![
            home.to_string_lossy().into_owned(),
            e.root.join("missing").to_string_lossy().into_owned(),
        ];
        let (r, w) = roots(&e.ctx());
        assert!(r.is_empty(), "{r:?}");
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].starts_with("Skipped project folder "), "{}", w[0]);
    }

    #[test]
    fn nested_root_dropped() {
        let mut e = Env::new();
        let inner = e.root.join("inner");
        fs::create_dir_all(&inner).unwrap();
        e.rules.project_roots = vec![
            inner.to_string_lossy().into_owned(),
            e.root.to_string_lossy().into_owned(),
        ];
        assert_eq!(roots(&e.ctx()).0, vec![e.root.clone()]);
    }
}
