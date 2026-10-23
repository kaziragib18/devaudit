//! Recovery vault. Task 12 part: `vault_for` only.

use crate::guard::{self, Repo};
use crate::{Ctx, platform, projects};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
/// vault inside a git repo, keeps it out of `git status`. An existing vault was hidden when
/// it was created and isn't marked again.
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
    // Marking a folder can take seconds (macOS `tmutil`), so only a new vault is marked.
    if fresh {
        platform::hide_from_backup_and_index(&vault).map_err(|x| {
            // Leave nothing half-set-up, so the next call marks it.
            let _ = fs::remove_dir(&vault);
            format!("can't hide {} from backups: {x}", vault.display())
        })?;
    }
    Ok(vault)
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
}
