//! Active-project guard: decides whether a project is in use. Fails closed.

use crate::disk;
use crate::model::Os;
use crate::never::BUILD_DIR_NAMES;
use crate::platform;
use crate::procs::{self, Proc};
use crate::run::{RunError, Runner};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq)]
pub struct Activity {
    pub locked: bool,
    pub reasons: Vec<String>,
    pub idle_days: Option<u32>,
}

#[derive(Debug)]
pub struct Guard {
    /// Kept for validate's running-tool and in-target checks.
    pub procs: Vec<Proc>,
    pub cwds: Vec<(u32, PathBuf)>,
    pub cmd_paths: Vec<(u32, String)>,
    pub unreadable: Vec<(u32, String)>,
    pub mounts: Vec<PathBuf>,
    /// Docker is up but couldn't be read: every project is locked.
    pub docker_error: Option<String>,
    pub git_available: bool,
    pub recent_days: u32,
    pub now: SystemTime,
}

#[derive(Debug, PartialEq)]
pub enum GuardError {
    NoProcessData,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Repo {
    Git(PathBuf),
    NotARepo,
    GitMissing,
    GitFailed(String),
}

const GIT_MISSING: &str = "Install Git so DevAudit can check projects";
const T: Duration = Duration::from_secs(30);

pub fn normalize_path_text(s: &str) -> String {
    normalize_path_text_for(Os::current(), s)
}

fn normalize_path_text_for(os: Os, s: &str) -> String {
    let mut t = s.to_string();
    if os == Os::Windows {
        if let Some(r) = t.strip_prefix(r"\\?\UNC\") {
            t = format!(r"\\{r}");
        } else if let Some(r) = t.strip_prefix(r"\\?\") {
            t = r.to_string();
        }
        t = t.replace('/', "\\");
    }
    let sep: &[char] = if os == Os::Windows { &['\\'] } else { &['/'] };
    let trimmed = t.trim_end_matches(sep);
    // Keep a bare root ("/" or "C:\") meaningful.
    let t = if trimmed.is_empty() {
        &t[..t.len().min(1)]
    } else {
        trimmed
    };
    t.to_lowercase()
}

pub fn normalize_mount(src: &str) -> Option<PathBuf> {
    normalize_mount_for(Os::current(), src)
}

pub(crate) fn normalize_mount_for(os: Os, src: &str) -> Option<PathBuf> {
    match os {
        Os::Macos => src.starts_with('/').then(|| PathBuf::from(src)),
        Os::Windows => {
            let b = src.as_bytes();
            if let Some(rest) = src.strip_prefix("/run/desktop/mnt/host/") {
                let (d, tail) = match rest.split_once('/') {
                    Some(x) => x,
                    None => (rest, ""),
                };
                let mut c = d.chars();
                let (Some(l), None) = (c.next(), c.next()) else {
                    return None;
                };
                if !l.is_ascii_alphabetic() {
                    return None;
                }
                let tail = tail.replace('/', "\\");
                return Some(PathBuf::from(format!(
                    "{}:\\{}",
                    l.to_ascii_uppercase(),
                    tail
                )));
            }
            if b.len() >= 3
                && b[0].is_ascii_alphabetic()
                && b[1] == b':'
                && (b[2] == b'\\' || b[2] == b'/')
            {
                return Some(PathBuf::from(src.replace('/', "\\")));
            }
            None
        }
    }
}

pub(crate) fn git(
    run: &dyn Runner,
    dir: &Path,
    args: &[&str],
) -> Result<crate::run::Output, RunError> {
    let d = dir.to_string_lossy();
    // A scanned repo's config must not be able to run commands (core.fsmonitor), nor may we write to it.
    let mut argv = vec![
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-C",
        &*d,
    ];
    argv.extend_from_slice(args);
    run.run(&argv, T)
}

/// The directory to run git in: `path` if it is a directory, else its nearest existing ancestor.
fn git_dir(path: &Path) -> PathBuf {
    path.ancestors()
        .find(|p| p.is_dir())
        .unwrap_or(path)
        .to_path_buf()
}

pub fn repo_of(path: &Path, run: &dyn Runner) -> Repo {
    match git(run, &git_dir(path), &["rev-parse", "--show-toplevel"]) {
        Ok(o) if o.status == 0 => {
            let t = PathBuf::from(o.stdout.trim());
            Repo::Git(platform::canon(&t).unwrap_or(t))
        }
        Ok(o)
            if o.stderr
                .contains("not a git repository (or any of the parent directories)") =>
        {
            Repo::NotARepo
        }
        Ok(o) => Repo::GitFailed(format!("exit {}: {}", o.status, o.stderr.trim())),
        Err(RunError::NotFound(_)) => Repo::GitMissing,
        Err(e) => Repo::GitFailed(format!("{e:?}")),
    }
}

pub fn git_ignored(path: &Path, run: &dyn Runner) -> Result<bool, String> {
    let dir = git_dir(path.parent().unwrap_or(path));
    let p = path.to_string_lossy();
    let o = git(run, &dir, &["check-ignore", "-q", "--", &p]).map_err(|e| format!("{e:?}"))?;
    match o.status {
        1 => return Ok(false),
        0 => {}
        n => return Err(format!("git check-ignore exit {n}: {}", o.stderr.trim())),
    }
    let o = git(run, &dir, &["ls-files", "--", &p]).map_err(|e| format!("{e:?}"))?;
    if o.status != 0 {
        return Err(format!(
            "git ls-files exit {}: {}",
            o.status,
            o.stderr.trim()
        ));
    }
    Ok(o.stdout.trim().is_empty())
}

/// Like `platform::inside`, but when a side can't be resolved it falls back to a
/// lexical comparison (equal, or below at a component boundary) instead of "not inside".
pub(crate) fn maybe_inside(child: &Path, parent: &Path) -> bool {
    let (c, p) = (platform::canon(child), platform::canon(parent));
    if c.is_ok() && p.is_ok() {
        return platform::inside(child, parent);
    }
    let c = normalize_path_text(&child.to_string_lossy());
    let mut parents = vec![normalize_path_text(&parent.to_string_lossy())];
    if let Ok(p) = p {
        parents.push(normalize_path_text(&p.to_string_lossy()));
    }
    parents.iter().any(|p| {
        c == *p
            || c.strip_prefix(p.as_str()).is_some_and(|r| {
                p.ends_with(std::path::MAIN_SEPARATOR) || r.starts_with(std::path::MAIN_SEPARATOR)
            })
    })
}

pub(crate) fn docker_down(stderr: &str) -> bool {
    [
        "Cannot connect to the Docker daemon",
        "Is the docker daemon running",
        "error during connect",
        "//./pipe/docker_engine",
    ]
    .iter()
    .any(|m| stderr.contains(m))
}

/// Bind-mount sources, or Err when Docker is running but can't be read (fail closed).
/// Docker not installed or not running gives an empty list.
fn docker_mounts(run: &dyn Runner) -> Result<Vec<PathBuf>, String> {
    let call = |argv: &[&str]| -> Result<Option<String>, String> {
        match run.run(argv, T) {
            Ok(o) if o.status == 0 => Ok(Some(o.stdout)),
            Ok(o) if docker_down(&o.stderr) => Ok(None),
            Ok(o) => Err(format!("exit {}: {}", o.status, o.stderr.trim())),
            Err(RunError::NotFound(_)) => Ok(None),
            Err(e) => Err(format!("{e:?}")),
        }
    };
    let Some(ids) = call(&["docker", "ps", "-q"])? else {
        return Ok(vec![]);
    };
    let ids: Vec<&str> = ids.split_whitespace().collect();
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let mut argv = vec!["docker", "inspect", "--format", "{{json .Mounts}}"];
    argv.extend(&ids);
    let Some(out) = call(&argv)? else {
        return Ok(vec![]);
    };
    let mut mounts = vec![];
    for l in out.lines().filter(|l| !l.trim().is_empty()) {
        let v: Vec<serde_json::Value> = serde_json::from_str(l.trim())
            .map_err(|e| format!("unreadable docker inspect output: {e}"))?;
        mounts.extend(
            v.iter()
                .filter(|m| m["Type"] == "bind")
                .filter_map(|m| m["Source"].as_str().and_then(normalize_mount)),
        );
    }
    Ok(mounts)
}

/// `needle` occurs in `hay` ending at a path/word boundary (so `app` doesn't match `app2`).
fn mentions(hay: &str, needle: &str) -> bool {
    !needle.is_empty()
        && hay.match_indices(needle).any(|(i, _)| {
            hay[i + needle.len()..]
                .chars()
                .next()
                .is_none_or(|c| matches!(c, '\\' | '/' | ' ' | '"' | '\''))
        })
}

impl Guard {
    pub fn build(
        s: &procs::Snapshot,
        run: &dyn Runner,
        recent_days: u32,
        now: SystemTime,
    ) -> Result<Guard, GuardError> {
        let cwds: Vec<(u32, PathBuf)> = s
            .procs
            .iter()
            .filter(|p| p.uid_matches_me)
            .filter_map(|p| p.cwd.clone().map(|c| (p.pid, c)))
            .collect();
        if cwds.is_empty() {
            return Err(GuardError::NoProcessData);
        }
        let cmd_paths = s
            .procs
            .iter()
            .flat_map(|p| {
                p.cmd
                    .iter()
                    .filter(|a| a.chars().count() > 3 && a.contains(['/', '\\']))
                    .map(|a| (p.pid, normalize_path_text(a)))
            })
            .collect();
        let (mounts, docker_error) = match docker_mounts(run) {
            Ok(m) => (m, None),
            Err(e) => (vec![], Some(e)),
        };
        Ok(Guard {
            procs: s.procs.clone(),
            cwds,
            cmd_paths,
            unreadable: s.own_cwd_unreadable.clone(),
            mounts,
            docker_error,
            git_available: !matches!(repo_of(Path::new("."), run), Repo::GitMissing),
            recent_days,
            now,
        })
    }

    fn name(&self, pid: u32) -> String {
        self.procs
            .iter()
            .find(|p| p.pid == pid)
            .map_or_else(|| "a process".into(), |p| p.name.clone())
    }

    pub fn check(&self, project: &Path, run: &dyn Runner) -> Activity {
        let mut reasons: Vec<String> = vec![];
        for (pid, name) in &self.unreadable {
            reasons.push(format!(
                "Can't see what {name} (pid {pid}) is working on — it may be running as administrator"
            ));
        }
        let mut users: Vec<u32> = self
            .cwds
            .iter()
            .filter(|(_, c)| maybe_inside(c, project))
            .map(|(p, _)| *p)
            .collect();
        let mut needles = vec![normalize_path_text(&project.to_string_lossy())];
        if let Ok(c) = platform::canon(project) {
            needles.push(normalize_path_text(&c.to_string_lossy()));
        }
        users.extend(
            self.cmd_paths
                .iter()
                .filter(|(_, a)| needles.iter().any(|n| mentions(a, n)))
                .map(|(p, _)| *p),
        );
        users.sort_unstable();
        users.dedup();
        for pid in users {
            reasons.push(format!("in use by {} (pid {pid})", self.name(pid)));
        }
        if let Some(e) = &self.docker_error {
            reasons.push(format!("Can't check Docker containers: {e}"));
        }
        // A mount of the project, or of a folder containing it, exposes it to the container.
        if self
            .mounts
            .iter()
            .any(|m| maybe_inside(m, project) || maybe_inside(project, m))
        {
            reasons.push("Docker container mounts it".into());
        }

        let mut commit = None;
        match repo_of(project, run) {
            Repo::Git(top) => {
                let st = [
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                    "--ignore-submodules=none",
                ];
                match git(run, &top, &st) {
                    Ok(o) if o.status == 0 => {
                        if !o.stdout.trim().is_empty() {
                            reasons.push("uncommitted changes".into());
                        }
                    }
                    Ok(o) => reasons.push(format!(
                        "Can't read git status: exit {}: {}",
                        o.status,
                        o.stderr.trim()
                    )),
                    Err(e) => reasons.push(format!("Can't read git status: {e:?}")),
                }
                // A repo with no commits yet is benign; any other history failure is not.
                match git(run, &top, &["rev-parse", "--verify", "-q", "HEAD"]) {
                    Ok(o) if o.status == 1 => {}
                    _ => match git(run, &top, &["log", "-1", "--format=%ct"]) {
                        Ok(o) if o.status == 0 => match o.stdout.trim().parse::<u64>() {
                            Ok(secs) => commit = Some(UNIX_EPOCH + Duration::from_secs(secs)),
                            Err(_) => reasons.push(format!(
                                "Can't read git history: unreadable commit time {:?}",
                                o.stdout.trim()
                            )),
                        },
                        Ok(o) if o.stderr.contains("does not have any commits") => {}
                        Ok(o) => reasons.push(format!(
                            "Can't read git history: exit {}: {}",
                            o.status,
                            o.stderr.trim()
                        )),
                        Err(e) => reasons.push(format!("Can't read git history: {e:?}")),
                    },
                }
            }
            Repo::NotARepo => {}
            Repo::GitMissing => reasons.push(GIT_MISSING.into()),
            Repo::GitFailed(d) => reasons.push(format!("git failed: {d}")),
        }

        let mut skip: Vec<&str> = BUILD_DIR_NAMES.to_vec();
        skip.extend([".git", ".devaudit-vault"]);
        let walk = platform::canon(project).unwrap_or_else(|_| project.to_path_buf());
        let usage = disk::usage(&walk, &skip, &AtomicBool::new(false));
        if !usage.skipped.is_empty() {
            reasons.push("Couldn't read some folders in the project".into());
        }
        let mtime = usage.newest_mtime;
        let idle_days = mtime.into_iter().chain(commit).max().map(|t| {
            let secs = self.now.duration_since(t).unwrap_or_default().as_secs();
            u32::try_from(secs / 86_400).unwrap_or(u32::MAX)
        });
        match idle_days {
            None => reasons.push("Can't tell when it was last used".into()),
            Some(d) if d < self.recent_days => reasons.push(match d {
                0 => "edited today".into(),
                1 => "edited 1 day ago".into(),
                d => format!("edited {d} days ago"),
            }),
            _ => {}
        }
        Activity {
            locked: !reasons.is_empty(),
            reasons,
            idle_days,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::procs::Snapshot;
    use crate::run::{FakeRunner, Output, SystemRunner};
    use std::fs::{self, File};
    use std::process::Command;

    const DAY: u64 = 86_400;

    pub(crate) fn real() -> SystemRunner {
        SystemRunner {
            tool_dirs: platform::tool_dirs(&platform::known_dirs()),
        }
    }

    pub(crate) fn git_bin() -> PathBuf {
        real().resolve("git").expect("git installed")
    }

    pub(crate) fn sh(dir: &Path, args: &[&str]) {
        let st = Command::new(git_bin())
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(dir)
            .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
            .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    }

    pub(crate) fn old(path: &Path) {
        let t = SystemTime::now() - Duration::from_secs(400 * DAY);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    /// Committed, clean repo whose files and commit are 2020-old.
    pub(crate) fn old_repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a.txt"), "x").unwrap();
        sh(d.path(), &["init", "-q"]);
        sh(d.path(), &["add", "."]);
        sh(d.path(), &["commit", "-q", "-m", "m"]);
        old(&d.path().join("a.txt"));
        d
    }

    pub(crate) fn old_plain() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a.txt"), "x").unwrap();
        old(&d.path().join("a.txt"));
        d
    }

    pub(crate) fn p(pid: u32, name: &str, cwd: Option<&str>, cmd: &[&str]) -> Proc {
        Proc {
            pid,
            uid_matches_me: true,
            name: name.into(),
            cwd: cwd.map(PathBuf::from),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            ..Proc::default()
        }
    }

    pub(crate) fn snap(procs: Vec<Proc>) -> Snapshot {
        Snapshot {
            procs,
            ..Snapshot::default()
        }
    }

    pub(crate) fn guard(procs: Vec<Proc>) -> Guard {
        Guard::build(&snap(procs), &FakeRunner::new(), 14, SystemTime::now()).unwrap()
    }

    /// A nonexistent path outside any test project.
    pub(crate) fn elsewhere() -> String {
        std::env::temp_dir()
            .join("devaudit-nonexistent-elsewhere")
            .to_string_lossy()
            .into_owned()
    }

    pub(crate) fn quiet() -> Guard {
        guard(vec![p(1, "zsh", Some(&elsewhere()), &[])])
    }

    #[test]
    fn no_process_data_fails_closed() {
        let s = snap(vec![p(1, "zsh", None, &[])]);
        let r = Guard::build(&s, &FakeRunner::new(), 14, SystemTime::now());
        assert_eq!(r.unwrap_err(), GuardError::NoProcessData);
    }

    #[test]
    fn one_unreadable_own_process_locks_everything() {
        let mut s = snap(vec![p(1, "zsh", Some("/x"), &[])]);
        s.own_cwd_unreadable = vec![(7, "Code".into())];
        let g = Guard::build(&s, &FakeRunner::new(), 14, SystemTime::now()).unwrap();
        let d = old_repo();
        let a = g.check(d.path(), &real());
        assert!(a.locked);
        assert!(a.reasons[0].contains("Code (pid 7)"), "{:?}", a.reasons);
    }

    #[test]
    fn cwd_inside_locks() {
        let d = old_repo();
        let sub = d.path().join("sub");
        fs::create_dir(&sub).unwrap();
        old(&d.path().join("a.txt"));
        let g = guard(vec![p(5, "node", Some(sub.to_str().unwrap()), &[])]);
        let a = g.check(d.path(), &real());
        assert!(a.locked);
        assert!(
            a.reasons.contains(&"in use by node (pid 5)".to_string()),
            "{:?}",
            a.reasons
        );
    }

    #[test]
    fn sibling_prefix_not_inside() {
        let d = old_repo();
        let sib = PathBuf::from(format!("{}2", d.path().display()));
        fs::create_dir(&sib).unwrap();
        let g = guard(vec![p(
            5,
            "node",
            Some(sib.to_str().unwrap()),
            &[&format!("{}/x", sib.display())],
        )]);
        let a = g.check(d.path(), &real());
        fs::remove_dir(&sib).unwrap();
        assert!(!a.locked, "{:?}", a.reasons);
    }

    #[test]
    fn command_line_mention_locks() {
        let d = old_repo();
        let canon = platform::canon(d.path()).unwrap();
        let arg = format!("{}/node_modules/.bin/next", canon.display());
        let g = guard(vec![
            p(1, "zsh", Some(&elsewhere()), &[]),
            p(9, "node", None, &[&arg, "dev"]),
        ]);
        let a = g.check(d.path(), &real());
        assert!(
            a.reasons.contains(&"in use by node (pid 9)".to_string()),
            "{:?}",
            a.reasons
        );
    }

    #[test]
    fn path_text_normalisation() {
        let n = |os, s| normalize_path_text_for(os, s);
        assert_eq!(
            n(Os::Windows, r"\\?\C:\Users\A B\Dev\App\"),
            r"c:\users\a b\dev\app"
        );
        assert_eq!(
            n(Os::Windows, "c:/users/a b/dev/app/x.js"),
            r"c:\users\a b\dev\app\x.js"
        );
        assert_eq!(n(Os::Windows, r"\\?\UNC\srv\Share\x"), r"\\srv\share\x");
        assert_eq!(n(Os::Macos, "/Users/A/App/"), "/users/a/app");
        assert_eq!(n(Os::Macos, "/"), "/");
    }

    #[cfg(windows)]
    #[test]
    fn command_line_forward_slash_and_verbatim_forms_lock() {
        let d = old_repo();
        let canon = platform::canon(d.path()).unwrap();
        let fwd = format!("{}/x.js", canon.display().to_string().replace('\\', "/"));
        let g = guard(vec![
            p(1, "cmd", Some(&elsewhere()), &[]),
            p(9, "node", None, &[&fwd]),
        ]);
        assert!(g.check(d.path(), &real()).locked);
    }

    #[test]
    fn not_a_repo_is_not_locked_but_git_missing_is() {
        let d = old_plain();
        let a = quiet().check(d.path(), &real());
        assert!(!a.locked, "{:?}", a.reasons);
        assert!(a.idle_days.unwrap() >= 399);
        assert_eq!(repo_of(d.path(), &real()), Repo::NotARepo);
        let a = quiet().check(d.path(), &FakeRunner::new());
        assert!(a.locked);
        assert!(a.reasons.contains(&GIT_MISSING.to_string()));
    }

    #[test]
    fn git_missing_fails_closed() {
        assert_eq!(
            repo_of(Path::new("/tmp"), &FakeRunner::new()),
            Repo::GitMissing
        );
        let timeout = FakeRunner::new().on(&["git"], Err(RunError::Timeout));
        assert!(matches!(
            repo_of(Path::new("/tmp"), &timeout),
            Repo::GitFailed(_)
        ));
        let d = old_plain();
        assert!(quiet().check(d.path(), &timeout).locked);
        let g = Guard::build(
            &snap(vec![p(1, "z", Some("/x"), &[])]),
            &FakeRunner::new(),
            14,
            SystemTime::now(),
        )
        .unwrap();
        assert!(!g.git_available);
    }

    #[test]
    fn force_added_file_in_ignored_dir_is_not_ignored() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join(".gitignore"), "dist/\n").unwrap();
        fs::create_dir(d.path().join("dist")).unwrap();
        fs::write(d.path().join("dist/keep.txt"), "k").unwrap();
        sh(d.path(), &["init", "-q"]);
        assert_eq!(git_ignored(&d.path().join("dist"), &real()), Ok(true));
        sh(d.path(), &["add", "-f", "dist/keep.txt"]);
        assert_eq!(git_ignored(&d.path().join("dist"), &real()), Ok(false));
    }

    #[test]
    fn gitignored_node_modules() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join(".gitignore"), "node_modules\n").unwrap();
        fs::create_dir(d.path().join("node_modules")).unwrap();
        fs::create_dir(d.path().join("src")).unwrap();
        sh(d.path(), &["init", "-q"]);
        assert_eq!(
            git_ignored(&d.path().join("node_modules"), &real()),
            Ok(true)
        );
        assert_eq!(git_ignored(&d.path().join("src"), &real()), Ok(false));
        assert!(git_ignored(&d.path().join("node_modules"), &FakeRunner::new()).is_err());
    }

    #[test]
    fn docker_mount_forms_normalised() {
        let w = |s| normalize_mount_for(Os::Windows, s);
        assert_eq!(
            w("/run/desktop/mnt/host/c/Users/x"),
            Some(PathBuf::from(r"C:\Users\x"))
        );
        assert_eq!(w("/run/desktop/mnt/host/d"), Some(PathBuf::from(r"D:\")));
        assert_eq!(w(r"C:\Users\x"), Some(PathBuf::from(r"C:\Users\x")));
        assert_eq!(w("c:/Users/x"), Some(PathBuf::from(r"c:\Users\x")));
        assert_eq!(w("/var/lib/docker"), None);
        assert_eq!(w("/run/desktop/mnt/host/wsl/x"), None);
        assert_eq!(
            normalize_mount_for(Os::Macos, "/Users/x"),
            Some(PathBuf::from("/Users/x"))
        );
        assert_eq!(normalize_mount_for(Os::Macos, "relative"), None);
    }

    #[test]
    fn docker_mounts_locks() {
        let d = old_repo();
        let src = platform::canon(d.path()).unwrap();
        let json = format!(
            r#"[{{"Type":"bind","Source":"{}"}},{{"Type":"volume","Source":"/v"}}]"#,
            src.display()
        );
        let ok = |s: &str| {
            Ok(Output {
                status: 0,
                stdout: s.into(),
                stderr: String::new(),
            })
        };
        let r = FakeRunner::new()
            .on(&["docker", "ps", "-q"], ok("abc\n"))
            .on(
                &["docker", "inspect", "--format", "{{json .Mounts}}", "abc"],
                ok(&format!("{json}\n")),
            );
        let g = Guard::build(
            &snap(vec![p(1, "z", Some(&elsewhere()), &[])]),
            &r,
            14,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(g.mounts, vec![src]);
        let a = g.check(d.path(), &real());
        assert!(
            a.reasons
                .contains(&"Docker container mounts it".to_string()),
            "{:?}",
            a.reasons
        );
        // Docker not running: no mounts.
        assert!(quiet().mounts.is_empty());
    }

    #[test]
    fn dirty_repo_locked() {
        let d = old_repo();
        fs::write(d.path().join("new.txt"), "n").unwrap();
        old(&d.path().join("new.txt"));
        let a = quiet().check(d.path(), &real());
        assert!(a.locked);
        assert!(
            a.reasons.contains(&"uncommitted changes".to_string()),
            "{:?}",
            a.reasons
        );
    }

    #[test]
    fn old_clean_repo_unlocked_with_idle_days() {
        let d = old_repo();
        let a = quiet().check(d.path(), &real());
        assert!(!a.locked, "{:?}", a.reasons);
        assert!(a.idle_days.unwrap() > 365);
    }

    #[test]
    fn recent_edit_locks_even_with_old_commit() {
        let d = old_repo();
        fs::write(d.path().join("b.txt"), "b").unwrap();
        sh(d.path(), &["add", "."]);
        sh(d.path(), &["commit", "-q", "-m", "b"]);
        let a = quiet().check(d.path(), &real());
        assert!(a.locked && a.idle_days == Some(0), "{a:?}");
        assert!(
            a.reasons.contains(&"edited today".to_string()),
            "{:?}",
            a.reasons
        );
    }

    #[test]
    fn empty_project_cannot_tell_idle() {
        let d = tempfile::tempdir().unwrap();
        let a = quiet().check(d.path(), &real());
        assert!(a.locked && a.idle_days.is_none());
    }

    #[test]
    fn repo_without_commits_uses_mtime_only() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a.txt"), "x").unwrap();
        old(&d.path().join("a.txt"));
        sh(d.path(), &["init", "-q"]);
        let a = quiet().check(d.path(), &real());
        // untracked file is "uncommitted changes", but idle days come from mtime
        assert!(a.idle_days.unwrap() > 365, "{a:?}");
    }

    #[test]
    fn worktree_recognised() {
        let d = old_repo();
        let wt = tempfile::tempdir().unwrap();
        let wt_path = wt.path().join("wt");
        sh(
            d.path(),
            &["worktree", "add", "-q", wt_path.to_str().unwrap()],
        );
        match repo_of(&wt_path, &real()) {
            Repo::Git(top) => assert_eq!(top, platform::canon(&wt_path).unwrap()),
            r => panic!("{r:?}"),
        }
    }

    fn ok(s: &str) -> Result<Output, RunError> {
        Ok(Output {
            status: 0,
            stdout: s.into(),
            stderr: String::new(),
        })
    }

    fn fail(code: i32, err: &str) -> Result<Output, RunError> {
        Ok(Output {
            status: code,
            stdout: String::new(),
            stderr: err.into(),
        })
    }

    #[cfg(unix)]
    #[test]
    fn fsmonitor_in_repo_config_is_not_run() {
        use std::os::unix::fs::PermissionsExt;
        let d = old_repo();
        let marker = d.path().join("MARKER");
        let script = d.path().join("hook.sh");
        fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        old(&script);
        sh(
            d.path(),
            &["config", "core.fsmonitor", script.to_str().unwrap()],
        );
        let _ = quiet().check(d.path(), &real());
        assert!(!marker.exists());
    }

    #[test]
    fn git_log_failure_locks_but_no_commits_is_benign() {
        let d = old_plain();
        let top = platform::canon(d.path()).unwrap();
        // Status ok+empty, HEAD verifies, log fails.
        let pre = [
            "git",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-C",
            top.to_str().unwrap(),
        ];
        let on = |r: FakeRunner, tail: &[&str], res| {
            let v: Vec<&str> = pre.iter().chain(tail).copied().collect();
            r.on(&v, res)
        };
        let r = on(
            FakeRunner::new(),
            &["rev-parse", "--show-toplevel"],
            ok(&format!("{}\n", top.display())),
        );
        let r = on(r, &["status"], ok(""));
        let r = on(r, &["rev-parse", "--verify"], ok("abc\n"));
        let broken = on(r, &["log"], fail(128, "fatal: bad object"));
        let a = quiet().check(&top, &broken);
        assert!(
            a.reasons
                .iter()
                .any(|r| r.starts_with("Can't read git history")),
            "{:?}",
            a.reasons
        );
        // Genuinely no commits: HEAD doesn't verify, log fails with the usual message.
        let r = on(
            FakeRunner::new(),
            &["rev-parse", "--show-toplevel"],
            ok(&format!("{}\n", top.display())),
        );
        let r = on(r, &["status"], ok(""));
        let r = on(r, &["rev-parse", "--verify"], fail(1, ""));
        let a = quiet().check(&top, &r);
        assert!(
            !a.reasons.iter().any(|r| r.contains("history")),
            "{:?}",
            a.reasons
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_subdir_locks() {
        use std::os::unix::fs::PermissionsExt;
        let d = old_repo();
        let sub = d.path().join("locked");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&sub).is_ok(); // running as root
        let a = quiet().check(d.path(), &real());
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        if !readable {
            assert!(
                a.reasons
                    .contains(&"Couldn't read some folders in the project".to_string()),
                "{:?}",
                a.reasons
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn dangling_cwd_under_project_locks() {
        let d = old_repo();
        let gone = d.path().join("gone/deeper");
        let g = guard(vec![p(5, "node", Some(gone.to_str().unwrap()), &[])]);
        let a = g.check(d.path(), &real());
        assert!(
            a.reasons.contains(&"in use by node (pid 5)".to_string()),
            "{:?}",
            a.reasons
        );
    }

    #[test]
    fn dangling_cwd_elsewhere_does_not_lock() {
        let d = old_repo();
        let g = guard(vec![p(5, "zsh", Some(&elsewhere()), &[])]);
        let a = g.check(d.path(), &real());
        assert!(!a.locked, "{:?}", a.reasons);
        // Sibling-prefix of an unresolvable path is not "inside" either.
        assert!(!maybe_inside(
            Path::new("/nope/app2/x"),
            Path::new("/nope/app")
        ));
        assert!(maybe_inside(
            Path::new("/nope/app/x"),
            Path::new("/nope/app")
        ));
        assert!(maybe_inside(
            Path::new("/nope/app"),
            Path::new("/nope/app/")
        ));
    }

    #[test]
    fn docker_failure_modes() {
        let s = snap(vec![p(1, "z", Some(&elsewhere()), &[])]);
        let build = |r: &FakeRunner| Guard::build(&s, r, 14, SystemTime::now()).unwrap();
        for down in [
            "Cannot connect to the Docker daemon at unix:///x",
            "error during connect: open //./pipe/docker_engine",
        ] {
            let g = build(&FakeRunner::new().on(&["docker"], fail(1, down)));
            assert!(g.docker_error.is_none() && g.mounts.is_empty(), "{down}");
        }
        for r in [
            FakeRunner::new().on(&["docker"], Err(RunError::Timeout)),
            FakeRunner::new().on(&["docker"], fail(1, "permission denied")),
            FakeRunner::new()
                .on(&["docker", "ps"], ok("abc\n"))
                .on(&["docker", "inspect"], ok("not json\n")),
        ] {
            let g = build(&r);
            assert!(g.docker_error.is_some());
            let d = old_repo();
            let a = g.check(d.path(), &real());
            assert!(
                a.locked
                    && a.reasons
                        .iter()
                        .any(|r| r.starts_with("Can't check Docker containers")),
                "{:?}",
                a.reasons
            );
        }
    }

    #[test]
    fn git_failed_shows_detail() {
        let d = old_plain();
        let r = FakeRunner::new().on(&["git"], fail(128, "fatal: broken .git pointer"));
        assert!(matches!(repo_of(d.path(), &r), Repo::GitFailed(_)));
        let a = quiet().check(d.path(), &r);
        assert!(
            a.reasons
                .iter()
                .any(|r| r.starts_with("git failed:") && r.contains("broken")),
            "{:?}",
            a.reasons
        );
        assert!(!a.reasons.contains(&GIT_MISSING.to_string()));
    }
}
