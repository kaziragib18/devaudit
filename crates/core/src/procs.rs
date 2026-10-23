//! Processes and memory via `sysinfo`: snapshot, app groups, orphans, duplicate MCP servers.

use crate::Ctx;
use crate::model::{AppGroup, Category, Finding, MemInfo, Method, Os, Tier, finding_id};
use crate::platform;
use crate::rules::Rules;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const MIB: u64 = 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Proc {
    pub pid: u32,
    pub parent: Option<u32>,
    pub uid_matches_me: bool,
    pub mem: u64,
    /// Seconds since the epoch.
    pub start_time: u64,
    pub exe: Option<PathBuf>,
    pub cmd: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub name: String,
    /// macOS: environ has XPC_SERVICE_NAME other than "0"; Windows: false.
    pub launchd_managed: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MemTotals {
    pub total: u64,
    pub available: u64,
    pub swap_used: u64,
    pub swap_total: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub procs: Vec<Proc>,
    /// Own-user procs whose cwd couldn't be read.
    pub own_cwd_unreadable: Vec<(u32, String)>,
    pub mem: MemTotals,
}

pub fn snapshot() -> Snapshot {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_memory()
            .with_cmd(UpdateKind::Always)
            .with_cwd(UpdateKind::Always)
            .with_exe(UpdateKind::Always)
            .with_user(UpdateKind::Always)
            .with_environ(UpdateKind::Always),
    );
    let me = sysinfo::get_current_pid()
        .ok()
        .and_then(|p| sys.process(p))
        .and_then(|p| p.user_id());
    let mac = Os::current() == Os::Macos;
    let mut s = Snapshot {
        mem: MemTotals {
            total: sys.total_memory(),
            available: sys.available_memory(),
            swap_used: sys.used_swap(),
            swap_total: sys.total_swap(),
        },
        ..Snapshot::default()
    };
    for (pid, p) in sys.processes() {
        let cmd: Vec<String> = p.cmd().iter().map(|a| a.to_string_lossy().into()).collect();
        let own = me.is_some() && p.user_id() == me;
        let name = p.name().to_string_lossy().into_owned();
        let pid = pid.as_u32();
        if own && pid != 0 && !cmd.is_empty() && p.cwd().is_none() {
            s.own_cwd_unreadable.push((pid, name.clone()));
        }
        let launchd_managed = mac
            && p.environ().iter().any(|e| {
                e.to_string_lossy()
                    .strip_prefix("XPC_SERVICE_NAME=")
                    .is_some_and(|v| !v.is_empty() && v != "0")
            });
        s.procs.push(Proc {
            pid,
            parent: p.parent().map(|p| p.as_u32()),
            uid_matches_me: own,
            mem: p.memory(),
            start_time: p.start_time(),
            exe: p.exe().map(Path::to_path_buf),
            cmd,
            cwd: p.cwd().map(Path::to_path_buf),
            name,
            launchd_managed,
        });
    }
    s
}

/// Start time of `pid` now, for re-checks before acting. None if it isn't running.
pub fn start_time_of(pid: u32) -> Option<u64> {
    let mut sys = System::new();
    let p = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[p]),
        true,
        ProcessRefreshKind::nothing(),
    );
    sys.process(p).map(|p| p.start_time())
}

/// Last path component, splitting on both separators so Windows paths work anywhere.
fn file_name(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

fn stem_of(s: &str) -> &str {
    let f = file_name(s);
    match f.rfind('.') {
        Some(i) if i > 0 => &f[..i],
        _ => f,
    }
}

fn exe_str(p: &Proc) -> String {
    p.exe
        .as_ref()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn exe_stem(p: &Proc) -> Option<String> {
    p.exe
        .as_ref()
        .map(|e| stem_of(&e.to_string_lossy()).to_lowercase())
}

fn name_stem(p: &Proc) -> String {
    let n = p.name.to_lowercase();
    n.strip_suffix(".exe").map(str::to_string).unwrap_or(n)
}

/// argv[1]'s stem (the script a runtime is running), unless it's a flag.
fn arg1_stem(p: &Proc) -> Option<String> {
    p.cmd
        .get(1)
        .filter(|a| !a.starts_with('-'))
        .map(|a| stem_of(a).to_lowercase())
}

/// Exact, case-insensitive match on exe stem, name (sans `.exe`) or argv[1] stem.
/// A name containing a space is compared against exe stem / name only.
pub fn stem_matches(p: &Proc, names: &[String]) -> bool {
    let (exe, name, arg1) = (exe_stem(p), name_stem(p), arg1_stem(p));
    names.iter().any(|n| {
        let n = n.to_lowercase();
        exe.as_deref() == Some(n.as_str())
            || name == n
            || (!n.contains(' ') && arg1.as_deref() == Some(n.as_str()))
    })
}

pub fn mem_info(s: &Snapshot) -> MemInfo {
    let m = s.mem;
    MemInfo {
        total: m.total,
        available: m.available,
        swap_used: m.swap_used,
        swap_total: m.swap_total,
        pressure: platform::memory_pressure(m.available, m.total, platform::commit_pct()),
        groups: group(&s.procs, Os::current()),
    }
}

fn known_windows_app(p: &Proc, exe: &str) -> Option<&'static str> {
    [file_name(exe).to_lowercase(), p.name.to_lowercase()]
        .iter()
        .find_map(|k| match k.as_str() {
            "chrome.exe" => Some("Google Chrome"),
            "msedge.exe" => Some("Microsoft Edge"),
            "code.exe" => Some("VS Code"),
            "cursor.exe" => Some("Cursor"),
            "vmmem" | "vmmemwsl" => Some("WSL / Docker VM"),
            "claude.exe" => Some("Claude Code"),
            "node.exe" => Some("Node.js"),
            _ => None,
        })
}

/// `...\Program Files*\X\...` or `...\AppData\Local\Programs\X\...` gives `X`.
fn windows_install_dir(parts: &[&str]) -> Option<String> {
    // The last part is the exe itself, so X must be a directory.
    let dirs = &parts[..parts.len().saturating_sub(1)];
    (0..dirs.len().saturating_sub(1)).find_map(|i| {
        let c = dirs[i].to_lowercase();
        let programs = c == "programs"
            && i >= 2
            && dirs[i - 1].eq_ignore_ascii_case("local")
            && dirs[i - 2].eq_ignore_ascii_case("appdata");
        (c.starts_with("program files") || programs).then(|| dirs[i + 1].to_string())
    })
}

fn group_name(p: &Proc, os: Os) -> String {
    let exe = exe_str(p);
    if exe.to_lowercase().contains("anthropic.claude-code")
        || p.cmd
            .iter()
            .any(|a| a.to_lowercase().contains("anthropic.claude-code"))
    {
        return "Claude Code (VS Code)".into();
    }
    let parts: Vec<&str> = exe.split(['/', '\\']).collect();
    let by_stem = || {
        if exe.is_empty() {
            p.name.clone()
        } else {
            stem_of(&exe).to_string()
        }
    };
    match os {
        Os::Macos => parts
            .iter()
            .find_map(|c| c.strip_suffix(".app").filter(|n| !n.is_empty()))
            .map(str::to_string)
            .unwrap_or_else(by_stem),
        // The exe map goes before the install dir: chrome.exe in Program Files is
        // "Google Chrome", not "Google".
        Os::Windows => known_windows_app(p, &exe)
            .map(str::to_string)
            .or_else(|| windows_install_dir(&parts))
            .unwrap_or_else(by_stem),
    }
}

/// App groups, memory summed, biggest first.
pub fn group(procs: &[Proc], os: Os) -> Vec<AppGroup> {
    let mut m: HashMap<String, AppGroup> = HashMap::new();
    for p in procs {
        let name = group_name(p, os);
        let g = m.entry(name.clone()).or_insert(AppGroup {
            name,
            mem: 0,
            procs: 0,
        });
        g.mem += p.mem;
        g.procs += 1;
    }
    let mut v: Vec<AppGroup> = m.into_values().collect();
    v.sort_by(|a, b| b.mem.cmp(&a.mem).then_with(|| a.name.cmp(&b.name)));
    v
}

/// A daemon entry is `<stem> [arg ...]`: the stem must match and every arg must be in argv[1..].
fn is_known_daemon(p: &Proc, rules: &Rules) -> bool {
    rules.known_daemons.iter().any(|d| {
        let mut w = d.split_whitespace();
        w.next()
            .is_some_and(|first| stem_matches(p, &[first.to_string()]))
            && w.all(|a| p.cmd.iter().skip(1).any(|c| c == a))
    })
}

fn is_gui(p: &Proc, os: Os) -> bool {
    let exe = exe_str(p);
    match os {
        Os::Macos => exe.contains(".app/Contents/MacOS/"),
        Os::Windows => {
            let under = |v: &str| {
                std::env::var_os(v)
                    .is_some_and(|d| platform::inside(Path::new(&exe), Path::new(&d)))
            };
            exe.split(['/', '\\'])
                .any(|c| c.to_lowercase().starts_with("program files"))
                || under("ProgramFiles")
                || under("ProgramFiles(x86)")
        }
    }
}

fn mcp_like(p: &Proc) -> bool {
    exe_stem(p)
        .iter()
        .chain(arg1_stem(p).iter())
        .any(|s| s.contains("mcp"))
}

fn now_secs(ctx: &Ctx) -> u64 {
    ctx.now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pids of `p`'s ancestors within `all` (cycle-safe).
fn ancestors(p: &Proc, all: &[Proc]) -> Vec<u32> {
    let by: HashMap<u32, &Proc> = all.iter().map(|p| (p.pid, p)).collect();
    let mut seen = HashSet::from([p.pid]);
    let mut out = vec![];
    let mut cur = p.parent;
    while let Some(pp) = cur.filter(|x| seen.insert(*x)) {
        out.push(pp);
        cur = by.get(&pp).and_then(|q| q.parent);
    }
    out
}

pub fn is_orphan(ctx: &Ctx, p: &Proc, all: &[Proc]) -> bool {
    let rules = ctx.rules;
    let parent_gone = match ctx.os {
        Os::Macos => p.parent == Some(1) && !p.launchd_managed,
        Os::Windows => p
            .parent
            .is_some_and(|pp| match all.iter().find(|q| q.pid == pp) {
                None => true,
                Some(q) => q.start_time > p.start_time,
            }),
    };
    parent_gone
        && p.uid_matches_me
        && now_secs(ctx).saturating_sub(p.start_time) > 3600
        && (stem_matches(p, &rules.dev_process_patterns) || mcp_like(p))
        && !is_known_daemon(p, rules)
        && p.pid != ctx.pid
        && all
            .iter()
            .find(|q| q.pid == ctx.pid)
            .is_none_or(|me| !ancestors(me, all).contains(&p.pid))
        && !is_gui(p, ctx.os)
}

pub fn findings(ctx: &Ctx, s: &Snapshot) -> Vec<Finding> {
    let mut out = vec![];
    let now = now_secs(ctx);
    let mac = ctx.os == Os::Macos;
    for p in s.procs.iter().filter(|p| is_orphan(ctx, p, &s.procs)) {
        out.push(Finding {
            id: finding_id(Category::Process, &format!("{}:{}", p.pid, p.start_time)),
            category: if mac {
                Category::Process
            } else {
                Category::Advice
            },
            title: format!("{} (pid {}) left running", p.name, p.pid),
            path: None,
            project: None,
            owner_processes: vec![],
            bytes: p.mem,
            bytes_estimate: false,
            idle_days: None,
            tier: Tier::Review,
            reason: if mac {
                format!(
                    "Parent process is gone; started {} h ago",
                    now.saturating_sub(p.start_time) / 3600
                )
            } else {
                format!("End it in Task Manager: {}, pid {}", p.name, p.pid)
            },
            rebuild: None,
            method: if mac {
                Method::Signal {
                    pid: p.pid,
                    start_time: p.start_time,
                }
            } else {
                Method::None
            },
        });
    }
    duplicate_mcp(s, &mut out);
    let g = group(&s.procs, ctx.os);
    let big = |n: &str| g.iter().find(|a| a.name == n).filter(|a| a.mem > 500 * MIB);
    if let (Some(c), Some(e)) = (big("Google Chrome"), big("Microsoft Edge")) {
        out.push(advice(
            "chromium-two",
            "Two Chromium browsers are both using a lot of memory".into(),
            c.mem + e.mem,
            "Google Chrome and Microsoft Edge each use over 500 MB. Pick one for daily use and close the other.".into(),
        ));
    }
    out
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

struct McpGroup {
    server: String,
    mem: u64,
    count: u32,
    sessions: HashSet<u32>,
}

/// A Claude session: `claude` by exe/name/argv[1] stem, or argv[0] file stem (native installs
/// whose exe is a version number).
fn is_claude(p: &Proc) -> bool {
    stem_matches(p, &["claude".to_string()])
        || p.cmd
            .first()
            .is_some_and(|a| stem_of(a).eq_ignore_ascii_case("claude"))
}

fn is_shell(p: &Proc) -> bool {
    const SHELLS: [&str; 7] = ["sh", "bash", "zsh", "fish", "pwsh", "powershell", "cmd"];
    let (e, n) = (exe_stem(p), name_stem(p));
    SHELLS.iter().any(|s| e.as_deref() == Some(*s) || n == *s)
}

/// Own-user, non-shell, non-Claude processes within 2 parent hops of a live Claude process
/// that run the same command line under >= 2 distinct Claude processes.
fn duplicate_mcp(s: &Snapshot, out: &mut Vec<Finding>) {
    let by: HashMap<u32, &Proc> = s.procs.iter().map(|p| (p.pid, p)).collect();
    let claude_at = |pid: Option<u32>| pid.filter(|id| by.get(id).is_some_and(|q| is_claude(q)));
    let mut groups: HashMap<String, McpGroup> = HashMap::new();
    for p in s
        .procs
        .iter()
        .filter(|p| p.uid_matches_me && !p.cmd.is_empty() && !is_claude(p) && !is_shell(p))
    {
        let session = claude_at(p.parent)
            .or_else(|| claude_at(p.parent.and_then(|pp| by.get(&pp)).and_then(|q| q.parent)));
        let Some(session) = session else { continue };
        let mut argv: Vec<&str> = p.cmd.iter().map(String::as_str).collect();
        argv[0] = file_name(argv[0]);
        let server = argv[1..]
            .iter()
            .rev()
            .map(|a| stem_of(a))
            .find(|n| !n.starts_with('-') && (n.contains("mcp") || n.contains("server")))
            .unwrap_or(argv[0])
            .to_string();
        let g = groups.entry(argv.join(" ")).or_insert(McpGroup {
            server,
            mem: 0,
            count: 0,
            sessions: HashSet::new(),
        });
        g.mem += p.mem;
        g.count += 1;
        g.sessions.insert(session);
    }
    let mut v: Vec<_> = groups
        .into_iter()
        .filter(|(_, g)| g.sessions.len() >= 2)
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, g) in v {
        out.push(advice(
            &format!("dup-mcp:{key}"),
            format!("{} copies of {} under {} Claude sessions", g.count, g.server, g.sessions.len()),
            g.mem,
            "Each Claude session starts its own copy. Share one server between sessions, or close idle sessions.".into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::FakeRunner;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: u64 = 1_000_000;
    const OLD: u64 = NOW - 7200;

    fn proc(pid: u32, parent: Option<u32>, exe: &str, cmd: &[&str]) -> Proc {
        let name = exe.rsplit(['/', '\\']).next().unwrap().to_string();
        Proc {
            pid,
            parent,
            uid_matches_me: true,
            mem: 100 * MIB,
            start_time: OLD,
            exe: Some(PathBuf::from(exe)),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            name,
            ..Proc::default()
        }
    }

    fn with_ctx<R>(os: Os, f: impl FnOnce(&Ctx) -> R) -> R {
        let run = FakeRunner::new();
        let rules = crate::rules::builtin();
        let dirs = platform::KnownDirs {
            home: PathBuf::from("/h"),
            local_app_data: None,
            app_data: None,
            temp: PathBuf::from("/t"),
            personal: vec![],
            cloud_roots: vec![],
        };
        let now = UNIX_EPOCH + Duration::from_secs(NOW);
        let ctx = Ctx::new(os, dirs, PathBuf::from("/d"), &run, &rules, now, 9999);
        f(&ctx)
    }

    fn orphan(os: Os, p: &Proc, all: &[Proc]) -> bool {
        with_ctx(os, |c| is_orphan(c, p, all))
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn groups_chrome_helpers_mac_and_windows_exe_map() {
        let mac = [
            proc(
                1,
                None,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                &[],
            ),
            proc(
                2,
                Some(1),
                "/Applications/Google Chrome.app/Contents/Frameworks/X.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
                &[],
            ),
            proc(3, None, "/usr/bin/vim", &[]),
        ];
        let g = group(&mac, Os::Macos);
        assert_eq!(
            g[0],
            AppGroup {
                name: "Google Chrome".into(),
                mem: 200 * MIB,
                procs: 2
            }
        );
        assert_eq!(g[1].name, "vim");
        let win = [
            proc(
                1,
                None,
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                &[],
            ),
            proc(
                2,
                None,
                r"C:\Users\x\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                &[],
            ),
            proc(3, None, r"C:\Program Files\Foo\bin\foo.exe", &[]),
            proc(
                4,
                None,
                r"C:\Users\x\AppData\Local\Programs\Bar\bar.exe",
                &[],
            ),
            proc(5, None, r"C:\tools\thing.exe", &[]),
            Proc {
                name: "vmmem".into(),
                mem: 1,
                ..Proc::default()
            },
            proc(7, None, r"C:\x\NODE.EXE", &[]),
        ];
        let n: Vec<String> = group(&win, Os::Windows)
            .into_iter()
            .map(|g| g.name)
            .collect();
        for want in [
            "Google Chrome",
            "VS Code",
            "Foo",
            "Bar",
            "thing",
            "WSL / Docker VM",
            "Node.js",
        ] {
            assert!(n.contains(&want.to_string()), "{want} in {n:?}");
        }
        let ext = proc(
            8,
            None,
            "/x/node",
            &[
                "node",
                "/h/.vscode/extensions/anthropic.claude-code-1.0/cli.js",
            ],
        );
        assert_eq!(group(&[ext], Os::Macos)[0].name, "Claude Code (VS Code)");
    }

    #[test]
    fn windows_orphan_by_dead_or_younger_parent() {
        let c = proc(10, Some(5), r"C:\n\node.exe", &["node.exe", "x.js"]);
        assert!(
            orphan(Os::Windows, &c, std::slice::from_ref(&c)),
            "parent absent"
        );
        let mut par = proc(5, None, r"C:\Windows\explorer.exe", &[]);
        par.start_time = OLD + 10;
        assert!(
            orphan(Os::Windows, &c, &[c.clone(), par.clone()]),
            "pid reuse"
        );
        par.start_time = OLD - 10;
        assert!(
            !orphan(Os::Windows, &c, &[c.clone(), par]),
            "live older parent"
        );
    }

    #[test]
    fn macos_orphan_by_ppid_1() {
        let c = proc(10, Some(1), "/usr/local/bin/node", &["node", "server.js"]);
        assert!(orphan(Os::Macos, &c, std::slice::from_ref(&c)));
        let c2 = proc(11, Some(42), "/usr/local/bin/node", &["node"]);
        assert!(!orphan(Os::Macos, &c2, std::slice::from_ref(&c2)));
    }

    #[test]
    fn known_daemon_not_flagged() {
        let pm2 = proc(10, Some(1), "/usr/local/bin/node", &["pm2"]);
        assert!(!orphan(
            Os::Macos,
            &Proc {
                name: "pm2".into(),
                exe: Some("/x/pm2".into()),
                ..pm2.clone()
            },
            &[]
        ));
        let d = proc(11, Some(1), "/x/ollama", &["ollama", "serve"]);
        assert!(!orphan(Os::Macos, &d, &[]));
        let m = proc(
            12,
            Some(1),
            "/x/codebase-memory-mcp",
            &["codebase-memory-mcp", "--cbm-daemon-internal"],
        );
        assert!(!orphan(Os::Macos, &m, &[]));
        let m2 = proc(
            13,
            Some(1),
            "/x/codebase-memory-mcp",
            &["codebase-memory-mcp"],
        );
        assert!(
            orphan(Os::Macos, &m2, &[]),
            "same exe without the daemon flag is an mcp orphan"
        );
    }

    #[test]
    fn launchd_managed_not_flagged() {
        let mut c = proc(10, Some(1), "/usr/local/bin/node", &["node", "s.js"]);
        assert!(orphan(Os::Macos, &c, &[]));
        c.launchd_managed = true;
        assert!(!orphan(Os::Macos, &c, &[]));
    }

    #[test]
    fn dev_pattern_is_exact_stem() {
        let m = |p: &Proc, n: &[&str]| stem_matches(p, &names(n));
        assert!(!m(
            &proc(1, None, "/bin/uvicorn", &["uvicorn", "app:a"]),
            &["uv"]
        ));
        assert!(!m(
            &proc(1, None, "/Users/x/node-tools/foo", &["foo"]),
            &["node"]
        ));
        assert!(m(
            &proc(1, None, "/bin/node", &["node", "/a/b/npm-cli.js", "i"]),
            &["npm-cli"]
        ));
        assert!(m(&proc(1, None, "/bin/NODE", &["node"]), &["node"]));
        assert!(m(&proc(1, None, r"C:\n\node.exe", &[]), &["node"]));
        assert!(!m(
            &proc(1, None, "/bin/node", &["node", "--inspect", "x"]),
            &["--inspect"]
        ));
        assert!(m(&proc(1, None, "/A/Code Helper", &[]), &["Code Helper"]));
        assert!(!m(
            &proc(1, None, "/bin/node", &["node", "Code Helper"]),
            &["Code Helper"]
        ));
    }

    #[test]
    fn other_users_and_young_procs_not_flagged() {
        let mut c = proc(10, Some(1), "/usr/local/bin/node", &["node", "s.js"]);
        c.uid_matches_me = false;
        assert!(!orphan(Os::Macos, &c, &[]));
        c.uid_matches_me = true;
        c.start_time = NOW - 3600;
        assert!(
            !orphan(Os::Macos, &c, &[]),
            "exactly 1 h is not more than 1 h"
        );
        c.start_time = NOW - 3601;
        assert!(orphan(Os::Macos, &c, &[]));
        let me = proc(9999, Some(10), "/bin/devaudit", &[]);
        assert!(
            !orphan(Os::Macos, &c, &[c.clone(), me]),
            "ancestor of ctx.pid"
        );
        let gui = proc(11, Some(1), "/A/Cursor.app/Contents/MacOS/node", &["node"]);
        assert!(!orphan(Os::Macos, &gui, &[]));
        let gui = proc(
            12,
            Some(99),
            r"C:\Program Files\App\node.exe",
            &["node.exe"],
        );
        assert!(!orphan(Os::Windows, &gui, &[]));
        let other = proc(13, Some(1), "/bin/vim", &["vim"]);
        assert!(!orphan(Os::Macos, &other, &[]));
    }

    #[test]
    fn windows_orphan_is_advice_not_signal() {
        let c = proc(10, Some(5), r"C:\n\node.exe", &["node.exe", "x.js"]);
        let s = Snapshot {
            procs: vec![c],
            ..Snapshot::default()
        };
        let f = with_ctx(Os::Windows, |ctx| findings(ctx, &s));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].method, Method::None);
        assert_eq!(f[0].category, Category::Advice);
        assert_eq!(f[0].tier, Tier::Review);
        assert_eq!(f[0].reason, "End it in Task Manager: node.exe, pid 10");
        let m = proc(10, Some(1), "/n/node", &["node", "x.js"]);
        let s = Snapshot {
            procs: vec![m],
            ..Snapshot::default()
        };
        let f = with_ctx(Os::Macos, |ctx| findings(ctx, &s));
        assert_eq!(
            f[0].method,
            Method::Signal {
                pid: 10,
                start_time: OLD
            }
        );
        assert_eq!(f[0].category, Category::Process);
        assert_eq!(f[0].title, "node (pid 10) left running");
        assert_eq!(f[0].reason, "Parent process is gone; started 2 h ago");
        assert_eq!(f[0].id, finding_id(Category::Process, &format!("10:{OLD}")));
    }

    fn dup(procs: Vec<Proc>) -> Vec<Finding> {
        let s = Snapshot {
            procs,
            ..Snapshot::default()
        };
        with_ctx(Os::Macos, |c| findings(c, &s))
            .into_iter()
            .filter(|f| f.title.contains("copies of"))
            .collect()
    }

    fn sessions() -> Vec<Proc> {
        vec![
            proc(101, Some(50), "/bin/claude", &["claude"]),
            proc(102, Some(50), "/bin/claude", &["claude"]),
        ]
    }

    #[test]
    fn dup_direct_child_without_mcp_in_name() {
        let mut v = sessions();
        for (pid, par) in [(11, 101), (12, 102)] {
            v.push(proc(
                pid,
                Some(par),
                "/opt/node",
                &[
                    "node",
                    "/u/.npm/_npx/ab12/node_modules/.bin/server-sequential-thinking",
                ],
            ));
        }
        let f = dup(v);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(
            f[0].title,
            "2 copies of server-sequential-thinking under 2 Claude sessions"
        );
    }

    #[test]
    fn dup_npx_wrapper_and_grandchild() {
        let mut v = sessions();
        for (w, g, par) in [(11, 21, 101), (12, 22, 102)] {
            v.push(proc(
                w,
                Some(par),
                "/opt/node",
                &[
                    "node",
                    "/n/npx-cli.js",
                    "-y",
                    "@modelcontextprotocol/server-filesystem@latest",
                    "/p",
                ],
            ));
            v.push(proc(
                g,
                Some(w),
                "/opt/node",
                &["node", "/n/.bin/mcp-server-filesystem", "/p"],
            ));
        }
        // a third wrapper with a different path must not join the group
        v.push(proc(
            13,
            Some(102),
            "/opt/node",
            &["node", "/n/npx-cli.js", "-y", "x", "/other"],
        ));
        let f = dup(v);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|f| f.title.starts_with("2 copies of")));
    }

    #[test]
    fn dup_uvx_python_and_single_session_and_shell() {
        let mut v = sessions();
        for (pid, par) in [(11, 101), (12, 102)] {
            v.push(proc(
                pid,
                Some(par),
                "/u/.local/bin/uvx",
                &["/u/.local/bin/uvx", "mcp-server-fetch"],
            ));
        }
        assert_eq!(dup(v).len(), 1);
        // only one session
        let mut v = sessions();
        v.push(proc(11, Some(101), "/u/uvx", &["uvx", "mcp-server-fetch"]));
        v.push(proc(12, Some(101), "/u/uvx", &["uvx", "mcp-server-fetch"]));
        assert!(dup(v).is_empty());
        // shells
        let mut v = sessions();
        for (pid, par) in [(11, 101), (12, 102)] {
            v.push(proc(pid, Some(par), "/bin/zsh", &["zsh", "-l"]));
        }
        assert!(dup(v).is_empty());
    }

    #[test]
    fn native_claude_with_version_exe_is_a_session() {
        let mut c = proc(
            101,
            Some(50),
            "/Users/u/.local/share/claude/versions/2.1.0",
            &["claude"],
        );
        c.name = "2.1.0".into();
        assert!(is_claude(&c));
        let mut c2 = c.clone();
        c2.pid = 102;
        let mut v = vec![c, c2];
        for (pid, par) in [(11, 101), (12, 102)] {
            v.push(proc(pid, Some(par), "/u/uvx", &["uvx", "mcp-server-fetch"]));
        }
        assert_eq!(dup(v).len(), 1);
    }

    #[test]
    fn two_big_browsers_is_advice() {
        let mut a = proc(
            1,
            None,
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            &[],
        );
        let mut b = proc(
            2,
            None,
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            &[],
        );
        a.mem = 501 * MIB;
        b.mem = 501 * MIB;
        let s = Snapshot {
            procs: vec![a.clone(), b.clone()],
            ..Snapshot::default()
        };
        assert_eq!(with_ctx(Os::Macos, |c| findings(c, &s)).len(), 1);
        b.mem = 500 * MIB;
        let s = Snapshot {
            procs: vec![a, b],
            ..Snapshot::default()
        };
        assert!(with_ctx(Os::Macos, |c| findings(c, &s)).is_empty());
    }

    #[test]
    fn snapshot_smoke() {
        let s = snapshot();
        let me = s
            .procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("self");
        assert!(me.uid_matches_me && me.mem > 0 && me.start_time > 0);
        assert!(s.mem.total > 0);
        assert!(start_time_of(std::process::id()).is_some());
        assert!(mem_info(&s).total > 0);
    }
}
