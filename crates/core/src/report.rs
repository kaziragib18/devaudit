//! Report assembly, persistence, history and growth.
//!
//! Files in the data dir:
//! - `report.json`: the last `Report`, pretty JSON, written atomically (temp file, then rename).
//! - `history.csv`: one row per saved scan, oldest first, at most [`MAX_HISTORY_ROWS`] rows.
//!   The header is `scanned_at,ProjectBuild,PackageCache,BrowserCache,AiTool,Docker,EditorData,Temp,Process,Advice`
//!   (`scanned_at` in seconds since the Unix epoch, then one column per `Category` in
//!   declaration order). Each cell is the sum of `bytes` of the findings in that category that
//!   have an actionable method (never `Method::None`: Report/Advice findings carry bytes but
//!   are not reclaimable). A file with a different header is started afresh.
//!
//! Growth compares the current report with the newest history row that is not the
//! current scan itself (same `scanned_at`), so it gives the same answer before and
//! after `save`.

use crate::guard::{Guard, GuardError};
use crate::model::{Category, DiskInfo, Finding, Method, Os, Report, Skipped};
use crate::platform::{self, KnownDirs};
use crate::{Ctx, disk, docker, procs, projects, targets};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

pub const MAX_HISTORY_ROWS: usize = 5000;
const REPORT_FILE: &str = "report.json";
const HISTORY_FILE: &str = "history.csv";
const CATEGORIES: [Category; 9] = [
    Category::ProjectBuild,
    Category::PackageCache,
    Category::BrowserCache,
    Category::AiTool,
    Category::Docker,
    Category::EditorData,
    Category::Temp,
    Category::Process,
    Category::Advice,
];

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct Growth {
    pub category: Category,
    pub delta_bytes: i64,
}

/// Tier first (Safe, Review, Protected), then biggest first; id keeps it deterministic.
fn sort_findings(f: &mut [Finding]) {
    f.sort_by(|a, b| (a.tier, Reverse(a.bytes), &a.id).cmp(&(b.tier, Reverse(b.bytes), &b.id)));
}

fn unseen(used: u64, home: u64, apps: u64, images: u64) -> u64 {
    used.saturating_sub(home)
        .saturating_sub(apps)
        .saturating_sub(images)
}

/// Bytes of the Windows Docker/WSL `*.vhdx` findings that `usage(home)` and `usage(apps)` did
/// not already count, i.e. images outside both. One inside either is already part of
/// the scanned total and must not be subtracted again.
fn counted_images(findings: &[Finding], home: &Path, apps: &Path) -> u64 {
    findings
        .iter()
        .filter(|f| {
            f.path.as_deref().is_some_and(|p| {
                p.extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("vhdx"))
                    && !platform::inside(p, home)
                    && !platform::inside(p, apps)
            })
        })
        .map(|f| f.bytes)
        .sum()
}

fn trash_bytes(ctx: &Ctx, cancel: &AtomicBool, notes: &mut Vec<String>) -> u64 {
    match ctx.os {
        Os::Macos => {
            let trash = ctx.home.join(".Trash");
            match fs::read_dir(&trash) {
                Ok(_) => disk::usage(&trash, &[], cancel).bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                Err(e) => {
                    notes.push(format!("Couldn't read the Trash ({e}); shown as 0."));
                    0
                }
            }
        }
        Os::Windows => {
            let root = ctx.home.ancestors().last().unwrap_or(&ctx.home);
            platform::recycle_bin_bytes(root).unwrap_or_else(|e| {
                notes.push(format!("Couldn't read the Recycle Bin ({e}); shown as 0."));
                0
            })
        }
    }
}

fn disk_info(
    ctx: &Ctx,
    cancel: &AtomicBool,
    images: u64,
    notes: &mut Vec<String>,
    skipped: &mut Vec<Skipped>,
) -> DiskInfo {
    let (total, free) = platform::volume_space(&ctx.home).unwrap_or_else(|e| {
        notes.push(format!("Couldn't read disk space ({e})."));
        (0, 0)
    });
    let home = disk::usage(&ctx.home, &[], cancel);
    let apps = disk::usage(&ctx.dirs.apps_dir, &[], cancel);
    skipped.extend(home.skipped);
    skipped.extend(apps.skipped);
    if home.cancelled || apps.cancelled {
        notes.push("The scan was cancelled; disk totals are partial.".into());
    }
    let scanned = home.bytes + apps.bytes;
    DiskInfo {
        total,
        free,
        scanned,
        unseen: unseen(
            total.saturating_sub(free),
            home.bytes,
            apps.bytes,
            if ctx.os == Os::Windows { images } else { 0 },
        ),
        trash: trash_bytes(ctx, cancel, notes),
    }
}

pub(crate) fn build_guard(ctx: &Ctx, snap: &procs::Snapshot) -> Result<Guard, GuardError> {
    Guard::build(snap, ctx.run, ctx.rules.recent_days, ctx.now)
}

/// Runs every scanner in order and assembles the report. Read-only.
pub fn scan(ctx: &Ctx, cancel: &AtomicBool, progress: &dyn Fn(&str)) -> Report {
    let mut notes = vec![];
    let mut skipped = vec![];
    let mut findings = vec![];
    if let Some(e) = &ctx.ctx_error {
        notes.push(format!("Cleaning is disabled: {e}"));
    }
    progress("Reading running programs");
    let snap = procs::snapshot();
    let mem = procs::mem_info(&snap);
    let guard = build_guard(ctx, &snap);
    let g = guard.as_ref();
    if g.is_err() {
        notes.push("Process data is unavailable, so project folders are protected.".into());
    }
    findings.extend(procs::findings(ctx, &snap));

    let stop = || cancel.load(Ordering::Relaxed);
    let (roots, warnings) = projects::roots(ctx);
    notes.extend(warnings);
    if !stop() {
        progress("Scanning project folders");
        let (f, s) = projects::findings(ctx, g, cancel);
        findings.extend(f);
        skipped.extend(s);
    }
    if !stop() {
        progress("Scanning caches and temp files");
        let (f, s) = targets::target_findings(ctx, cancel);
        findings.extend(f);
        skipped.extend(s);
    }
    if !stop() {
        progress("Scanning AI tools");
        findings.extend(targets::claude_findings(ctx, g, &roots));
        progress("Checking WSL");
        findings.extend(targets::wsl_findings(ctx));
    }
    let swap_pct = (mem.swap_used.saturating_mul(100))
        .checked_div(mem.swap_total)
        .map_or(0, |p| p.min(100) as u8);
    progress("Checking Docker");
    let d = docker::scan(ctx, g, mem.total, swap_pct);
    findings.extend(d.findings);
    notes.extend(d.notes);
    findings.extend(targets::advice_findings(ctx, &mem));

    progress("Measuring the disk");
    let images = counted_images(&findings, &ctx.home, &ctx.dirs.apps_dir);
    let disk = disk_info(ctx, cancel, images, &mut notes, &mut skipped);
    sort_findings(&mut findings);
    Report {
        os: ctx.os,
        scanned_at: ctx
            .now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        disk,
        memory: mem,
        findings,
        skipped,
        notes,
    }
}

/// The data dir for these known dirs, created if needed, private to the user.
pub fn ensure_data_dir(d: &KnownDirs) -> Result<PathBuf, String> {
    let dir = platform::data_dir(d);
    prepare_dir(&dir)?;
    Ok(dir)
}

fn prepare_dir(dir: &Path) -> Result<(), String> {
    let e = |e: std::io::Error| format!("{}: {e}", dir.display());
    fs::create_dir_all(dir).map_err(e)?;
    platform::set_private_dir(dir).map_err(e)
}

/// Temp file in the same dir, then rename over the old file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let e = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let res = (|| {
        let mut f = platform::create_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // Replacing the old file is intended here.
        fs::rename(&tmp, path)
    })();
    if let Err(err) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e(err));
    }
    Ok(())
}

fn header() -> String {
    let mut h = String::from("scanned_at");
    for c in CATEGORIES {
        h.push_str(&format!(",{c:?}"));
    }
    h
}

fn category_bytes(r: &Report) -> Vec<u64> {
    CATEGORIES
        .iter()
        .map(|c| {
            r.findings
                .iter()
                .filter(|f| f.category == *c && f.method != Method::None)
                .map(|f| f.bytes)
                .sum()
        })
        .collect()
}

type Row = (u64, Vec<u64>);

/// (scanned_at, bytes per category) of every well-formed row, oldest first. A missing
/// file or a foreign header is an empty history; any other failure is an error.
fn read_history_checked(data_dir: &Path) -> Result<Vec<Row>, String> {
    let path = data_dir.join(HISTORY_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut lines = text.lines();
    if lines.next() != Some(header().as_str()) {
        return Ok(vec![]);
    }
    Ok(lines
        .filter_map(|l| {
            let v: Vec<u64> = l
                .split(',')
                .map(|c| c.parse().ok())
                .collect::<Option<_>>()?;
            (v.len() == CATEGORIES.len() + 1).then(|| (v[0], v[1..].to_vec()))
        })
        .collect())
}

fn append_history(data_dir: &Path, report: &Report) -> Result<(), String> {
    // Never overwrite a history that couldn't be read.
    let mut rows = read_history_checked(data_dir)?;
    rows.push((report.scanned_at, category_bytes(report)));
    let skip = rows.len().saturating_sub(MAX_HISTORY_ROWS);
    let mut out = header();
    out.push('\n');
    for (t, b) in rows.into_iter().skip(skip) {
        out.push_str(&t.to_string());
        for x in b {
            out.push_str(&format!(",{x}"));
        }
        out.push('\n');
    }
    write_atomic(&data_dir.join(HISTORY_FILE), out.as_bytes())
}

/// Writes `report.json` (atomically) and appends a `history.csv` row.
pub fn save(report: &Report, data_dir: &Path) -> Result<(), String> {
    prepare_dir(data_dir)?;
    let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    write_atomic(&data_dir.join(REPORT_FILE), json.as_bytes())?;
    append_history(data_dir, report)
}

pub fn load_last(data_dir: &Path) -> Option<Report> {
    serde_json::from_slice(&fs::read(data_dir.join(REPORT_FILE)).ok()?).ok()
}

/// Per-category change in reclaimable bytes since the previous scan; unchanged
/// categories and `Process` (memory, not disk) are left out. Empty without history.
pub fn growth(data_dir: &Path, current: &Report) -> Vec<Growth> {
    let prev = read_history_checked(data_dir)
        .unwrap_or_default()
        .into_iter()
        .rev()
        .find(|(t, _)| *t != current.scanned_at);
    let Some((_, before)) = prev else {
        return vec![];
    };
    CATEGORIES
        .iter()
        .zip(category_bytes(current).into_iter().zip(before))
        .filter(|(c, (now, old))| **c != Category::Process && now != old)
        .map(|(c, (now, old))| Growth {
            category: *c,
            delta_bytes: now as i64 - old as i64,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AppGroup, FileId, MemInfo, Pressure, Tier, finding_id};
    use crate::platform::KnownDirs;
    use crate::rules;
    use crate::run::SystemRunner;
    use std::time::SystemTime;

    fn finding(cat: Category, key: &str, bytes: u64, tier: Tier, method: Method) -> Finding {
        Finding {
            id: finding_id(cat, key),
            category: cat,
            title: format!("Item {key}"),
            path: Some(PathBuf::from(format!("/x/{key}"))),
            project: None,
            owner_processes: vec![],
            bytes,
            bytes_estimate: false,
            idle_days: Some(3),
            tier,
            reason: "because".into(),
            rebuild: Some("rebuild it".into()),
            method,
        }
    }

    fn report(at: u64, findings: Vec<Finding>) -> Report {
        Report {
            os: Os::Macos,
            scanned_at: at,
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
            skipped: vec![Skipped {
                path: PathBuf::from("/x/skipped"),
                why: "can't read".into(),
            }],
            notes: vec!["a note".into()],
        }
    }

    fn dirs(home: &Path) -> KnownDirs {
        KnownDirs {
            home: home.to_path_buf(),
            local_app_data: Some(home.join("AppData").join("Local")),
            app_data: None,
            temp: home.join("tmp"),
            personal: vec![],
            cloud_roots: vec![],
            apps_dir: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn report_file_private() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        let dir = ensure_data_dir(&d).unwrap();
        assert!(dir.starts_with(tmp.path()));
        save(&report(1, vec![]), &dir).unwrap();
        assert!(dir.join("report.json").is_file());
        assert!(dir.join("history.csv").is_file());
        assert!(load_last(&dir).is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join("report.json")), 0o600);
            assert_eq!(mode(&dir.join("history.csv")), 0o600);
        }
        // No temp file is left behind.
        assert!(!dir.join("report.json.tmp").exists());
    }

    #[test]
    fn save_failure_is_error_not_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        fs::write(&blocker, "x").unwrap();
        assert!(save(&report(1, vec![]), &blocker.join("data")).is_err());
        assert!(save(&report(1, vec![]), &blocker).is_err());
        assert_eq!(load_last(&blocker.join("data")), None);
    }

    #[test]
    fn growth_reports_delta_per_category() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let f = |c, b, m| finding(c, "a", b, Tier::Safe, m);
        let cmd = || Method::Command { argv: vec![] };
        let first = report(
            100,
            vec![
                f(Category::PackageCache, 1000, cmd()),
                f(Category::Docker, 500, cmd()),
                f(Category::Advice, 9999, Method::None),
                f(Category::Process, 7, cmd()),
            ],
        );
        assert!(growth(dir, &first).is_empty(), "no history yet");
        save(&first, dir).unwrap();
        assert!(
            growth(dir, &first).is_empty(),
            "the current row is not the baseline"
        );
        let second = report(
            200,
            vec![
                f(Category::PackageCache, 4000, cmd()),
                f(Category::Docker, 500, cmd()),
                f(Category::Temp, 50, cmd()),
                f(Category::Advice, 1, Method::None),
                f(Category::Process, 900, cmd()),
            ],
        );
        let expect = vec![
            Growth {
                category: Category::PackageCache,
                delta_bytes: 3000,
            },
            Growth {
                category: Category::Temp,
                delta_bytes: 50,
            },
        ];
        assert_eq!(growth(dir, &second), expect, "before save");
        save(&second, dir).unwrap();
        assert_eq!(growth(dir, &second), expect, "after save");
        // Shrinking is negative.
        let third = report(300, vec![f(Category::PackageCache, 100, cmd())]);
        assert!(growth(dir, &third).contains(&Growth {
            category: Category::PackageCache,
            delta_bytes: -3900
        }));
        let csv = fs::read_to_string(dir.join("history.csv")).unwrap();
        assert!(csv.starts_with("scanned_at,ProjectBuild,PackageCache,"));
        assert_eq!(csv.lines().count(), 3);
    }

    #[test]
    fn history_with_foreign_header_starts_afresh() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("history.csv"), "junk\n1,2,3\n").unwrap();
        save(&report(5, vec![]), tmp.path()).unwrap();
        assert_eq!(read_history_checked(tmp.path()).unwrap().len(), 1);
    }

    #[test]
    fn findings_sorted_by_tier_then_size() {
        let m = || Method::None;
        let mut v = vec![
            finding(Category::Temp, "a", 10, Tier::Protected, m()),
            finding(Category::Temp, "b", 5, Tier::Safe, m()),
            finding(Category::Temp, "c", 50, Tier::Review, m()),
            finding(Category::Temp, "d", 90, Tier::Safe, m()),
            finding(Category::Temp, "e", 500, Tier::Protected, m()),
        ];
        sort_findings(&mut v);
        let order: Vec<_> = v.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(order, ["Item d", "Item b", "Item c", "Item e", "Item a"]);
    }

    #[test]
    fn unseen_is_floored_and_images_inside_home_are_not_subtracted() {
        assert_eq!(unseen(100, 30, 20, 10), 40);
        assert_eq!(unseen(10, 30, 20, 10), 0);
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let apps = tmp.path().join("apps");
        let elsewhere = tmp.path().join("other");
        let vhdx = |dir: &Path, bytes| {
            let mut f = finding(Category::Advice, "x", bytes, Tier::Review, Method::None);
            f.path = Some(dir.join("Docker/wsl/disk/docker_data.VHDX"));
            f
        };
        let other = finding(Category::Temp, "t", 5, Tier::Safe, Method::None);
        let inside = vhdx(&home.join("AppData/Local"), 700);
        assert_eq!(counted_images(&[inside, other.clone()], &home, &apps), 0);
        assert_eq!(counted_images(&[vhdx(&apps, 9)], &home, &apps), 0);
        let out = vhdx(&elsewhere, 300);
        assert_eq!(counted_images(&[out, other], &home, &apps), 300);
    }

    #[test]
    fn raised_recent_days_reaches_the_guard() {
        use crate::guard::tests::{elsewhere, p, snap};
        let mut rules = rules::builtin();
        rules.recent_days = 45;
        let run = crate::run::FakeRunner::new();
        let tmp = tempfile::tempdir().unwrap();
        let ctx = Ctx::new(
            Os::current(),
            dirs(tmp.path()),
            tmp.path().join(".devaudit"),
            &run,
            &rules,
            SystemTime::now(),
            1,
        );
        let g = build_guard(&ctx, &snap(vec![p(1, "zsh", Some(&elsewhere()), &[])])).unwrap();
        assert_eq!(g.recent_days, 45);
    }

    #[test]
    fn unreadable_history_is_an_error_and_left_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = [0xff, 0xfe, b'\n', 0x80];
        fs::write(tmp.path().join("history.csv"), bad).unwrap();
        assert!(save(&report(5, vec![]), tmp.path()).is_err());
        assert_eq!(fs::read(tmp.path().join("history.csv")).unwrap(), bad);
        assert!(append_history(tmp.path(), &report(5, vec![])).is_err());
        assert!(growth(tmp.path(), &report(5, vec![])).is_empty());
    }

    #[test]
    fn report_contains_no_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap().join("home");
        let root = home.join("code");
        let proj = root.join("app");
        fs::create_dir_all(proj.join("node_modules/pkg")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();
        fs::write(proj.join("package-lock.json"), "{}").unwrap();
        fs::write(
            proj.join("node_modules/pkg/secret.txt"),
            "TOPSECRET-FILE-BODY",
        )
        .unwrap();
        fs::write(proj.join(".env"), "API_KEY=TOPSECRET-ENV-VALUE").unwrap();
        let mut rules = rules::builtin();
        rules.project_roots = vec![root.to_string_lossy().into_owned()];
        let run = SystemRunner { tool_dirs: vec![] };
        let ctx = Ctx::new(
            Os::current(),
            dirs(&home),
            home.join(".devaudit"),
            &run,
            &rules,
            SystemTime::now(),
            1,
        );
        let (f, s) = projects::findings(
            &ctx,
            Err(&crate::guard::GuardError::NoProcessData),
            &AtomicBool::new(false),
        );
        assert!(!f.is_empty());
        let json = serde_json::to_string(&report(1, f)).unwrap();
        let mut r = report(1, vec![]);
        r.skipped = s;
        let json2 = serde_json::to_string(&r).unwrap();
        for j in [json, json2] {
            assert!(!j.contains("TOPSECRET"), "{j}");
        }
    }

    /// One finding of every `Method` variant, covering every `Tier`.
    fn fixture_report() -> Report {
        let id = FileId {
            volume: 16777234,
            index: 12345678,
        };
        let methods = vec![
            Method::Vault {
                path: PathBuf::from("/Users/dev/code/shop/node_modules"),
                id,
                keep_days: 7,
            },
            Method::PruneOlderThan {
                path: PathBuf::from("/tmp"),
                days: 7,
            },
            Method::Command {
                argv: ["npm", "cache", "clean", "--force"]
                    .map(String::from)
                    .to_vec(),
            },
            Method::DockerVolumeBackupRm {
                name: "shop_pgdata".into(),
            },
            Method::WorktreeVault {
                repo: PathBuf::from("/Users/dev/code/shop"),
                worktree: PathBuf::from("/Users/dev/code/shop-wt"),
                id,
                branch: "feature/x".into(),
                keep_days: 14,
            },
            Method::DockerStop {
                container_ids: vec!["abc123".into(), "def456".into()],
            },
            Method::Signal {
                pid: 4242,
                start_time: 1_700_000_000,
            },
            Method::None,
        ];
        let tiers = [Tier::Safe, Tier::Review, Tier::Protected];
        let cats = [
            Category::ProjectBuild,
            Category::PackageCache,
            Category::BrowserCache,
            Category::AiTool,
            Category::Docker,
            Category::EditorData,
            Category::Temp,
            Category::Advice,
        ];
        let mut findings: Vec<Finding> = methods
            .into_iter()
            .enumerate()
            .map(|(i, m)| {
                let mut f = finding(
                    cats[i],
                    &format!("fixture-{i}"),
                    (i as u64 + 1) * 1_000_000,
                    tiers[i % 3],
                    m,
                );
                f.owner_processes = if i == 0 { vec!["node".into()] } else { vec![] };
                f.project = (i == 0).then(|| PathBuf::from("/Users/dev/code/shop"));
                f.bytes_estimate = i == 4;
                f.idle_days = (i != 2).then_some(i as u32 * 10);
                f.rebuild = (i % 2 == 0).then(|| "Run npm install".into());
                f
            })
            .collect();
        findings.push(finding(
            Category::Process,
            "no-path",
            1,
            Tier::Safe,
            Method::None,
        ));
        findings.last_mut().unwrap().path = None;
        sort_findings(&mut findings);
        report(1_760_000_000, findings)
    }

    #[test]
    fn report_fixture_is_current() {
        let r = fixture_report();
        for t in [Tier::Safe, Tier::Review, Tier::Protected] {
            assert!(r.findings.iter().any(|f| f.tier == t));
        }
        let mut json = serde_json::to_string_pretty(&r).unwrap();
        json.push('\n');
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/report.json");
        if std::env::var_os("UPDATE_FIXTURES").is_some() {
            fs::write(&path, &json).unwrap();
            return;
        }
        let have = fs::read_to_string(&path).expect("run with UPDATE_FIXTURES=1 to create it");
        assert_eq!(have, json, "fixture is stale: rerun with UPDATE_FIXTURES=1");
        assert_eq!(serde_json::from_str::<Report>(&have).unwrap(), r);
    }
}
