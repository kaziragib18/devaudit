//! Docker findings: dangling images, build cache, unused volumes, monitoring stacks, and the
//! VM allowance. Reads only; never starts Docker, never prunes everything.
//!
//! Parsed output (all `--format '{{json .}}'`, one JSON object per line unless noted):
//! - `docker info --format {{.ServerVersion}}`: only its exit status matters.
//! - `docker ps -a --no-trunc`: ID, Names, Image, Labels ("k=v,k=v"), State, Mounts (names or paths).
//! - `docker volume ls`: Name, Driver.
//! - `docker system df -v`: ONE JSON object with Images, Volumes (Links, Size) and BuildCache
//!   (InUse, Size) arrays. Sizes are go-units strings such as "1.2GB".
//! - `docker stats --no-stream --no-trunc`: Name, MemUsage ("45MiB / 7.6GiB").
//! - `docker inspect --format {{json .Mounts}} <ids>`: one JSON array per line, in argument order.

use crate::guard::{self, Guard, GuardError};
use crate::model::{Category, Finding, Method, Os, Tier, finding_id};
use crate::run::{RunError, Runner};
use crate::{Ctx, platform, projects, targets};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const T: Duration = Duration::from_secs(30);
const MOUNT_REASON: &str = "Docker container mounts it";

#[derive(Clone, Debug, PartialEq)]
pub struct VmInfo {
    pub memory_bytes: Option<u64>,
    /// "Docker settings" | ".wslconfig" | "WSL default (50% RAM)"
    pub memory_source: &'static str,
    pub disk_image_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DockerScan {
    pub running: bool,
    pub vm: VmInfo,
    /// Running containers: id, name, compose project, memory in use (bytes, 0 if unknown).
    pub containers: Vec<(String, String, Option<String>, u64)>,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

enum Call {
    Out(String),
    Down,
    Missing,
    Fail(String),
}

fn call(run: &dyn Runner, argv: &[&str]) -> Call {
    match run.run(argv, T) {
        Ok(o) if o.status == 0 => Call::Out(o.stdout),
        Ok(o) if guard::docker_down(&o.stderr) => Call::Down,
        Ok(o) => Call::Fail(format!("exit {}: {}", o.status, o.stderr.trim())),
        Err(RunError::NotFound(_)) => Call::Missing,
        Err(e) => Call::Fail(format!("{e:?}")),
    }
}

/// A read that must work, else a note says what was skipped.
fn read(run: &dyn Runner, argv: &[&str], what: &str, notes: &mut Vec<String>) -> Option<String> {
    match call(run, argv) {
        Call::Out(o) => Some(o),
        Call::Down | Call::Missing => {
            notes.push(format!("Docker stopped answering, so {what} was skipped."));
            None
        }
        Call::Fail(e) => {
            notes.push(format!("Couldn't read {what} from Docker ({e}); skipped."));
            None
        }
    }
}

fn json_lines(text: &str) -> Result<Vec<Value>, String> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l.trim()).map_err(|e| e.to_string()))
        .collect()
}

/// A string, number or bool field as text.
fn field(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// "1.2GB" (decimal, go-units) or "45MiB" (binary) to bytes. Anything else is None.
fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim();
    let split = t.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (num, unit) = t.split_at(split);
    let n: f64 = num.parse().ok()?;
    let unit = unit.trim().to_ascii_lowercase();
    let mult: f64 = match unit.as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "pb" => 1e15,
        "kib" => 1024.0,
        "mib" => 1024f64.powi(2),
        "gib" => 1024f64.powi(3),
        "tib" => 1024f64.powi(4),
        _ => return None,
    };
    Some((n * mult).round() as u64)
}

fn finding(key: &str, title: String, bytes: u64, tier: Tier, reason: String, m: Method) -> Finding {
    Finding {
        id: finding_id(Category::Docker, key),
        category: Category::Docker,
        title,
        path: None,
        project: None,
        owner_processes: vec![],
        bytes,
        bytes_estimate: false,
        idle_days: None,
        tier,
        reason,
        rebuild: None,
        method: m,
    }
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64)
}

// ---------------------------------------------------------------- VM info

#[derive(Deserialize)]
struct DockerSettings {
    #[serde(rename = "memoryMiB", alias = "MemoryMiB")]
    memory_mib: Option<serde_json::Number>,
}

fn docker_raw(ctx: &Ctx) -> PathBuf {
    ctx.home
        .join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw")
}

/// Only `memoryMiB` is read; `settings-store.json` (newer) first, then `settings.json`.
fn docker_settings_memory(ctx: &Ctx) -> Option<u64> {
    let dir = ctx.home.join("Library/Group Containers/group.com.docker");
    ["settings-store.json", "settings.json"]
        .iter()
        .filter_map(|f| fs::read_to_string(dir.join(f)).ok())
        .filter_map(|t| serde_json::from_str::<DockerSettings>(&t).ok())
        .find_map(|s| s.memory_mib.and_then(|n| n.as_u64()))
        .and_then(|m| m.checked_mul(1 << 20))
}

/// `memory=` of the `[wsl2]` section; no other key is read.
pub fn parse_wslconfig_memory(text: &str) -> Option<u64> {
    let mut in_wsl2 = false;
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        if let Some(sec) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_wsl2 = sec.trim().eq_ignore_ascii_case("wsl2");
            continue;
        }
        if !in_wsl2 {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case("memory") {
            continue;
        }
        let v = v.trim().trim_matches('"').to_ascii_lowercase();
        let split = v.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let (num, unit) = v.split_at(split);
        let n: f64 = num.parse().ok()?;
        let mult = match unit.trim() {
            "b" => 1u64,
            "kb" | "k" | "kib" => 1 << 10,
            "mb" | "m" | "mib" => 1 << 20,
            "gb" | "g" | "gib" => 1 << 30,
            "tb" | "t" | "tib" => 1 << 40,
            _ => return None,
        };
        return Some((n * mult as f64).round() as u64);
    }
    None
}

fn size_of(p: &Path) -> Option<u64> {
    let md = fs::symlink_metadata(p).ok()?;
    (md.is_file() && !platform::is_link(&md)).then(|| platform::size_on_disk(&md))
}

pub fn read_vm(ctx: &Ctx, ram_total: u64) -> VmInfo {
    match ctx.os {
        Os::Macos => VmInfo {
            memory_bytes: docker_settings_memory(ctx),
            memory_source: "Docker settings",
            disk_image_bytes: size_of(&docker_raw(ctx)),
        },
        Os::Windows => {
            let configured = fs::read_to_string(ctx.home.join(".wslconfig"))
                .ok()
                .and_then(|t| parse_wslconfig_memory(&t));
            let disk = ctx
                .dirs
                .local_app_data
                .as_deref()
                .into_iter()
                .flat_map(targets::docker_vhdx)
                .filter_map(|p| size_of(&p))
                .max();
            let (memory_bytes, memory_source) = match configured {
                Some(m) => (Some(m), ".wslconfig"),
                None => (Some(ram_total / 2), "WSL default (50% RAM)"),
            };
            VmInfo {
                memory_bytes,
                memory_source,
                disk_image_bytes: disk,
            }
        }
    }
}

fn allowance_advice(ctx: &Ctx, vm: &VmInfo, ram_total: u64, swap_used_pct: u8) -> Option<Finding> {
    let mem = vm.memory_bytes?;
    if ram_total == 0 || swap_used_pct <= 50 {
        return None;
    }
    // The WSL default is exactly half, so it counts; an explicit setting must exceed half.
    let default = vm.memory_source.starts_with("WSL default");
    let (m2, r) = (u128::from(mem) * 2, u128::from(ram_total));
    if !(m2 > r || (default && m2 == r)) {
        return None;
    }
    let (what, swap, fix) = match ctx.os {
        Os::Macos => (
            "Docker's VM",
            "swap",
            "Lower Memory in Docker Desktop > Settings > Resources. DevAudit does not change Docker's settings.",
        ),
        Os::Windows => (
            "WSL",
            "page file",
            "Set memory= under [wsl2] in %USERPROFILE%\\.wslconfig, then run wsl --shutdown. DevAudit does not change WSL's settings.",
        ),
    };
    let src = if default {
        ", the default of 50% of RAM"
    } else {
        ""
    };
    let mut f = finding(
        "allowance",
        format!(
            "{what} is allowed {} of {} RAM{src}, and {swap} is {swap_used_pct}% used",
            gib(mem),
            gib(ram_total)
        ),
        0,
        Tier::Review,
        format!(
            "An allowance over 50% of RAM while the {swap} is mostly used leaves little for everything else. {fix}"
        ),
        Method::None,
    );
    f.category = Category::Advice;
    f.id = finding_id(Category::Advice, "docker-allowance");
    Some(f)
}

// ---------------------------------------------------------------- containers

struct Container {
    id: String,
    name: String,
    image: String,
    project: Option<String>,
    running: bool,
    mounts: Vec<String>,
}

fn parse_containers(text: &str) -> Result<Vec<Container>, String> {
    Ok(json_lines(text)?
        .iter()
        .filter_map(|v| {
            let id = field(v, "ID")?;
            let labels = field(v, "Labels").unwrap_or_default();
            let project = labels
                .split(',')
                .find_map(|kv| kv.strip_prefix("com.docker.compose.project="))
                .map(str::to_string);
            Some(Container {
                name: field(v, "Names").unwrap_or_else(|| id.clone()),
                image: field(v, "Image").unwrap_or_default(),
                running: field(v, "State").is_some_and(|s| s == "running"),
                mounts: field(v, "Mounts")
                    .unwrap_or_default()
                    .split(',')
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect(),
                project,
                id,
            })
        })
        .collect())
}

/// Image repository without registry host, tag or digest, lowercased.
fn repo_of(image: &str) -> String {
    let i = image.to_ascii_lowercase();
    let i = i.split('@').next().unwrap_or("");
    let i = match i.rsplit_once(':') {
        Some((l, tag)) if !tag.contains('/') => l,
        _ => i,
    };
    match i.split_once('/') {
        Some((host, rest)) if host.contains(['.', ':']) || host == "localhost" => rest.to_string(),
        _ => i.to_string(),
    }
}

fn is_monitoring(image: &str) -> bool {
    let r = repo_of(image);
    let last = r.rsplit('/').next().unwrap_or("");
    r.starts_with("grafana/")
        || r.starts_with("prom/")
        || r.starts_with("otel/")
        || ["prometheus", "loki", "tempo", "alloy", "promtail"]
            .iter()
            .any(|n| r.ends_with(&format!("/{n}")))
        || (r.contains('/') && last.starts_with("jaeger"))
}

/// Mount sources of `inspect` output lines, one list per container; None when unreadable.
fn inspect_mounts(text: &str, os: Os, expect: usize) -> Option<Vec<Vec<PathBuf>>> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() != expect {
        return None;
    }
    lines
        .iter()
        .map(|l| {
            let v: Vec<Value> = serde_json::from_str(l.trim()).ok()?;
            Some(
                v.iter()
                    .filter(|m| m["Type"] == "bind")
                    .filter_map(|m| m["Source"].as_str())
                    .filter_map(|s| guard::normalize_mount_for(os, s))
                    .collect(),
            )
        })
        .collect()
}

/// Why a stop group can't be offered, or None. Project mounts are those inside (or
/// containing) a project root; they must not be locked by anything but Docker itself.
fn group_blocker(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    members: &[&Container],
) -> Option<String> {
    let Ok(g) = guard else {
        return Some("Can't tell which projects are active (no process data)".into());
    };
    let ids: Vec<&str> = members.iter().map(|c| c.id.as_str()).collect();
    let mut argv = vec!["docker", "inspect", "--format", "{{json .Mounts}}"];
    argv.extend(&ids);
    let out = match call(ctx.run, &argv) {
        Call::Out(o) => o,
        _ => return Some("Can't read the containers' mounts".into()),
    };
    let Some(mounts) = inspect_mounts(&out, ctx.os, ids.len()) else {
        return Some("Can't read the containers' mounts".into());
    };
    let (roots, _) = projects::roots(ctx);
    let mut reasons: Vec<String> = vec![];
    for m in mounts.iter().flatten() {
        let project = roots
            .iter()
            .any(|r| guard::maybe_inside(m, r) || guard::maybe_inside(r, m));
        if !project {
            continue;
        }
        for r in g.check(m, ctx.run).reasons {
            if r != MOUNT_REASON && !reasons.contains(&r) {
                reasons.push(r);
            }
        }
    }
    (!reasons.is_empty()).then(|| format!("Mounts an active project: {}", reasons.join("; ")))
}

fn stop_groups(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    containers: &[Container],
) -> Vec<Finding> {
    // Group key: compose project, else the container itself.
    let mut groups: Vec<(Option<String>, Vec<&Container>)> = vec![];
    for c in containers
        .iter()
        .filter(|c| c.running && is_monitoring(&c.image))
    {
        match groups
            .iter_mut()
            .find(|(p, _)| p.is_some() && *p == c.project)
        {
            Some((_, v)) => v.push(c),
            None => groups.push((c.project.clone(), vec![c])),
        }
    }
    groups
        .into_iter()
        .map(|(project, members)| {
            let names: Vec<&str> = members.iter().map(|c| c.name.as_str()).collect();
            let title = match &project {
                Some(p) => format!(
                    "Monitoring stack \"{p}\" ({} containers: {})",
                    members.len(),
                    names.join(", ")
                ),
                None => format!("Monitoring container {}", names[0]),
            };
            let key = match &project {
                Some(p) => format!("stop:project:{p}"),
                None => format!("stop:container:{}", members[0].id),
            };
            let blocker = group_blocker(ctx, guard, &members);
            let (tier, reason) = match blocker {
                Some(b) => (Tier::Protected, b),
                None => (
                    Tier::Review,
                    "Monitoring tools that are probably not needed right now. Stopping them frees memory and they can be started again.".into(),
                ),
            };
            let mut f = finding(
                &key,
                title,
                0,
                tier,
                reason,
                Method::DockerStop {
                    container_ids: members.iter().map(|c| c.id.clone()).collect(),
                },
            );
            f.rebuild = Some("Start again with docker start".into());
            f
        })
        .collect()
}

// ---------------------------------------------------------------- disk usage

fn sum_sizes<'a>(items: impl Iterator<Item = &'a Value>) -> u64 {
    items
        .filter_map(|v| field(v, "Size").and_then(|s| parse_size(&s)))
        .sum()
}

fn arr<'a>(df: &'a Value, key: &str) -> &'a [Value] {
    df.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn command_finding(key: &str, title: String, bytes: u64, argv: &[&str], reason: &str) -> Finding {
    let mut f = finding(
        key,
        title,
        bytes,
        Tier::Safe,
        reason.into(),
        Method::Command {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        },
    );
    f.bytes_estimate = true;
    f.rebuild = Some("Docker downloads or rebuilds them when needed. This can't be undone.".into());
    f
}

fn disk_findings(df: &Value, volumes: &[String], containers: &[Container], out: &mut Vec<Finding>) {
    let dangling: Vec<&Value> = arr(df, "Images")
        .iter()
        .filter(|i| {
            field(i, "Repository").is_some_and(|r| r == "<none>")
                && field(i, "Tag").is_some_and(|t| t == "<none>")
                && field(i, "Containers").is_some_and(|c| c == "0")
        })
        .collect();
    if !dangling.is_empty() {
        out.push(command_finding(
            "dangling-images",
            format!("{} dangling Docker image(s)", dangling.len()),
            sum_sizes(dangling.iter().copied()),
            &["docker", "image", "prune", "-f"],
            "Untagged images no container uses.",
        ));
    }
    let cache: Vec<&Value> = arr(df, "BuildCache")
        .iter()
        .filter(|c| field(c, "InUse").is_some_and(|u| u == "false"))
        .collect();
    let cache_bytes = sum_sizes(cache.iter().copied());
    if cache_bytes > 0 {
        out.push(command_finding(
            "build-cache",
            "Docker build cache not used in the last 7 days".into(),
            cache_bytes,
            &["docker", "builder", "prune", "-f", "--filter", "until=168h"],
            "Build layers older than 7 days that no build is using.",
        ));
    }
    // Unused: listed, size known, no link in `system df`, and no container (running or
    // stopped) names it in `docker ps -a`.
    for name in volumes {
        let Some(v) = arr(df, "Volumes")
            .iter()
            .find(|v| field(v, "Name").as_deref() == Some(name))
        else {
            continue;
        };
        if field(v, "Links").as_deref() != Some("0")
            || containers.iter().any(|c| c.mounts.contains(name))
            || name.starts_with('-')
        {
            continue;
        }
        let bytes = field(v, "Size").and_then(|s| parse_size(&s)).unwrap_or(0);
        out.push(finding(
            &format!("volume:{name}"),
            format!("Unused Docker volume {name}"),
            bytes,
            Tier::Review,
            "No container, running or stopped, uses it. DevAudit backs it up before removing it."
                .into(),
            Method::DockerVolumeBackupRm { name: name.clone() },
        ));
    }
}

// ---------------------------------------------------------------- scan

fn memory_by_name(run: &dyn Runner) -> Vec<(String, u64)> {
    let Call::Out(o) = call(
        run,
        &[
            "docker",
            "stats",
            "--no-stream",
            "--no-trunc",
            "--format",
            "{{json .}}",
        ],
    ) else {
        return vec![];
    };
    json_lines(&o)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| {
            let used = field(v, "MemUsage")?;
            let used = parse_size(used.split('/').next()?)?;
            Some((field(v, "Name")?, used))
        })
        .collect()
}

pub fn scan(
    ctx: &Ctx,
    guard: Result<&Guard, &GuardError>,
    ram_total: u64,
    swap_used_pct: u8,
) -> DockerScan {
    let vm = read_vm(ctx, ram_total);
    let mut s = DockerScan {
        running: false,
        vm,
        containers: vec![],
        findings: vec![],
        notes: vec![],
    };
    match call(
        ctx.run,
        &["docker", "info", "--format", "{{.ServerVersion}}"],
    ) {
        Call::Out(_) => s.running = true,
        Call::Missing => s.notes.push("Docker isn't installed.".into()),
        Call::Down => s
            .notes
            .push("Docker isn't running. DevAudit never starts it.".into()),
        Call::Fail(e) => s.notes.push(format!("Docker didn't answer: {e}")),
    }
    if !s.running {
        return s;
    }

    if ctx.os == Os::Macos {
        let raw = docker_raw(ctx);
        if let Some(b) = size_of(&raw) {
            let mut f = finding(
                &raw.to_string_lossy(),
                "Docker disk image (Docker.raw)".into(),
                b,
                Tier::Review,
                "It doesn't shrink by itself. DevAudit only reports its size.".into(),
                Method::None,
            );
            f.path = Some(raw);
            s.findings.push(f);
        }
    }

    let ps = read(
        ctx.run,
        &["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"],
        "the container list",
        &mut s.notes,
    )
    .and_then(|t| match parse_containers(&t) {
        Ok(c) => Some(c),
        Err(e) => {
            s.notes
                .push(format!("Couldn't read the container list ({e}); skipped."));
            None
        }
    });

    if let Some(containers) = &ps {
        let mem = memory_by_name(ctx.run);
        s.containers = containers
            .iter()
            .filter(|c| c.running)
            .map(|c| {
                let m = mem.iter().find(|(n, _)| *n == c.name).map_or(0, |m| m.1);
                (c.id.clone(), c.name.clone(), c.project.clone(), m)
            })
            .collect();

        // Without the full container list nothing about volumes can be proven.
        let df = read(
            ctx.run,
            &["docker", "system", "df", "-v", "--format", "{{json .}}"],
            "disk usage",
            &mut s.notes,
        )
        .and_then(|t| {
            serde_json::from_str::<Value>(t.trim())
                .map_err(|e| {
                    s.notes
                        .push(format!("Couldn't read disk usage ({e}); skipped."))
                })
                .ok()
        });
        let vols = read(
            ctx.run,
            &["docker", "volume", "ls", "--format", "{{json .}}"],
            "the volume list",
            &mut s.notes,
        )
        .and_then(|t| {
            json_lines(&t)
                .map_err(|e| {
                    s.notes
                        .push(format!("Couldn't read the volume list ({e}); skipped."))
                })
                .ok()
        });
        if let (Some(df), Some(vols)) = (&df, &vols) {
            let names: Vec<String> = vols
                .iter()
                .filter(|v| field(v, "Driver").is_some_and(|d| d == "local"))
                .filter_map(|v| field(v, "Name"))
                .collect();
            disk_findings(df, &names, containers, &mut s.findings);
        }
        s.findings.extend(stop_groups(ctx, guard, containers));
    }

    s.findings
        .extend(allowance_advice(ctx, &s.vm, ram_total, swap_used_pct));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Method, Os, Tier};
    use crate::run::{FakeRunner, Output, RunError};
    use crate::{platform::KnownDirs, rules};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    const GIB: u64 = 1 << 30;

    fn fx(name: &str) -> String {
        fs::read_to_string(format!(
            "{}/tests/fixtures/docker_{name}.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn ok(s: &str) -> Result<Output, RunError> {
        Ok(Output {
            status: 0,
            stdout: s.into(),
            stderr: String::new(),
        })
    }

    fn fail(stderr: &str) -> Result<Output, RunError> {
        Ok(Output {
            status: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        })
    }

    /// A running Docker answering from one fixture set ("macos" or "windows").
    fn docker(set: &str) -> FakeRunner {
        FakeRunner::new()
            .on(&["docker", "info"], ok("26.1.4\n"))
            .on(&["docker", "ps", "-a"], ok(&fx(&format!("{set}_ps"))))
            .on(
                &["docker", "volume", "ls"],
                ok(&fx(&format!("{set}_volume_ls"))),
            )
            .on(&["docker", "system", "df"], ok(&fx(&format!("{set}_df"))))
            .on(&["docker", "stats"], ok(&fx(&format!("{set}_stats"))))
            .on(&["docker", "inspect"], ok(&fx(&format!("{set}_inspect"))))
    }

    struct Env {
        _tmp: tempfile::TempDir,
        rules: rules::Rules,
        dirs: KnownDirs,
    }

    impl Env {
        fn new() -> Env {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().canonicalize().unwrap().join("home");
            let local = home.join("AppData/Local");
            fs::create_dir_all(&local).unwrap();
            fs::create_dir_all(home.join("code")).unwrap();
            let mut rules = rules::builtin();
            rules.project_roots = vec![home.join("code").to_string_lossy().into_owned()];
            let dirs = KnownDirs {
                home: home.clone(),
                local_app_data: Some(local.clone()),
                app_data: Some(home.join("AppData/Roaming")),
                temp: local.join("Temp"),
                personal: vec![],
                cloud_roots: vec![],
            };
            Env {
                _tmp: tmp,
                rules,
                dirs,
            }
        }
        fn ctx<'a>(&'a self, os: Os, run: &'a FakeRunner) -> Ctx<'a> {
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
        fn home(&self) -> &Path {
            &self.dirs.home
        }
        fn write(&self, rel: &str, text: &str) -> PathBuf {
            let p = self.home().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, text).unwrap();
            p
        }
        fn raw(&self) -> PathBuf {
            self.write(
                "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
                "raw-image-bytes",
            )
        }
    }

    fn guard(cwds: Vec<(u32, PathBuf)>) -> Guard {
        Guard {
            procs: vec![],
            cwds,
            cmd_paths: vec![],
            unreadable: vec![],
            mounts: vec![],
            docker_error: None,
            git_available: true,
            recent_days: 14,
            now: SystemTime::now(),
        }
    }

    fn scan_mac(e: &Env, r: &FakeRunner, g: &Guard) -> DockerScan {
        scan(&e.ctx(Os::Macos, r), Ok(g), 16 * GIB, 10)
    }

    fn by_title<'a>(s: &'a DockerScan, needle: &str) -> Vec<&'a Finding> {
        s.findings
            .iter()
            .filter(|f| f.title.contains(needle))
            .collect()
    }

    #[test]
    fn not_running_is_note_only() {
        let e = Env::new();
        let g = guard(vec![(1, e.home().to_path_buf())]);
        for r in [
            FakeRunner::new().on(
                &["docker", "info"],
                fail("Cannot connect to the Docker daemon at unix:///x"),
            ),
            FakeRunner::new(),
            FakeRunner::new().on(&["docker", "info"], Err(RunError::Timeout)),
        ] {
            let s = scan_mac(&e, &r, &g);
            assert!(!s.running);
            assert!(s.findings.is_empty() && s.containers.is_empty());
            assert_eq!(s.notes.len(), 1, "{:?}", s.notes);
            let calls = r.calls();
            assert!(
                calls.iter().all(|c| c[..2] == ["docker", "info"]),
                "{calls:?}"
            );
        }
    }

    #[test]
    fn macos_fixture_parses() {
        let e = Env::new();
        e.raw();
        let r = docker("macos");
        let s = scan_mac(&e, &r, &guard(vec![]));
        assert!(s.running && s.notes.is_empty(), "{:?}", s.notes);
        // Running containers only, with project label and memory.
        let names: Vec<&str> = s.containers.iter().map(|c| c.1.as_str()).collect();
        assert_eq!(
            names,
            ["grafana", "prometheus", "loki", "shop-api", "shop-db"]
        );
        let loki = s.containers.iter().find(|c| c.1 == "loki").unwrap();
        assert_eq!(loki.2.as_deref(), Some("obs"));
        assert_eq!(loki.3, (1.5 * (1u64 << 30) as f64) as u64);
        // Docker.raw report, dangling images, build cache, 3 unused volumes, 1 stop group.
        assert_eq!(by_title(&s, "Docker.raw").len(), 1);
        let img = by_title(&s, "dangling");
        assert_eq!(img.len(), 1);
        assert_eq!(img[0].bytes, 1_350_000_000);
        let cache = by_title(&s, "build cache");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache[0].bytes, 1_548_500_000);
        let vols: Vec<&Finding> = s
            .findings
            .iter()
            .filter(|f| matches!(f.method, Method::DockerVolumeBackupRm { .. }))
            .collect();
        assert_eq!(vols.len(), 3);
        let stops: Vec<&Finding> = s
            .findings
            .iter()
            .filter(|f| matches!(f.method, Method::DockerStop { .. }))
            .collect();
        assert_eq!(stops.len(), 1);
        assert!(s.findings.iter().all(|f| f.category == Category::Docker));
    }

    #[test]
    fn windows_fixture_parses() {
        let e = Env::new();
        let r = docker("windows");
        let g = guard(vec![]);
        let s = scan(&e.ctx(Os::Windows, &r), Ok(&g), 16 * GIB, 10);
        assert!(s.running && s.notes.is_empty(), "{:?}", s.notes);
        assert_eq!(s.containers.len(), 5);
        // No vhdx findings here: Task 9 emits those.
        assert!(by_title(&s, "vhdx").is_empty() && by_title(&s, "Docker.raw").is_empty());
        let stop = s
            .findings
            .iter()
            .find(|f| matches!(f.method, Method::DockerStop { .. }))
            .unwrap();
        assert_eq!(stop.tier, Tier::Review);
        let vols = s
            .findings
            .iter()
            .filter(|f| matches!(f.method, Method::DockerVolumeBackupRm { .. }))
            .count();
        assert_eq!(vols, 3);
        // Both Windows bind-mount spellings reach the guard as C:\ paths.
        let shop = fx("windows_shop_inspect");
        let m: Vec<serde_json::Value> = serde_json::from_str(shop.trim()).unwrap();
        let src = m[0]["Source"].as_str().unwrap();
        assert_eq!(
            crate::guard::normalize_mount_for(Os::Windows, src),
            Some(PathBuf::from(r"C:\Users\dev\code\shop"))
        );
        assert_eq!(
            crate::guard::normalize_mount_for(
                Os::Windows,
                "/run/desktop/mnt/host/c/Users/dev/code/obs-config"
            ),
            Some(PathBuf::from(r"C:\Users\dev\code\obs-config"))
        );
    }

    fn volume_names(s: &DockerScan) -> Vec<String> {
        s.findings
            .iter()
            .filter_map(|f| match &f.method {
                Method::DockerVolumeBackupRm { name } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn volume_used_by_stopped_container_not_offered() {
        let e = Env::new();
        let s = scan_mac(&e, &docker("macos"), &guard(vec![]));
        let names = volume_names(&s);
        // old_worker_data belongs to an exited container.
        assert!(!names.contains(&"old_worker_data".to_string()), "{names:?}");
        // Even if system df says Links 0, `docker ps -a` still names the volume.
        let df = fx("macos_df").replace(
            r#""Links":"1","Mountpoint":"","Name":"old_worker_data""#,
            r#""Links":"0","Mountpoint":"","Name":"old_worker_data""#,
        );
        assert_ne!(df, fx("macos_df"));
        // First matching rule wins, so the changed df goes first.
        let r = FakeRunner::new()
            .on(&["docker", "system", "df"], ok(&df))
            .on(&["docker", "info"], ok("26\n"))
            .on(&["docker", "ps", "-a"], ok(&fx("macos_ps")))
            .on(&["docker", "volume", "ls"], ok(&fx("macos_volume_ls")))
            .on(&["docker", "stats"], ok(&fx("macos_stats")))
            .on(&["docker", "inspect"], ok(&fx("macos_inspect")));
        let s = scan_mac(&e, &r, &guard(vec![]));
        assert!(!volume_names(&s).contains(&"old_worker_data".to_string()));
    }

    #[test]
    fn unused_volume_is_review_backup_rm() {
        let e = Env::new();
        let s = scan_mac(&e, &docker("macos"), &guard(vec![]));
        let f = s
            .findings
            .iter()
            .find(|f| {
                f.method
                    == Method::DockerVolumeBackupRm {
                        name: "scratch_vol".into(),
                    }
            })
            .unwrap();
        assert_eq!(f.tier, Tier::Review);
        assert_eq!(f.category, Category::Docker);
        assert_eq!(f.bytes, 2_100_000_000);
        assert!(f.method.undoable());
        let names = volume_names(&s);
        assert!(names.contains(&"orphan_cache".to_string()));
        assert!(!names.contains(&"shop_pgdata".to_string()));
    }

    #[test]
    fn dangling_images_and_build_cache_are_non_undoable_commands() {
        let e = Env::new();
        let s = scan_mac(&e, &docker("macos"), &guard(vec![]));
        let argvs: Vec<Vec<String>> = s
            .findings
            .iter()
            .filter_map(|f| match &f.method {
                Method::Command { argv } => Some(argv.clone()),
                _ => None,
            })
            .collect();
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            argvs,
            vec![
                v(&["docker", "image", "prune", "-f"]),
                v(&["docker", "builder", "prune", "-f", "--filter", "until=168h"]),
            ]
        );
        assert!(
            s.findings
                .iter()
                .filter(|f| matches!(f.method, Method::Command { .. }))
                .all(|f| !f.method.undoable() && f.tier == Tier::Safe)
        );
    }

    #[test]
    fn never_prune_all_or_volumes() {
        let e = Env::new();
        let r = docker("macos");
        let s = scan_mac(&e, &r, &guard(vec![]));
        for f in &s.findings {
            if let Method::Command { argv } = &f.method {
                for bad in ["-a", "--all", "--volumes", "down", "rm"] {
                    assert!(!argv.iter().any(|a| a == bad), "{argv:?}");
                }
            }
        }
        // The scan itself only reads from Docker.
        let calls = r.calls();
        assert!(!calls.is_empty());
        for c in calls {
            let reads = matches!(
                c[1].as_str(),
                "info" | "ps" | "volume" | "system" | "stats" | "inspect"
            );
            assert!(reads, "{c:?}");
            assert!(
                !c.iter()
                    .any(|a| matches!(a.as_str(), "rm" | "stop" | "prune" | "down")),
                "{c:?}"
            );
        }
    }

    #[test]
    fn monitoring_stack_grouped_per_compose_project() {
        let e = Env::new();
        let r = docker("macos");
        let s = scan_mac(&e, &r, &guard(vec![]));
        let stop = s
            .findings
            .iter()
            .filter_map(|f| match &f.method {
                Method::DockerStop { container_ids } => Some((f, container_ids)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0].1.len(), 3);
        assert_eq!(stop[0].0.tier, Tier::Review);
        assert!(stop[0].0.title.contains("obs"));
        // shop-api / shop-db are not monitoring images.
        let ps = fx("macos_ps");
        for id in stop[0].1 {
            assert!(ps.contains(id.as_str()));
        }
        assert!(
            !s.findings
                .iter()
                .any(|f| f.title.contains("shop") && matches!(f.method, Method::DockerStop { .. }))
        );
    }

    fn old_project(e: &Env, name: &str) -> PathBuf {
        let p = e.home().join("code").join(name);
        fs::create_dir_all(&p).unwrap();
        let f = p.join("a.txt");
        fs::write(&f, "x").unwrap();
        let t = SystemTime::now() - Duration::from_secs(400 * 86_400);
        fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(t)
            .unwrap();
        p
    }

    fn mount_runner(src: &Path) -> FakeRunner {
        let one = |m: serde_json::Value| format!("{m}\n");
        let bind =
            serde_json::json!([{"Type":"bind","Source":src.to_string_lossy(),"Destination":"/p"}]);
        let vol = serde_json::json!([{"Type":"volume","Name":"obs_prom_data","Source":"/v","Destination":"/prometheus"}]);
        let inspect = format!("{}{}{}", one(vol.clone()), one(bind), one(vol));
        FakeRunner::new()
            .on(&["docker", "inspect"], ok(&inspect))
            .on(
                &["git"],
                Ok(Output {
                    status: 128,
                    stdout: String::new(),
                    stderr: "fatal: not a git repository (or any of the parent directories): .git"
                        .into(),
                }),
            )
            .on(&["docker", "info"], ok("26\n"))
            .on(&["docker", "ps", "-a"], ok(&fx("macos_ps")))
            .on(&["docker", "volume", "ls"], ok(&fx("macos_volume_ls")))
            .on(&["docker", "system", "df"], ok(&fx("macos_df")))
            .on(&["docker", "stats"], ok(&fx("macos_stats")))
    }

    fn obs_tier(s: &DockerScan) -> Tier {
        s.findings
            .iter()
            .find(|f| matches!(f.method, Method::DockerStop { .. }))
            .unwrap()
            .tier
    }

    #[test]
    fn container_bind_mounting_active_project_not_stoppable() {
        let e = Env::new();
        let proj = old_project(&e, "api");
        let r = mount_runner(&proj);
        // Idle project: stoppable.
        let s = scan_mac(&e, &r, &guard(vec![]));
        assert_eq!(obs_tier(&s), Tier::Review);
        // The same project is someone's working directory: locked, so Protected.
        let g = guard(vec![(7, proj.clone())]);
        let s = scan_mac(&e, &r, &g);
        assert_eq!(obs_tier(&s), Tier::Protected);
        let f = s
            .findings
            .iter()
            .find(|f| matches!(f.method, Method::DockerStop { .. }))
            .unwrap();
        assert!(f.reason.contains("in use"), "{}", f.reason);
        // A mounted folder that is not a project is ignored.
        let other = e.home().join("elsewhere");
        fs::create_dir_all(&other).unwrap();
        let s = scan_mac(&e, &mount_runner(&other), &guard(vec![(7, other)]));
        assert_eq!(obs_tier(&s), Tier::Review);
    }

    #[test]
    fn guard_failure_and_unreadable_inspect_fail_closed() {
        let e = Env::new();
        let r = docker("macos");
        let s = scan(
            &e.ctx(Os::Macos, &r),
            Err(&GuardError::NoProcessData),
            16 * GIB,
            10,
        );
        assert_eq!(obs_tier(&s), Tier::Protected);
        // inspect gives fewer lines than containers.
        let r2 = FakeRunner::new()
            .on(&["docker", "inspect"], ok("[]\n"))
            .on(&["docker", "info"], ok("26\n"))
            .on(&["docker", "ps", "-a"], ok(&fx("macos_ps")))
            .on(&["docker", "volume", "ls"], ok(&fx("macos_volume_ls")))
            .on(&["docker", "system", "df"], ok(&fx("macos_df")));
        let s = scan_mac(&e, &r2, &guard(vec![]));
        assert_eq!(obs_tier(&s), Tier::Protected);
    }

    #[test]
    fn mac_allowance_advice_when_over_half_ram_and_swap_high() {
        let e = Env::new();
        e.write(
            "Library/Group Containers/group.com.docker/settings-store.json",
            r#"{"MemoryMiB": 12288, "DiskSizeMiB": 65536, "ProxyHttpMode":"secret-proxy"}"#,
        );
        let r = docker("macos");
        let g = guard(vec![]);
        let run = |swap| scan(&e.ctx(Os::Macos, &r), Ok(&g), 16 * GIB, swap);
        let s = run(80);
        let a: Vec<&Finding> = s
            .findings
            .iter()
            .filter(|f| f.category == Category::Advice)
            .collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].method, Method::None);
        assert!(a[0].title.contains("12.0 GiB"), "{}", a[0].title);
        assert_eq!(s.vm.memory_bytes, Some(12 * GIB));
        assert_eq!(s.vm.memory_source, "Docker settings");
        assert!(!format!("{:?}", s.findings).contains("secret-proxy"));
        // Swap not high: no advice.
        assert!(
            run(40)
                .findings
                .iter()
                .all(|f| f.category != Category::Advice)
        );
        // Older settings.json with the lowercase key.
        let e2 = Env::new();
        e2.write(
            "Library/Group Containers/group.com.docker/settings.json",
            r#"{"memoryMiB": 4096}"#,
        );
        let r2 = docker("macos");
        let s = scan(&e2.ctx(Os::Macos, &r2), Ok(&g), 16 * GIB, 90);
        assert_eq!(s.vm.memory_bytes, Some(4 * GIB));
        assert!(s.findings.iter().all(|f| f.category != Category::Advice));
    }

    #[test]
    fn docker_raw_size_from_metadata_only() {
        let e = Env::new();
        let p = e.raw();
        let r = FakeRunner::new();
        let vm = read_vm(&e.ctx(Os::Macos, &r), 16 * GIB);
        let md = fs::symlink_metadata(&p).unwrap();
        assert_eq!(
            vm.disk_image_bytes,
            Some(crate::platform::size_on_disk(&md))
        );
        assert!(r.calls().is_empty());
        // Missing image: None.
        let e2 = Env::new();
        assert_eq!(
            read_vm(&e2.ctx(Os::Macos, &r), 16 * GIB).disk_image_bytes,
            None
        );
    }

    #[test]
    fn wslconfig_parse() {
        assert_eq!(
            parse_wslconfig_memory("[wsl2]\nmemory=6GB\nswap=0"),
            Some(6 << 30)
        );
        assert_eq!(parse_wslconfig_memory("[wsl2]\nprocessors=4"), None);
        assert_eq!(
            parse_wslconfig_memory("[wsl2]\n# memory=1GB\n Memory = 512MB ; c\n"),
            Some(512 << 20)
        );
        assert_eq!(
            parse_wslconfig_memory("[experimental]\nmemory=9GB\n[wsl2]\nswap=1GB"),
            None
        );
        assert_eq!(parse_wslconfig_memory("[wsl2]\nmemory=lots"), None);
    }

    #[test]
    fn wsl_default_half_ram_advice() {
        let e = Env::new();
        let r = docker("windows");
        let g = guard(vec![]);
        let s = scan(&e.ctx(Os::Windows, &r), Ok(&g), 16 * GIB, 80);
        assert_eq!(s.vm.memory_source, "WSL default (50% RAM)");
        assert_eq!(s.vm.memory_bytes, Some(8 * GIB));
        let a = s
            .findings
            .iter()
            .find(|f| f.category == Category::Advice)
            .unwrap();
        assert!(a.title.contains("50%") || a.reason.contains("50%"), "{a:?}");
        // Explicit .wslconfig at exactly half is not "over half".
        e.write(".wslconfig", "[wsl2]\nmemory=8GB\n");
        let s = scan(&e.ctx(Os::Windows, &r), Ok(&g), 16 * GIB, 80);
        assert_eq!(s.vm.memory_source, ".wslconfig");
        assert!(s.findings.iter().all(|f| f.category != Category::Advice));
        e.write(".wslconfig", "[wsl2]\nmemory=12GB\n");
        let s = scan(&e.ctx(Os::Windows, &r), Ok(&g), 16 * GIB, 80);
        assert!(s.findings.iter().any(|f| f.category == Category::Advice));
    }

    #[test]
    fn wslconfig_other_keys_not_stored() {
        let e = Env::new();
        e.write(
            ".wslconfig",
            "[wsl2]\nkernelCommandLine=secret\nmemory=12GB\nswap=secret2\n[user]\nx=secret3\n",
        );
        let r = docker("windows");
        let g = guard(vec![]);
        let s = scan(&e.ctx(Os::Windows, &r), Ok(&g), 16 * GIB, 80);
        let all = format!("{s:?}");
        assert!(!all.contains("secret"), "{all}");
        assert_eq!(s.vm.memory_bytes, Some(12 * GIB));
    }

    #[test]
    fn windows_vm_disk_image_is_largest_vhdx() {
        let e = Env::new();
        let wsl = e.dirs.local_app_data.clone().unwrap().join("Docker/wsl");
        for (rel, n) in [("main/ext4.vhdx", 10), ("disk/docker_data.vhdx", 9000)] {
            let p = wsl.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, vec![1u8; n]).unwrap();
        }
        let r = FakeRunner::new();
        let vm = read_vm(&e.ctx(Os::Windows, &r), 16 * GIB);
        assert_eq!(vm.disk_image_bytes, Some(12288));
    }
}
