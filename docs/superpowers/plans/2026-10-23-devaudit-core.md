# DevAudit Core + CLI Implementation Plan (macOS + Windows)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A cross-platform Rust library and `devaudit` CLI that scans storage and memory on macOS and Windows, sorts every finding into Safe / Review / Protected, and executes only user-selected, re-validated actions. Every file action is recoverable through the Recovery vault.

**Architecture:** One `core` crate holds every safety rule. OS differences are confined to `platform/macos.rs` and `platform/windows.rs`, which expose the same function set. Processes and memory come from `sysinfo` on both OSes. External tools (git, docker, npm…) run through a `Runner` trait with fixed argv, so tests can feed in recorded output. `actions` re-checks each finding from scratch before acting.

**Tech Stack:**
- Rust stable ≥ 1.89 (for `File::try_lock`; it also covers the ≥ 1.77.2 `.cmd` fix)
- `serde` + `serde_json`, `sysinfo` 0.3x, `notify-rust` 4.x, `getrandom`
- macOS: `libc`
- Windows: `windows-sys` (features: `Win32_Storage_FileSystem`, `Win32_UI_Shell`, `Win32_System_Registry`, `Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`, `Win32_System_ProcessStatus`, `Win32_System_Threading`)
- dev only: `tempfile`

**Spec:** `docs/superpowers/specs/2026-10-23-devaudit-design.md`

## Global Constraints

- **Targets:** macOS 13+; Windows 10 22H2 and 11 (x64). Every test runs on both in CI unless marked `#[cfg(target_os = ...)]`.
- **No network crates** in `core`/`cli`: `reqwest`, `hyper`, `ureq`, `curl`, `isahc`, `surf`, `attohttpc`, `tokio`. Enforced in Task 16.
- **Commands:**
  - No shell strings: every external command is `std::process::Command` with argv.
  - **Env:** cleared, then only `PATH` (built from resolved tool dirs plus system dirs), `HOME`/`USERPROFILE`, `USERNAME`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `SystemRoot`, `SystemDrive`, `ComSpec`, `PATHEXT`, `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, `LANG=C`, `LC_ALL=C`. These are passed through only if the parent has them, because they move tool caches or the Docker endpoint: `npm_config_cache`, `XDG_CACHE_HOME`, `UV_CACHE_DIR`, `PIP_CACHE_DIR`, `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`.
  - **Timeout:** 30 s by default; 600 s for cleanup commands.
- **Platform code:** only `crates/core/src/platform/` may contain `#[cfg(target_os)]` code. Every other module calls `platform::*`.
- **Path comparison:**
  - always via `platform::canon(path)` (canonicalise; on Windows this resolves 8.3 names and verbatim prefixes), then component-wise and case-insensitive
  - never string prefixes
- **Sizes:**
  - macOS: allocated bytes (`st_blocks * 512`)
  - Windows: logical length rounded up to 4096
  - Walks never follow symlinks, junctions or reparse points, and never read cloud placeholders.
- **Fail closed:** if a check cannot run, the item becomes `Tier::Protected` with the failure as its reason.
- **Fixed values:** never-touch lists, the command allowlist, thresholds and target paths are copied verbatim from the spec.
- **Data dir** (`platform::data_dir()`): `~/.devaudit` (0700) on macOS, `%LOCALAPPDATA%\DevAudit` on Windows. Files are written atomically (temp file, then rename).
- **Tests** never touch the real profile: every function takes a `Ctx` or explicit dirs. Integration tests of the CLI set `DEVAUDIT_TEST_ROOT`, which `platform::known_dirs()` honours **only in debug builds** (`cfg(debug_assertions)`): every known dir is then derived under that root. Env vars alone are not enough, because `SHGetKnownFolderPath` ignores them.
- **Instance lock:** every core function that changes the vault or acts (`recovery::{move_in, move_files_in, backup_volume, record, restore, purge, purge_expired, repair}`, `actions::{execute, auto_clean}`) takes `&lock::InstanceLock` as its first argument after `ctx`, so the compiler enforces that the CLI, the app and the background job never mutate concurrently. `lock.rs` is therefore built in Task 1, not Task 15.
- **No-replace renames:** every rename that must not overwrite uses `platform::rename_no_replace`, never `std::fs::rename`. On Windows `std::fs::rename` replaces existing files, and on macOS `rename(2)` replaces an existing empty directory.

## Review Focus

1. **Restore after the user already ran `npm install`** (the original path exists again): expect the item restored next to it as `node_modules.restored-<date>`; nothing is overwritten. Pinned in Task 13.
2. **App killed in the middle of a vault move:** expect the next start to roll forward or back, with no orphaned payload and no lost folder. Pinned in Task 13.
3. **node_modules with a file held open by VS Code on Windows:** expect "in use — skipped" and the folder fully intact. VS Code and node open files with `FILE_SHARE_DELETE`, so the rename may succeed; the active-project guard is the real protection there. Both cases are pinned in Task 14.
4. **A folder swapped for a symlink or junction** between scan and clean, or the parent turning into a link before restore: expect a refusal. Pinned in Tasks 12 and 13.
5. **Project folders with spaces, unicode, paths over 260 characters, or `nul` files:** expect correct discovery, sizing, vault move and restore. Pinned in Tasks 1, 5, 8, 13 and 14.

---

## File Structure

```
devaudit/
  Cargo.toml                      workspace
  rules/rules.json                built-in targets (embedded)
  scripts/windows-survey.ps1      read-only survey (already written)
  scripts/check-no-network.sh / .ps1
  .github/CODEOWNERS, .github/workflows/ci.yml
  crates/core/src/
    lib.rs          module list; Ctx (added in Task 4)
    model.rs        Tier, Category, Method, Finding, Report…
    run.rs          Runner, SystemRunner (tool resolution per OS), FakeRunner
    platform/mod.rs     the shared function set (re-exports macos or windows)
    platform/macos.rs
    platform/windows.rs
    never.rs        never-touch checks (common + per-OS lists)
    rules.rs        rules.json + strict-only overlay
    disk.rs         walker
    procs.rs        sysinfo snapshot, app groups, memory info, process findings
    guard.rs        active-project guard
    projects.rs     build-dir discovery + tiering
    targets.rs      caches, Temp prune, AI tools, Claude worktrees/transcripts, WSL, advice
    docker.rs       Docker findings + VM/WSL allowance advice
    report.rs       scan, save, history, growth
    recovery.rs     vault: move in, restore, purge, journal repair, docker volume backup
    actions.rs      preview, validate, execute, log
    lock.rs         single instance
  crates/core/tests/fixtures/     recorded docker/git output (anonymised); report.json (shared with the app)
  crates/core/src/bin/echo-args.rs   test helper: prints its argv as UTF-8 JSON
  crates/cli/src/main.rs
```

---

### Task 1: Workspace, model types, Runner, instance lock

**Files:**
- Create: `Cargo.toml`, `crates/core/Cargo.toml`, `crates/core/src/{lib,model,run,lock}.rs`, `crates/core/src/bin/echo-args.rs`, `.gitignore`
- Test: `model.rs`, `lock.rs`, `crates/core/tests/runner.rs` (integration test, so it can use `env!("CARGO_BIN_EXE_echo-args")`)

**Interfaces:**
- Produces (`model.rs`):
  ```rust
  pub enum Os { Macos, Windows }                       // Os::current()
  pub enum Tier { Safe, Review, Protected }            // derive Ord: Safe < Review < Protected
  pub enum Category { ProjectBuild, PackageCache, BrowserCache, AiTool, Docker, EditorData, Temp, Process, Advice }
  pub struct FileId { pub volume: u64, pub index: u128 }  // macOS dev+ino; Windows FILE_ID_INFO (128-bit, correct on ReFS / Dev Drive)
  pub enum Method {
      Vault { path: PathBuf, id: FileId, keep_days: u32 },   // same-volume rename into the Recovery vault
      PruneOlderThan { path: PathBuf, days: u32 },     // Windows %TEMP%: old files go into one vault entry
      Command { argv: Vec<String> },                   // only the non-undoable cache commands
      DockerVolumeBackupRm { name: String },           // back up to the vault, then `docker volume rm`
      WorktreeVault { repo: PathBuf, worktree: PathBuf, id: FileId, branch: String, keep_days: u32 },  // whole worktree folder into the vault; never `git worktree remove`, which deletes ignored files such as .env
      DockerStop { container_ids: Vec<String> },
      Signal { pid: u32, start_time: u64 },            // macOS only
      None,
  }
  impl Method { pub fn undoable(&self) -> bool; }      // false only for Command and Signal
  pub struct Finding { pub id: String, pub category: Category, pub title: String, pub path: Option<PathBuf>,
      pub project: Option<PathBuf> /* set for build dirs and worktrees; validate re-checks this project */,
      pub owner_processes: Vec<String> /* from Target.owner_processes; validate refuses while any runs */,
      pub bytes: u64, pub bytes_estimate: bool, pub idle_days: Option<u32>, pub tier: Tier,
      pub reason: String, pub rebuild: Option<String>, pub method: Method }
  pub struct Skipped { pub path: PathBuf, pub why: String }
  pub struct AppGroup { pub name: String, pub mem: u64, pub procs: u32 }
  pub enum Pressure { Normal, Warn, Critical, Unknown }
  pub struct MemInfo { pub total: u64, pub available: u64, pub swap_used: u64, pub swap_total: u64,
      pub pressure: Pressure, pub groups: Vec<AppGroup> }
  pub struct DiskInfo { pub total: u64, pub free: u64, pub scanned: u64, pub unseen: u64, pub trash: u64 }
  pub struct Report { pub os: Os, pub scanned_at: u64, pub disk: DiskInfo, pub memory: MemInfo,
      pub findings: Vec<Finding>, pub skipped: Vec<Skipped>, pub notes: Vec<String> }
  pub fn finding_id(category: Category, key: &str) -> String;   // FNV-1a 64 over "{category:?}\0{key}", "{:016x}"
  ```
  All structs/enums derive `Serialize, Deserialize, Clone, Debug, PartialEq`.
- Produces (`run.rs`):
  ```rust
  pub struct Output { pub status: i32, pub stdout: String, pub stderr: String }
  pub enum RunError { NotFound(String), Timeout, Io(String) }
  pub trait Runner: Send + Sync {
      fn run(&self, argv: &[&str], timeout: Duration) -> Result<Output, RunError>;
      // stdout streamed to `out` (created new; deleted on any error). Non-zero exit → Err(Io("exit N: <stderr>")).
      fn run_to_file(&self, argv: &[&str], timeout: Duration, out: &Path) -> Result<(), RunError>;
      // `input` streamed to stdin. Non-zero exit → Err.
      fn run_from_file(&self, argv: &[&str], timeout: Duration, input: &Path) -> Result<Output, RunError>;
  }
  pub struct SystemRunner { pub tool_dirs: Vec<PathBuf> }      // from platform::tool_dirs() (Task 2)
  impl SystemRunner { pub fn resolve(&self, program: &str) -> Option<PathBuf>; }
  #[cfg(any(test, feature = "fake"))] pub struct FakeRunner;   // new(), on(prefix, result), calls()
  ```
  - `resolve` looks only in `tool_dirs`, never the inherited `PATH`.
  - On Windows it tries the extensions `.exe`, then `.cmd`, then `.bat`.
  - stdout is decoded as UTF-8 lossy. The caller decodes UTF-16 where needed (Task 9, `wsl.exe`).
- Produces (`lock.rs`):
  ```rust
  pub struct InstanceLock(std::fs::File);
  pub fn acquire(data_dir: &Path) -> Result<InstanceLock, String>;   // `<data_dir>/lock`, File::try_lock; Err("Another DevAudit is running")
  ```
- `Ctx` is defined in Task 4, once `platform::KnownDirs` and `rules::Rules` exist.

- [ ] **Step 1: Write failing tests**

```rust
// crates/core/tests/runner.rs — the target is the echo-args helper, so the check doesn't depend on cmd.exe's OEM code page
#[test] fn runner_passes_args_with_spaces_and_unicode_verbatim() {
    let helper = Path::new(env!("CARGO_BIN_EXE_echo-args"));
    let r = SystemRunner { tool_dirs: vec![helper.parent().unwrap().into()] };
    let out = r.run(&["echo-args", "All projects/Café app"], secs(5)).unwrap();
    assert_eq!(serde_json::from_str::<Vec<String>>(&out.stdout).unwrap()[1], "All projects/Café app");
}
#[test] fn runner_times_out() { /* sleep 5 (unix) / `ping -n 6 127.0.0.1` (windows), timeout 200 ms → Timeout */ }
#[test] fn runner_missing_binary_is_not_found() {}
#[test] fn runner_env_is_allowlisted() { /* set FOO_SECRET=x in parent; child `env`/`cmd /c set` output lacks FOO_SECRET */ }
#[test] fn run_to_file_deletes_partial_output_on_failure() { /* command prints then exits 1 → Err, file absent */ }
#[cfg(windows)] #[test] fn cmd_shim_resolved_and_metacharacters_not_executed() {
    /* tempdir with t.cmd ("@echo %*"); resolve("t") finds t.cmd.
       For each arg in ["a&echo INJECTED", "a\"&echo INJECTED", "%PATH%"]: run(["t", arg]) is either
       Err(InvalidInput) or Ok whose stdout does not contain "INJECTED" on its own line and does not expand %PATH%. */
}
#[test] fn finding_id_is_stable() {}
// lock.rs
#[test] fn second_lock_fails() {}
```

- [ ] **Step 2: Run** `cargo test -p devaudit-core` → expect FAIL.
- [ ] **Step 3: Implement.** Timeout: `try_wait` polling every 20 ms, then `kill` + `wait`.
- [ ] **Step 4: Run** → expect PASS on macOS and Windows.
- [ ] **Step 5: Commit** `git init` (first task only), then `git add -A && git commit -m "feat(core): model, sandboxed runner, instance lock"`

---

### Task 2: Platform layer

**Files:**
- Create: `crates/core/src/platform/{mod,macos,windows}.rs`
- Test: `platform/mod.rs` (shared tests) plus per-OS test modules

**Interfaces:**
- Produces (identical signatures on both OSes):
  ```rust
  pub struct KnownDirs { pub home: PathBuf, pub local_app_data: Option<PathBuf>, pub app_data: Option<PathBuf>,
      pub temp: PathBuf, pub personal: Vec<PathBuf>, pub cloud_roots: Vec<PathBuf> }
  pub fn known_dirs() -> KnownDirs;              // Windows: SHGetKnownFolderPath (follows OneDrive redirection) + OneDrive registry roots; debug builds: DEVAUDIT_TEST_ROOT override (Global Constraints)
  pub fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()>;  // macOS renamex_np(RENAME_EXCL); Windows MoveFileExW(flags = 0). Err(AlreadyExists) if `to` exists
  pub fn data_dir(d: &KnownDirs) -> PathBuf;     // ~/.devaudit | %LOCALAPPDATA%\DevAudit
  pub fn tool_dirs(d: &KnownDirs) -> Vec<PathBuf>;
  pub fn canon(p: &Path) -> std::io::Result<PathBuf>;
  pub fn eq_ci(a: &Path, b: &Path) -> bool;      // component-wise, case-insensitive
  pub fn inside(child: &Path, parent: &Path) -> bool;   // component-wise, case-insensitive, after canon
  pub fn file_id(p: &Path) -> std::io::Result<FileId>;  // does NOT follow links. Windows: CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS) + GetFileInformationByHandleEx(FileIdInfo)
  pub fn is_link(md: &std::fs::Metadata) -> bool;       // symlink | junction | any reparse point (Windows)
  pub fn is_cloud_placeholder(md: &std::fs::Metadata) -> bool;  // macOS SF_DATALESS; Windows RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
  pub fn size_on_disk(md: &std::fs::Metadata) -> u64;
  pub fn volume_of(p: &Path) -> std::io::Result<u64>;            // dev / volume serial
  pub fn volume_space(p: &Path) -> std::io::Result<(u64, u64)>;  // (total, free): statfs | GetDiskFreeSpaceExW
  pub fn is_mount_point(p: &Path) -> bool;
  pub fn memory_pressure(available: u64, total: u64, commit_pct: Option<u8>) -> Pressure;   // macOS reads sysctl itself; Windows derives from the args
  pub fn commit_pct() -> Option<u8>;             // Windows: GetPerformanceInfo (CommitTotal / CommitLimit); sysinfo doesn't expose it. macOS: None
  pub fn user_sid() -> Option<String>;           // Windows: GetTokenInformation(TokenUser) + ConvertSidToStringSidW; macOS: None
  pub const VAULT_DIR_NAME: &str;                // macOS "vault.noindex" (Spotlight skips *.noindex; `.metadata_never_index` no longer works); Windows "vault"
  pub fn hide_from_backup_and_index(dir: &Path) -> Result<(), String>;  // macOS: `tmutil addexclusion <dir>` (sticky, no root needed); Windows: FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
  pub fn sync_dir(dir: &Path) -> std::io::Result<()>;            // fsync the dir entry (macOS) / FlushFileBuffers on dir handle (Windows); journal durability
  pub fn graceful_stop(pid: u32) -> Result<(), String>;          // macOS SIGTERM; Windows Err("not supported")
  pub struct ForbiddenRoots { pub exact: Vec<PathBuf>, pub system: Vec<PathBuf> }
  pub fn forbidden_roots(d: &KnownDirs) -> ForbiddenRoots;
  // exact: every drive root / "/", and home itself — a project root may not equal or contain these.
  // system: %WINDIR%, %ProgramFiles%, %ProgramFiles(x86)%, %ProgramData%, /System, /Library, /Applications, /usr, /opt
  //         — a project root may not equal, contain, or be inside these.
  ```
- **Test hooks:** `#[cfg(test)] pub fn fake_volume(path: &Path, volume: u64)` and `#[cfg(test)] pub fn fake_free_space(path: &Path, free: u64)` set thread-local overrides read by `volume_of` and `volume_space`. Tasks 12–14 use them to simulate other drives and full disks.
- `tool_dirs` must include:
  - **macOS:** `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`, `/usr/sbin`, `~/.nvm/versions/node/<highest>/bin`, `~/.volta/bin`, `~/.bun/bin`, `~/.local/bin`
  - **Windows:**
    - `%ProgramFiles%\nodejs`, `%APPDATA%\npm`, `%NVM_SYMLINK%`, `%LOCALAPPDATA%\pnpm`, `%LOCALAPPDATA%\Volta\bin`
    - `%USERPROFILE%\scoop\shims`, `%USERPROFILE%\.local\bin`
    - `%ProgramFiles%\Git\cmd`, `%LOCALAPPDATA%\GitHubDesktop\app-<highest>\resources\app\git\cmd`
    - `%ProgramFiles%\Docker\Docker\resources\bin`, `%ProgramFiles%\dotnet`
    - `%LOCALAPPDATA%\Programs\Python\Python3<highest>\Scripts`
    - `%SystemRoot%\System32`
- **No OS Trash / Recycle Bin is used.** The Recovery vault (Task 13) replaces it, so neither the `trash` crate nor `IFileOperation` is needed.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn inside_is_component_wise_and_case_insensitive() {
    let d = tempdir(); fs::create_dir_all(d.path().join("Dev/app/src")).unwrap(); fs::create_dir_all(d.path().join("Dev/app-old")).unwrap();
    assert!(inside(&d.path().join("dev/APP/src"), &d.path().join("Dev/app")));
    assert!(!inside(&d.path().join("Dev/app-old"), &d.path().join("Dev/app")));
}
#[test] fn symlink_is_link() { /* unix symlink / windows: std::os::windows::fs::symlink_dir may need dev mode → fall back to junction via `cmd /c mklink /J` */ }
#[cfg(windows)] #[test] fn junction_is_link() { /* mklink /J → is_link == true */ }
#[test] fn file_id_changes_when_dir_replaced() { /* id(a); remove a; create a; id differs */ }
#[test] fn file_id_does_not_follow_link() { /* id(link) != id(target) */ }
#[test] fn known_dirs_has_existing_home_and_temp() {}
#[cfg(windows)] #[test] fn canon_resolves_short_names() {
    /* GetShortPathNameW of "Long Folder Name" → if it equals the long form (8.3 names disabled on this volume), skip with a printed note;
       otherwise canon(short) == canon(long) */
}
#[test] fn rename_no_replace_refuses_existing_file_and_empty_dir() { /* target file exists → AlreadyExists, both intact; target empty dir exists → AlreadyExists */ }
#[cfg(windows)] #[test] fn commit_pct_is_some() {}
#[test] fn hide_from_backup_and_index_marks_dir() { /* macOS: `tmutil isexcluded` reports Excluded; Windows: attribute bit set */ }
#[test] fn forbidden_roots_contain_home_and_program_files() {}
#[cfg(windows)] #[test] fn pressure_derivation() {
    assert_eq!(memory_pressure(1, 100, Some(50)), Pressure::Critical);
    assert_eq!(memory_pressure(15, 100, Some(50)), Pressure::Warn);
    assert_eq!(memory_pressure(40, 100, Some(95)), Pressure::Critical);
}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** on both OSes → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): platform layer for macOS and Windows"`

---

### Task 3: Never-touch checks

**Files:**
- Create: `crates/core/src/never.rs`
- Test: same file

**Interfaces:**
- Consumes: `platform::{KnownDirs, canon, inside, is_link, volume_of, is_mount_point, forbidden_roots}`
- Produces:
  ```rust
  pub const NEVER_NAMES: &[&str];                 // spec rule 1, verbatim
  pub const NEVER_HOME_COMMON: &[&str];           // spec rule 2, common part
  pub const NEVER_HOME_MACOS: &[&str];
  pub const NEVER_WINDOWS: &[&str];               // "{appdata}/…", "{localappdata}/…" tokens
  pub const BUILD_DIR_NAMES: &[&str] = &["node_modules",".next",".turbo",".nuxt",".svelte-kit",".parcel-cache","dist","build",".venv","venv","target",".gradle","bin","obj"];   // must equal the names in rules.json build_dirs (test in Task 4)
  pub fn name_is_secret(name: &OsStr) -> bool;
  pub struct NeverCfg<'a> { pub dirs: &'a KnownDirs, pub data_dir: &'a Path, pub project_roots: &'a [PathBuf], pub extra_never: &'a [PathBuf] /* expanded org overlay paths */ }
  pub fn forbidden(path: &Path, cfg: &NeverCfg) -> Option<String>;
  pub fn valid_project_root(root: &Path, d: &KnownDirs) -> Result<(), String>;
  pub fn find_secret_inside(dir: &Path, max_entries: usize) -> Result<Option<PathBuf>, String>;   // Err when the limit is hit (fail closed)
  pub const SECRET_WALK_LIMIT: usize = 500_000;   // a large node_modules is ~100–300k entries; scan and validate both use this limit and both walk again
  ```
- `forbidden` checks, in order; the first hit wins:
  0. **Own data:** the path is inside the data dir or any `.devaudit-vault`. Only `recovery.rs` touches those, and it does not go through `forbidden`.
  1. **Allowed root:** the path is under neither `home` nor any valid project root.
  2. **Depth:** fewer than 2 components below that root.
  3. **Secret name:** any component name is a secret.
  4. **Never-touch path:** any never prefix for this OS matches, any `extra_never` entry matches, or the path is inside a `cloud_roots` entry.
  5. **Personal folder:** the path is inside a personal dir, unless it is inside a project root and its last component is in `BUILD_DIR_NAMES`.
  6. **Link:** the path itself is a link or reparse point.
  7. **Volume:** the path is on a different volume from its allowed root, or is a mount point.
- `valid_project_root` applies `forbidden_roots` as defined in Task 2 (equal/contain for `exact`; equal/contain/inside for `system`). It also rejects a root inside a never-touch path or a cloud root.
- **Which root:** when a path is under both home and a project root (or several project roots), checks 2 and 7 use the **deepest** matching root.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn secret_names_detected_case_insensitively() {
    for n in [".env", ".ENV", ".env.production", ".npmrc", "_netrc", "id_ed25519.pub", "prod.pem", "key.ppk",
              "service-account-x.json", "token", "app.sqlite3", ".git", "Login Data", "Cookies", "Local State"] { assert!(name_is_secret(OsStr::new(n)), "{n}"); }
    for n in ["env.ts", "tokenizer.json", "dist", "cookies.ts", "keyboard.ts"] { assert!(!name_is_secret(OsStr::new(n)), "{n}"); }
}
#[test] fn forbidden_paths_common() { /* home itself, outside home, depth 1, .ssh/x, .SSH/x, .claude/settings.json, Downloads/x, proj/.env.local → Some; .npm/_cacache, .sshfoo/x → None */ }
#[cfg(target_os = "macos")] #[test] fn forbidden_paths_macos() { /* Library/CloudStorage/x, Library/Keychains/x → Some */ }
#[cfg(windows)] #[test] fn forbidden_paths_windows() { /* {appdata}/Microsoft/Protect/x, {localappdata}/Docker/wsl/x, OneDrive root/x → Some */ }
#[test] fn build_dir_in_project_root_under_documents_is_allowed() { /* roots=[Documents/code] → Documents/code/app/node_modules None; Documents/code/app/src Some */ }
#[test] fn overlay_extra_never_forbidden() { /* extra_never=[home/company-data] → home/company-data/x Some */ }
#[test] fn depth_uses_deepest_root() { /* roots=[home/Dev]; home/Dev/app → Some (depth 1 below Dev) even though depth 2 below home */ }
#[test] fn project_root_outside_home_is_allowed_but_drive_root_is_not() {
    /* valid_project_root(tempdir/"work") Ok; valid_project_root(home) Err; Windows: "C:\\" Err, "C:\\Program Files\\X" Err; macOS: "/" Err, "/Applications/X" Err */
}
#[test] fn link_is_forbidden() {}
#[test] fn secret_inside_cache_found() { /* huggingface/token found; hub/ clean */ }
#[test] fn secret_walk_fails_closed_on_limit() {}
#[test] fn secret_walk_does_not_follow_links() { /* cache/link -> dir containing .env → None */ }
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** on both OSes → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): never-touch checks"`

---

### Task 4: Rules, strict-only org overlay, user settings, Ctx

**Files:**
- Create: `rules/rules.json`, `crates/core/src/rules.rs`
- Modify: `crates/core/src/lib.rs` (add `Ctx`)
- Test: same file

**Interfaces:**
- Produces:
  ```rust
  pub enum OsFilter { Any, Macos, Windows }
  pub struct Target { pub id: String, pub os: OsFilter, pub title: String, pub category: Category,
      pub path: String /* tokens: {home} {localappdata} {appdata} {temp} {npm_cache} */,
      pub tier: Tier, pub method: TargetMethod, pub rebuild: String, pub min_idle_days: u32,
      pub owner_processes: Vec<String> /* exe stems or argv script stems; while any runs, the move is refused ("close X first") */ }
  pub enum TargetMethod { Vault, Command(Vec<String>) /* non-undoable only */, PruneOlderThan(u32), Report }
  pub struct Retention { pub safe_days: u32, pub review_days: u32, pub volume_backup_days: u32 }   // defaults 3 / 30 / 30; ranges 0–30 / 7–90 / 7–90
  pub struct BuildDirRule { pub name: String, pub requires_any: Vec<String> /* literal names, or "*.ext" (extension match only) */, pub lockfiles: Vec<String> }
  pub struct Thresholds { pub free_pct: u8, pub swap_pct: u8, pub growth_gb: u32 }
  pub struct Rules { pub targets: Vec<Target>, pub build_dirs: Vec<BuildDirRule>, pub project_roots: Vec<String>,
      pub safe_idle_days: u32, pub recent_days: u32, pub known_daemons: Vec<String>, pub dev_process_patterns: Vec<String>,
      pub extra_never: Vec<String>, pub thresholds: Thresholds, pub retention: Retention,
      pub auto_clean: bool, pub org_overlay_error: Option<String> /* Some → actions::execute refuses everything */ }
  // Org overlay: <data_dir>/org-overlay.json, shipped by IT, never written by DevAudit. Strict-only.
  pub struct Overlay { /* #[serde(default, deny_unknown_fields)] */ pub extra_never: Vec<String>, pub project_roots: Vec<String>,
      pub tier_overrides: HashMap<String, Tier>, pub safe_idle_days: Option<u32>, pub recent_days: Option<u32> }
  // User settings: <data_dir>/settings.json, written only by the app's Settings page / CLI. Can add project roots and set
  // retention within its ranges; cannot touch never-lists, tiers or commands.
  pub struct UserSettings { /* #[serde(default, deny_unknown_fields)] */ pub project_roots: Vec<String>,
      pub retention: Option<Retention>, pub auto_clean: bool }
  pub const ALLOWED_PROGRAMS: &[&str] = &["npm","pnpm","yarn","brew","docker","git","xcrun","pip3","uv","dotnet"];
  pub fn builtin() -> Rules;
  pub fn merge(base: Rules, o: Overlay) -> Result<Rules, String>;
  pub fn apply_user(base: Rules, s: UserSettings) -> Result<Rules, String>;   // Err if retention out of range
  pub fn load(data_dir: &Path) -> (Rules, Vec<String>);
  pub fn save_user(data_dir: &Path, s: &UserSettings) -> Result<(), String>;   // atomic write
  pub fn for_os(r: &Rules, os: Os) -> Vec<&Target>;
  pub fn expand(path: &str, d: &KnownDirs, npm_cache: Option<&Path>) -> Option<PathBuf>;   // None if a token is unavailable on this OS
  ```
- **load:**
  - Org overlay missing → fine. Present but unreadable or invalid → `org_overlay_error = Some(reason)`. Scans still run, but every action is refused until IT fixes the file. Never fall back to the built-in rules silently, because that would drop the org's never-paths.
  - User settings missing → defaults. Invalid → warning, and defaults are used (this can only make rules stricter than the user asked).
- Produces (`lib.rs`):
  ```rust
  pub struct Ctx<'a> { pub os: Os, pub home: PathBuf, pub dirs: platform::KnownDirs, pub data_dir: PathBuf,
      pub run: &'a dyn Runner, pub rules: &'a rules::Rules, pub now: SystemTime, pub pid: u32 }
  impl Ctx<'_> { pub fn never_cfg(&self, project_roots: &[PathBuf]) -> never::NeverCfg<'_>; }
  ```
- **Methods in `rules.json`:**
  - **`Vault`:** package caches (npm `_cacache` and `_npx`, Yarn, pip, uv, NuGet http-cache), Playwright, browser caches, editor CachedData, Xcode DerivedData. These used to run commands; moving the folder instead makes them recoverable.
  - **`Command`:** only `brew cleanup --prune=30`, `pnpm store prune`, `xcrun simctl delete unavailable`, `docker image prune -f`, and `docker builder prune -f --filter until=168h`.
- **`rules.json`:** contains every row of the spec's "Storage targets by OS" table, each with its own `os`. Two notes:
  - Windows Temp: `{temp}`, Safe, `PruneOlderThan(7)`.
  - npm targets use `{npm_cache}/_cacache` and `{npm_cache}/_npx`; `{npm_cache}` comes from `npm config get cache`, falling back to the OS default.
  - **build_dirs** (a build dir counts only when its parent folder contains one of `requires_any`):

    | name | requires_any | lockfiles |
    |---|---|---|
    | `node_modules` | `package.json` | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb` |
    | `.next`, `.turbo`, `.nuxt`, `.svelte-kit`, `.parcel-cache`, `dist`, `build` | `package.json` | same as node_modules |
    | `.venv`, `venv` | `pyproject.toml`, `requirements.txt` | `uv.lock`, `poetry.lock`, `requirements.txt` |
    | `target` | `Cargo.toml` | `Cargo.lock` |
    | `.gradle` | `build.gradle`, `build.gradle.kts` | `gradle.lockfile` |
    | `bin`, `obj` | `*.csproj`, `*.fsproj` | `packages.lock.json` |
  - **Idle and recent days:** `safe_idle_days` 30, `recent_days` 14.
  - **known_daemons:** `codebase-memory-mcp --cbm-daemon-internal`, `pm2` (God Daemon), `ollama serve`. Matched as a substring of the joined command line.
  - **dev_process_patterns:** `node`, `npm`, `npx`, `python`, `python3`, `uv`, `bun`, `deno`, `tsserver`, `esbuild`, `vite`, `next-server`, `turbopack`, plus any stem containing `mcp`. Matched **exactly**, case-insensitively, against the exe stem or the stem of argv[1] (so `uv` doesn't match `uvicorn`, and `node` doesn't match a path containing "node").
  - **owner_processes** for Vault targets. These are matched like dev patterns (exe stem or argv[1] stem), so `npm-cli` matches `node …/npm-cli.js` without matching every node process:
    - npm `_cacache` / `_npx`: `npm`, `npx`, `npm-cli`, `npx-cli`
    - Yarn: `yarn`
    - pip: `pip`, `pip3`
    - uv: `uv`
    - NuGet: `dotnet`, `MSBuild`, `devenv`
    - Chrome cache: `Google Chrome`, `chrome`
    - Edge cache: `Microsoft Edge`, `msedge`
    - Code/Cursor CachedData: `Code`, `Code Helper`, `Cursor`, `Cursor Helper`
    - Xcode DerivedData: `Xcode`, `xcodebuild`
    - Playwright: none by name
  - **Also, for every Vault target** (Task 12 validate): refuse when any process's exe, cwd or any command-line argument is inside the target path. This is what protects running `npx` MCP servers (their scripts live under `_npx`) and Playwright browsers.
  - **thresholds:** `{free_pct: 15, swap_pct: 75, growth_gb: 5}`.
  - **retention:** `{safe_days: 3, review_days: 30, volume_backup_days: 30}`.
- **project_roots defaults:**
  - macOS: `{home}/All projects`, `{home}/Dev`, `{home}/Projects`, `{home}/code`, `{home}/src`, `{home}/Developer`, `{home}/Documents/GitHub`
  - Windows: `{home}/source/repos`, `{home}/Projects`, `{home}/Dev`, `{home}/code`, `{home}/Documents/GitHub`
  - Roots outside home (`C:\Projects`, `D:\work`) are added by the user in Settings and go through `valid_project_root`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn builtin_parses_and_commands_allowlisted() {}
#[test] fn every_target_path_expands_on_its_os() { /* for_os(current) → expand(...) is Some for all */ }
#[test] fn no_windows_target_on_macos_and_vice_versa() {}
#[test] fn overlay_can_tighten() {}
#[test] fn overlay_cannot_loosen() {}
#[test] fn overlay_has_no_command_field() {}
#[test] fn overlay_has_no_retention_field() { /* org-overlay.json with "retention" → org_overlay_error is Some */ }
#[test] fn bad_org_overlay_blocks_actions_not_scans() { /* garbage org-overlay.json → load returns Rules with org_overlay_error Some; no panic */ }
#[test] fn bad_user_settings_is_warning_and_defaults() {}
#[test] fn retention_clamped_to_allowed_ranges() { /* user settings safe_days 99 → Err; review_days 3 → Err; safe_days 0 → Ok */ }
#[test] fn build_dir_names_match_never_list() { /* set of rules.json build_dirs names == never::BUILD_DIR_NAMES */ }
#[test] fn every_vault_cache_target_except_playwright_has_owner_processes() {}
#[test] fn every_command_target_is_marked_non_undoable_in_title_or_reason() {}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): rules, strict org overlay, user settings, Ctx"`

---

### Task 5: Disk walker

**Files:**
- Create: `crates/core/src/disk.rs`
- Test: same file

**Interfaces:**
- Consumes: `platform::{is_link, is_cloud_placeholder, size_on_disk, volume_of}`
- Produces:
  ```rust
  pub struct Usage { pub bytes: u64, pub files: u64, pub newest_mtime: Option<SystemTime>, pub skipped: Vec<Skipped>, pub cancelled: bool }
  pub fn usage(path: &Path, skip_for_mtime: &[&str], cancel: &AtomicBool) -> Usage;
  ```
- **Walk rules:**
  - explicit stack; never descends into links, reparse points or other volumes
  - skips placeholders: neither counted nor opened
  - counts hardlinks once (macOS: `(dev, ino)` when `nlink > 1`; Windows: not detected, see the pnpm estimate in Task 8)
  - permission errors go to `skipped`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(unix)] #[test] fn sparse_file_counts_allocated() {}
#[test] fn links_not_followed() { /* symlink (unix) / junction (windows) to a big dir → bytes small */ }
#[cfg(unix)] #[test] fn hardlinks_counted_once() {}
#[test] fn unreadable_dir_is_skipped() { /* unix chmod 000; windows: icacls deny → skipped.len()==1 */ }
#[test] fn long_paths_and_reserved_names_walk() {
    /* build a 300-char deep path; on windows also create a file named "nul" via \\?\ prefix → walk completes, files counted */
}
#[test] fn cancel_stops_walk() {}
#[test] fn skip_for_mtime_excluded() {}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** on both OSes → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): cross-platform disk walker"`

---

### Task 6: Processes and memory

**Files:**
- Create: `crates/core/src/procs.rs`
- Test: same file (pure functions tested on hand-built `Proc` lists; one smoke test against the real `sysinfo`)

**Interfaces:**
- Consumes: `sysinfo`, `platform::memory_pressure`, `Rules`
- Produces:
  ```rust
  pub struct Proc { pub pid: u32, pub parent: Option<u32>, pub uid_matches_me: bool, pub mem: u64, pub start_time: u64,
      pub exe: Option<PathBuf>, pub cmd: Vec<String>, pub cwd: Option<PathBuf>, pub name: String,
      pub launchd_managed: bool /* macOS: environ has XPC_SERVICE_NAME other than "0"; Windows: false */ }
  pub struct Snapshot { pub procs: Vec<Proc>, pub own_cwd_unreadable: Vec<(u32, String)> /* own-user procs whose cwd couldn't be read */ }
  pub fn snapshot() -> Snapshot;                         // sysinfo refresh: processes(cmd, cwd, exe, memory, user, environ) + memory
  pub fn stem_matches(p: &Proc, names: &[String]) -> bool;   // exact, case-insensitive match on exe stem or argv[1] stem
  pub fn mem_info(s: &Snapshot, sys: &sysinfo::System) -> MemInfo;   // Windows pressure uses platform::commit_pct()
  pub fn group(procs: &[Proc], os: Os) -> Vec<AppGroup>;
  pub fn is_orphan(p: &Proc, all: &[Proc], os: Os) -> bool;
  pub fn findings(ctx: &Ctx, s: &Snapshot) -> Vec<Finding>;
  pub fn start_time_of(pid: u32) -> Option<u64>;         // re-check helper
  ```
- **group:**
  - **macOS:** outermost `.app` → its name.
  - **Windows:**
    - `…\Program Files*\X\…` or `%LOCALAPPDATA%\Programs\X\…` → `X`
    - known exe map: `chrome.exe` → Google Chrome, `msedge.exe` → Microsoft Edge, `Code.exe` → VS Code, `Cursor.exe` → Cursor, `vmmem` / `VmmemWSL` → "WSL / Docker VM", `claude.exe` → Claude Code, `node.exe` → Node.js
    - otherwise the exe stem.
  - **Both:** the VS Code extension path `anthropic.claude-code*` → "Claude Code (VS Code)".
- **is_orphan:**
  - **macOS:** `parent == Some(1)` and not `launchd_managed` (LaunchAgents and pm2-style daemons are deliberate).
  - **Windows:** the parent pid is missing from the snapshot, or the parent's `start_time` is greater than the child's.
  - **Both:** own user, `start_time` more than 1 h ago, `stem_matches(dev_process_patterns)`, no known daemon matches, not `ctx.pid` or any of its ancestors, not a GUI exe (macOS: inside `.app/Contents/MacOS/`; Windows: under Program Files).
- **findings:**
  - Orphan → macOS: Review `Signal`; Windows: Advice ("End it in Task Manager: <name>, pid <pid>").
  - Duplicate MCP servers → Advice.
  - Two Chromium browsers, each > 500 MB → Advice.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn groups_chrome_helpers_mac_and_windows_exe_map() {}
#[test] fn windows_orphan_by_dead_or_younger_parent() { /* parent pid absent → orphan; parent start > child start (pid reuse) → orphan */ }
#[test] fn macos_orphan_by_ppid_1() {}
#[test] fn known_daemon_not_flagged() {}
#[test] fn launchd_managed_not_flagged() {}
#[test] fn dev_pattern_is_exact_stem() { /* "uvicorn" not matched by "uv"; "/Users/x/node-tools/foo" not matched by "node"; "node …/npm-cli.js" matched by "npm-cli" */ }
#[test] fn other_users_and_young_procs_not_flagged() {}
#[test] fn windows_orphan_is_advice_not_signal() {}
#[test] fn mcp_under_live_sessions_is_advice() {}
#[test] fn snapshot_smoke() { let s = snapshot(); assert!(s.procs.iter().any(|p| p.pid == std::process::id())); }
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): processes and memory via sysinfo"`

---

### Task 7: Active-project guard

**Files:**
- Create: `crates/core/src/guard.rs`
- Test: same file (real git in tempdirs; FakeRunner for docker)

**Interfaces:**
- Consumes: `procs::Snapshot`, `Runner`, `platform::inside`, `disk::usage`
- Produces:
  ```rust
  pub struct Activity { pub locked: bool, pub reasons: Vec<String>, pub idle_days: Option<u32> }
  pub struct Guard { pub procs: Vec<procs::Proc> /* kept for validate's running-tool and in-target checks */,
      pub cwds: Vec<(u32, PathBuf)>, pub cmd_paths: Vec<(u32, String)>, pub unreadable: Vec<(u32, String)>,
      pub mounts: Vec<PathBuf>, pub git_available: bool, pub recent_days: u32, pub now: SystemTime }
  pub enum GuardError { NoProcessData }
  pub enum Repo { Git(PathBuf /*toplevel*/), NotARepo, GitMissing, GitFailed(String) }
  impl Guard {
      pub fn build(s: &procs::Snapshot, run: &dyn Runner, recent_days: u32, now: SystemTime) -> Result<Guard, GuardError>;
      pub fn check(&self, project: &Path, run: &dyn Runner) -> Activity;
  }
  pub fn repo_of(path: &Path, run: &dyn Runner) -> Repo;
  pub fn git_ignored(path: &Path, run: &dyn Runner) -> Result<bool, String>;   // true only if `git check-ignore -q` says ignored AND `git ls-files -- <path>` prints nothing (no force-added files inside). Err if git fails
  pub fn normalize_path_text(s: &str) -> String;   // strip `\\?\` and `\\?\UNC\`, `/` → `\` on Windows, trim trailing separators, lowercase
  pub fn normalize_mount(src: &str) -> Option<PathBuf>;   // "/run/desktop/mnt/host/c/Users/x" → C:\Users\x ; "C:\\Users\\x" → same ; unix path unchanged
  ```
- **build:**
  - Returns `Err(NoProcessData)` when no own-user process has a readable cwd.
  - `unreadable` = `s.own_cwd_unreadable`. On Windows this is usually an elevated terminal or editor.
  - `cmd_paths` keeps args longer than 3 characters that contain a path separator, after `normalize_path_text`.
  - Mounts come from `docker ps -q` + `docker inspect --format "{{json .Mounts}}"`, using bind `Source` paths after `normalize_mount`. Docker not running → empty list.
- **check** locks the project when:
  - `unreadable` is non-empty. Fail closed; the reason names the process: "Can't see what <name> (pid N) is working on — it may be running as administrator".
  - any cwd is `inside` it
  - any `cmd_paths` entry contains `normalize_path_text` of the canonical project path **or** of the project path as configured (node often prints `C:/…` or 8.3 forms)
  - any mount is inside it
  - `repo_of` is `GitMissing` or `GitFailed` (the UI says "Install Git so DevAudit can check projects")
  - `Git(_)` and `git status --porcelain` is non-empty
  - idle days < `recent_days`
  - Idle days are the minimum of the newest source mtime and, for a git repo, `git log -1 --format=%ct`.
  - `NotARepo` doesn't lock by itself. Task 8 caps such projects at Review, never Safe.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn no_process_data_fails_closed() {}
#[test] fn one_unreadable_own_process_locks_everything() {}
#[test] fn cwd_inside_locks() {}
#[test] fn sibling_prefix_not_inside() {}
#[test] fn command_line_mention_locks() { /* cmd_paths contains "C:\\Users\\a b\\Dev\\app\\node_modules\\.bin\\next dev" → project Dev/app locked */ }
#[cfg(windows)] #[test] fn command_line_forward_slash_and_verbatim_forms_lock() { /* "c:/users/a b/dev/app/x.js" and project canon "\\\\?\\C:\\Users\\a b\\Dev\\app" → locked */ }
#[test] fn not_a_repo_is_not_locked_but_git_missing_is() {}
#[test] fn force_added_file_in_ignored_dir_is_not_ignored() { /* dist/ in .gitignore, `git add -f dist/keep.txt` → git_ignored false */ }
#[test] fn docker_mount_forms_normalised() {
    assert_eq!(normalize_mount("/run/desktop/mnt/host/c/Users/x"), Some(PathBuf::from(r"C:\Users\x")));   // windows only cfg
}
#[test] fn dirty_repo_locked() {}
#[test] fn old_clean_repo_unlocked_with_idle_days() {}
#[test] fn git_missing_fails_closed() {}
#[test] fn gitignored_node_modules() {}
#[test] fn worktree_recognised() {}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): active-project guard"`

---

### Task 8: Project build-dir discovery and tiering

**Files:**
- Create: `crates/core/src/projects.rs`
- Test: same file

**Interfaces:**
- Consumes: `Ctx`, `Rules`, `Guard`, `git_ignored`, `disk::usage`, `platform::file_id`, `never::{forbidden, valid_project_root}`
- Produces:
  ```rust
  pub struct BuildDir { pub project: PathBuf, pub dir: PathBuf, pub rule: String }
  pub fn roots(ctx: &Ctx) -> (Vec<PathBuf>, Vec<String> /*warnings for rejected roots*/);
  pub fn discover(roots: &[PathBuf], rules: &[BuildDirRule], max_depth: usize) -> Vec<BuildDir>;   // max_depth 6
  pub fn findings(ctx: &Ctx, guard: Result<&Guard, &GuardError>, cancel: &AtomicBool) -> (Vec<Finding>, Vec<Skipped>);
  ```
- **Tiering:** the same table as in the spec. Every finding sets `project: Some(project)`.
  - **Safe** → `Vault { id, keep_days: retention.safe_days }`. Requires `Repo::Git`, `git_ignored == Ok(true)`, idle ≥ `safe_idle_days`, and a lockfile.
  - **Review** → `Vault { id, keep_days: retention.review_days }`. This covers everything unlocked that isn't Safe, including `Repo::NotARepo` projects.
  - **Protected:** locked, inside a git repo but not ignored, or `git_ignored` errs.
  - **pnpm projects** (a `pnpm-lock.yaml` exists): `bytes_estimate = true`, and the reason adds "shared with pnpm store — may free less".
- **Discovery:** does not descend into build dirs, `.git`, `.devaudit-vault`, links or reparse points. The idle-time mtime walk skips the same names.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn discovers_in_roots_with_spaces_and_unicode() {}
#[test] fn ignores_node_modules_without_package_json() {}
#[test] fn nested_node_modules_reported_once() {}
#[test] fn does_not_follow_symlink_or_junction() {}
#[test] fn idle_ignored_with_lockfile_is_safe_vault_3_days() {}
#[test] fn missing_lockfile_is_review_vault_30_days() {}
#[test] fn committed_dist_is_protected() {}
#[test] fn guard_error_protects_everything() {}
#[test] fn non_git_project_is_review_never_safe() {}
#[test] fn devaudit_vault_not_discovered() {}
#[test] fn pnpm_project_marked_estimate() {}
#[test] fn invalid_project_root_rejected_with_warning() { /* overlay root = home → warning, not scanned */ }
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): project build-dir findings"`

---

### Task 9: Targets, Temp prune, Claude, WSL, advice

**Files:**
- Create: `crates/core/src/targets.rs`
- Test: same file

**Interfaces:**
- Consumes: `Ctx`, `rules::{for_os, expand}`, `disk`, `never`, `guard`, `Runner`
- Produces:
  ```rust
  pub fn npm_cache_dir(ctx: &Ctx) -> Option<PathBuf>;   // `npm config get cache`, validated: must be under home and not forbidden
  pub fn target_findings(ctx: &Ctx, cancel: &AtomicBool) -> (Vec<Finding>, Vec<Skipped>);
  pub fn claude_findings(ctx: &Ctx, guard: Result<&Guard, &GuardError>, roots: &[PathBuf]) -> Vec<Finding>;
  pub fn wsl_findings(ctx: &Ctx) -> Vec<Finding>;      // Windows only; macOS returns empty
  pub fn advice_findings(ctx: &Ctx, mem: &MemInfo) -> Vec<Finding>;
  pub fn parse_wsl_list(utf16le: &[u8]) -> Vec<(String /*name*/, String /*state*/, u8 /*version*/)>;
  ```
- **target_findings:**
  - Methods: Vault / Command / Report.
  - `min_idle_days` downgrade: if the target's newest mtime is younger than `min_idle_days`, the tier is raised one step (Safe → Review, Review → Protected).
  - The secret-inside check (`find_secret_inside`, `SECRET_WALK_LIMIT`) applies to every Review-tier Vault target. A hit or a limit error → Protected.
  - `owner_processes` is copied onto the finding.
  - **PruneOlderThan targets:** collect regular files older than N days. Never descend into links, and skip any file where a component below the base is a secret name (`name_is_secret`) or `forbidden` returns Some. bytes = the sum of the collected files only. Tier Safe.
- **claude_findings** (all paths from `{home}/.claude`; settings files are on the never list and are never read except `cleanupPeriodDays`):
  - **Transcripts:** each subfolder of `{home}/.claude/projects/` is one finding, Category `AiTool`, Method `Vault` with `review_days`.
    - Protected if any file inside was modified within `recent_days`, or a running `claude` process (or the VS Code extension) has a cwd whose encoded form matches the folder name. Claude encodes a cwd by replacing every path separator and `.` with `-`.
    - Otherwise Review. Transcripts are never Safe, since they're not rebuildable.
  - **Worktrees:** for every git repo found under the project roots, parse `git worktree list --porcelain`. Keep the worktrees whose path is inside `<repo>/.claude/worktrees/`.
    - Method `WorktreeVault { repo, worktree, id, branch, keep_days: review_days }`, with `project: Some(worktree)`.
    - Protected if `Guard::check(worktree)` is locked (dirty, recent, cwd inside…), the worktree is detached (no branch), or `find_secret_inside` finds anything. Otherwise Review.
- **wsl_findings:**
  - Run `wsl.exe -l -v` (UTF-16LE output).
  - For each distro, find its `ext4.vhdx` under `{localappdata}/Packages/*/LocalState/` or the Docker paths, and add a Report-only finding with its size.
  - Add one Advice: "WSL disk images don't shrink by themselves — see Settings › Help". The exact compaction steps are written up in `docs/WINDOWS-NOTES.md` after they are checked on a real WSL ≥ 2.0 machine in Task 16.
- **advice_findings:**
  - Claude `cleanupPeriodDays` missing.
  - MCP `@latest` duplicates.
  - **Windows:** "Windows Update cleanup and hibernation file — Settings › System › Storage › Cleanup recommendations", only when free < 15%.
  - **macOS:** a System Data explanation.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn npm_cache_from_config_is_validated() { /* FakeRunner returns "/etc" → falls back to default; returns home/.npm-alt → used */ }
#[test] fn missing_targets_produce_nothing() {}
#[test] fn review_vault_target_with_secret_inside_protected() {}
#[test] fn browser_cache_target_never_includes_profile_secrets() { /* Default/Cache sibling "Login Data" not inside target; Cache itself clean → Review */ }
#[test] fn temp_prune_counts_only_old_files() { /* 2 files: 10 days old, today → bytes == old only */ }
#[test] fn temp_prune_skips_secret_names() { /* old files cert.pfx, x/token, a.txt → only a.txt collected */ }
#[test] fn worktree_with_env_file_protected() {}
#[test] fn parse_wsl_list_utf16() { /* fixture bytes for "  NAME STATE VERSION\r\n* Ubuntu Running 2\r\n  docker-desktop Stopped 2" */ }
#[test] fn dirty_claude_worktree_protected_clean_one_review() {}
#[test] fn recent_transcript_dir_protected() {}
#[test] fn settings_read_does_not_leak_other_keys() {}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): caches, temp, AI tools, WSL and advice"`

---

### Task 10: Docker findings

**Files:**
- Create: `crates/core/src/docker.rs`, fixtures `crates/core/tests/fixtures/docker_*.txt` (one set recorded on macOS, one on Windows, anonymised)
- Test: same file

**Interfaces:**
- Produces:
  ```rust
  pub struct VmInfo { pub memory_bytes: Option<u64>, pub memory_source: &'static str /* "Docker settings" | ".wslconfig" | "WSL default (50% RAM)" */, pub disk_image_bytes: Option<u64> }
  pub struct DockerScan { pub running: bool, pub vm: VmInfo, pub containers: Vec<(String /*id*/, String /*name*/, Option<String> /*project*/, u64)>, pub findings: Vec<Finding>, pub notes: Vec<String> }
  pub fn scan(ctx: &Ctx, ram_total: u64, swap_used_pct: u8) -> DockerScan;
  pub fn read_vm(ctx: &Ctx, ram_total: u64) -> VmInfo;
  pub fn parse_wslconfig_memory(text: &str) -> Option<u64>;   // "[wsl2]\nmemory=6GB" → 6 GiB; reads only memory=
  ```
- **read_vm:**
  - **macOS:** `memoryMiB` from Docker's settings; the image is `Docker.raw`, size from metadata only.
  - **Windows:** `.wslconfig` `memory=`; if absent, `ram_total / 2` with source "WSL default (50% RAM)". The image is the largest `*.vhdx` under `{localappdata}/Docker/wsl`, size from metadata only.
- **Findings:**
  - dangling images and build cache: `Command`, non-undoable
  - each unused volume: Review, `DockerVolumeBackupRm{name}`
  - monitoring-container stop groups: `DockerStop { container_ids }`, grouped per compose project (`com.docker.compose.project` label). Monitoring images are `grafana/*`, `prom/*`, `*/prometheus`, `*/loki`, `*/tempo`, `*/alloy`, `*/promtail`, `*/jaeger*`, `otel/*`. Review tier. Protected if any container in the group bind-mounts a locked project.
  - allowance advice
- **Docker not installed or not running:** a note only; never start Docker.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn not_running_is_note_only() { /* FakeRunner: `docker info` fails → running false, no findings, one note; no `docker` call other than info */ }
#[test] fn macos_fixture_parses() { /* recorded `docker ps -a --format {{json .}}`, `docker volume ls`, `docker system df -v`, `docker inspect` */ }
#[test] fn volume_used_by_stopped_container_not_offered() {}
#[test] fn unused_volume_is_review_backup_rm() {}
#[test] fn dangling_images_and_build_cache_are_non_undoable_commands() { /* argv exactly ["docker","image","prune","-f"] and ["docker","builder","prune","-f","--filter","until=168h"] */ }
#[test] fn never_prune_all_or_volumes() { /* no finding's argv contains "-a", "--all", "--volumes", "down", "rm" */ }
#[test] fn monitoring_stack_grouped_per_compose_project() { /* grafana+prometheus+loki in project "obs" → one DockerStop with 3 ids */ }
#[test] fn container_bind_mounting_active_project_not_stoppable() {}
#[test] fn mac_allowance_advice_when_over_half_ram_and_swap_high() {}
#[test] fn docker_raw_size_from_metadata_only() {}
#[test] fn wslconfig_parse() { assert_eq!(parse_wslconfig_memory("[wsl2]\nmemory=6GB\nswap=0"), Some(6 << 30)); assert_eq!(parse_wslconfig_memory("[wsl2]\nprocessors=4"), None); }
#[test] fn wsl_default_half_ram_advice() { /* windows, no .wslconfig, ram 16 GiB, swap 80% → Advice mentions "50%" */ }
#[test] fn wslconfig_other_keys_not_stored() { /* .wslconfig with kernelCommandLine=secret → nothing contains "secret" */ }
#[test] fn windows_fixture_parses() {}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): docker findings incl. WSL allowance"`

---

### Task 11: Report assembly, save, history, growth

**Files:**
- Create: `crates/core/src/report.rs`
- Test: same file

**Interfaces:**
- Produces:
  ```rust
  pub fn scan(ctx: &Ctx, cancel: &AtomicBool, progress: &dyn Fn(&str)) -> Report;
  pub fn save(report: &Report, data_dir: &Path) -> Result<(), String>;
  pub fn load_last(data_dir: &Path) -> Option<Report>;
  pub struct Growth { pub category: Category, pub delta_bytes: i64 }
  pub fn growth(data_dir: &Path, current: &Report) -> Vec<Growth>;
  pub fn ensure_data_dir(d: &KnownDirs) -> Result<PathBuf, String>;
  ```
- **Order:** `procs::snapshot` → `Guard::build` → projects → targets → claude → wsl → docker → advice. Then sort by tier, then bytes.
- **`disk.unseen`** (computed for the home volume):
  - macOS: `used − usage(home) − usage(/Applications)`
  - Windows: `used − usage(home) − usage(%ProgramFiles%)` − the image sizes already counted
  - floored at 0
- **`disk.trash`:**
  - macOS: `~/.Trash`, or 0 with a note when it can't be read
  - Windows: `SHQueryRecycleBinW` for the home drive

- [ ] **Step 1: Write failing tests**
  - `report_file_private`: macOS mode 0600 / dir 0700; on Windows the file is created inside a data dir under a hand-built `KnownDirs` whose `local_app_data` is a tempdir
  - `save_failure_is_error_not_panic`
  - `growth_reports_delta_per_category`
  - `findings_sorted_by_tier_then_size`
  - `report_contains_no_file_contents`
  - `report_fixture_is_current`: builds a `Report` containing one finding of every `Method` variant and every `Tier`, and compares its JSON with `crates/core/tests/fixtures/report.json`. With `UPDATE_FIXTURES=1` it rewrites the file instead. The app's `types_match_core_fixture` test reads this file.
- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): report, history, growth"`

---

### Task 12: Preview and re-validation

**Files:**
- Create: `crates/core/src/actions.rs` (part 1), `crates/core/src/recovery.rs` (`vault_for` only; the rest is Task 13)
- Test: same files

**Interfaces:**
- Produces:
  ```rust
  pub struct PlannedItem { pub id: String, pub title: String, pub what_runs: String, pub undo: String, pub permanent: bool, pub bytes: u64, pub blocked: Option<String> }
  pub struct Plan { pub token: String, pub report_scanned_at: u64, pub items: Vec<PlannedItem>, pub created: SystemTime }
  pub fn preview(ctx: &Ctx, report: &Report, ids: &[String]) -> Plan;   // builds a fresh procs::snapshot + Guard::build itself
  pub fn validate(ctx: &Ctx, f: &Finding, guard: Result<&Guard, &GuardError>) -> Result<(), String>;
  // recovery.rs (Task 12 part):
  pub fn vault_for(path: &Path, ctx: &Ctx) -> Result<PathBuf, String>;   // see Task 13 for the rules; creates + hides the vault dir
  ```
- **preview:**
  - `token`: 32 hex characters from `getrandom` (add the `getrandom` crate).
  - `what_runs` examples: `Move to Recovery (kept 3 days): …/node_modules`, `Run: brew cleanup --prune=30`.
  - `undo` examples: "Recoverable for 3 days", "Back up 1.2 GB, then remove — recoverable for 30 days", "Start again from History", "Can't be undone — re-downloads when needed". With retention 0: "Not recoverable — retention is set to 0 days", and `permanent = true`.
- **validate** runs these checks in order:
  0. `ctx.rules.org_overlay_error` is Some → refused with that reason.
  1. Protected or `None` → refused.
  2. **Path methods** (`Vault`, `WorktreeVault`):
     - `forbidden(path, ctx.never_cfg(roots))`
     - `file_id` differs → "changed since scan"
     - **only when `f.project` is Some:** the project is now locked (`guard.check`), or the guard errs; and, if `repo_of(project)` is `Git`, `git_ignored(path)` must be `Ok(true)`. The ignored check doesn't apply to `WorktreeVault`, because the worktree is its own checkout.
     - any `guard.procs` entry `stem_matches(f.owner_processes)` → "Close <name> first"
     - any `guard.procs` entry has its exe, cwd or a command-line argument inside `path` → "In use by <name> (pid N)"
     - for Review-tier items: `find_secret_inside(path, SECRET_WALK_LIMIT)` must be `Ok(None)`
     - `recovery::vault_for(path)` returns Ok, so a same-volume vault is available
  3. **PruneOlderThan:** the path still equals `ctx.dirs.temp`.
  4. **Command:** `argv[0]` is in `ALLOWED_PROGRAMS`, and no `guard.procs` entry `stem_matches([argv[0], argv[0] + "-cli"])` is running. The `-cli` form catches `node …/npm-cli.js`; `pnpm` and `yarn` also match `pnpm.cjs` and `yarn.js` by stem.
  5. **WorktreeVault** (in addition to 2): `git -C repo worktree list --porcelain` still lists the worktree with the same branch, `git status --porcelain` inside it is empty, and no cwd is inside it.
  6. **DockerVolumeBackupRm:**
     - no container references the volume
     - at least one local image exists
     - free space on the data-dir volume ≥ 1.1 × the volume size (`docker system df -v`)
  7. **DockerStop:** the containers are still running.
  8. **Signal:**
     - Windows → always Err("not supported on Windows").
     - macOS: `start_time_of(pid)` must match the recorded start, and the pid is not the tool's own.

- [ ] **Step 1: Write failing tests**
  - `protected_never_validates`
  - `link_swap_after_scan_refused` (symlink on macOS, junction on Windows)
  - `replaced_dir_new_identity_refused`
  - `project_became_active_refused`
  - `secret_added_after_scan_blocks_review_vault_move`
  - `bad_org_overlay_refuses_everything`
  - `cache_move_refused_while_owner_runs` (fake proc `Code Helper` → CachedData refused)
  - `cache_move_refused_while_process_runs_from_inside` (fake proc argv `…/_npx/abc/node_modules/x/cli.js` → `_npx` refused)
  - `non_project_cache_skips_git_checks` (cache outside any repo validates Ok)
  - `command_refused_while_tool_running` (includes `node …/pnpm.cjs install` blocking `pnpm store prune`)
  - `non_allowlisted_program_refused`
  - `pid_reuse_refused` (macOS)
  - `signal_refused_on_windows`
  - `no_same_volume_vault_refused` (`platform::fake_volume` puts the item on volume 2 and makes its project root's `.devaudit-vault` uncreatable)
  - `volume_now_in_use_refused`
  - `volume_backup_without_space_refused`
  - `preview_shows_undo_text_for_every_item`
  - `unknown_id_blocked_in_preview`
  - `preview_wording_per_os`
- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): preview and re-validation"`

---

### Task 13: Recovery vault

**Files:**
- Create: `crates/core/src/recovery.rs`
- Test: same file

**Interfaces:**
- Consumes: `platform::{volume_of, file_id, is_link, hide_from_backup_and_index, sync_dir, inside, rename_no_replace, VAULT_DIR_NAME}`, `never::forbidden`, `guard::repo_of`, `lock::InstanceLock`, `Runner`
- Produces (every mutating function takes `&InstanceLock`, see Global Constraints):
  ```rust
  pub enum EntryState { Moving, Held, Restoring, Purging, Orphaned /* journal couldn't be resolved; never purged automatically */ }
  pub enum EntryKind { Path, TempFiles { base: PathBuf }, DockerVolume { name: String }, DockerStopped { ids: Vec<String> },
      Worktree { repo: PathBuf, branch: String } /* payload = the worktree folder */ }
  pub struct Entry { pub id: String, pub kind: EntryKind, pub title: String, pub original: Option<PathBuf>, pub bytes: u64,
      pub tier: Tier, pub moved_at: u64, pub expires_at: Option<u64>, pub state: EntryState, pub vault_dir: PathBuf,
      pub note: Option<String> /* "drive not connected", "unreadable — restore by hand", "partly purged" */ }
  pub fn vault_for(path: &Path, ctx: &Ctx) -> Result<PathBuf, String>;   // (built in Task 12)
  pub fn move_in(ctx: &Ctx, l: &InstanceLock, path: &Path, kind: EntryKind, title: &str, tier: Tier, keep_days: u32) -> Result<Entry, String>;
  pub fn move_files_in(ctx: &Ctx, l: &InstanceLock, files: &[PathBuf], base: &Path, title: &str, keep_days: u32) -> Result<(Entry, Vec<String> /*skipped*/), String>;  // Temp prune; keeps relative layout under payload/
  pub fn backup_volume(ctx: &Ctx, l: &InstanceLock, name: &str, bytes: u64, keep_days: u32) -> Result<Entry, String>;
  pub fn record(ctx: &Ctx, l: &InstanceLock, kind: EntryKind, title: &str) -> Result<Entry, String>;   // DockerStopped only: no payload, undo metadata, never expires
  pub fn list(ctx: &Ctx) -> Vec<Entry>;
  pub fn total_held(ctx: &Ctx) -> u64;
  pub fn restore(ctx: &Ctx, l: &InstanceLock, id: &str) -> Result<PathBuf /*restored to*/, String>;
  pub fn purge(ctx: &Ctx, l: &InstanceLock, id: &str) -> Result<u64 /*bytes freed*/, String>;
  pub fn purge_expired(ctx: &Ctx, l: &InstanceLock) -> (u64, Vec<String>);
  pub fn repair(ctx: &Ctx, l: &InstanceLock) -> Vec<String>;   // journal recovery, run at start of every scan/execute/CLI command
  ```
- **vault_for:**
  - Same volume as `data_dir` → `<data_dir>/<VAULT_DIR_NAME>`.
  - Else, the deepest project root containing `path` that is on the same volume → `<root>/.devaudit-vault/<VAULT_DIR_NAME>`. If `repo_of(root)` is `Git`, append `.devaudit-vault/` to that repo's `.git/info/exclude` (create it if needed), so the vault never shows in `git status` and can't be committed.
  - Otherwise Err("no Recovery space on this drive"). Never copy across volumes.
  - The vault dir is created 0700 (macOS) and passed to `hide_from_backup_and_index`.
- **Index:** `<data_dir>/vault-index.json` (atomic write) lists every vault dir in use, and for each one its entries' id, title, bytes and `expires_at`. It is updated on every move-in, restore and purge. `list` reads the manifests in every listed dir. When a dir is unreachable, its index rows are shown with the note "drive not connected".
- **Manifest writes** (every state change): write `manifest.json.tmp`, `sync_all` it, `std::fs::rename` it over `manifest.json`, then `sync_dir(entry_dir)`. This is the one place where replacing is intended.
- **move_in:**
  1. `vault_for(path)`. Cross-volume (`volume_of(path) != volume_of(vault)`) → Err before anything is created.
  2. Create `<vault>/<id>/`. `id` = `{yyyyMMdd-HHmmss}-{8 hex random}`.
  3. Write `manifest.json` (state `Moving`) and `README.txt`.
  4. `rename_no_replace(path, <vault>/<id>/payload)`. On error, remove the entry dir and return Err("in use — skipped (close apps using this folder)"); nothing changes.
  5. Set state `Held`.
  6. `keep_days == 0` → the caller (Task 14) purges right away. `move_in` itself never deletes.
- **move_files_in** (Temp): one entry, state `Moving` first. Each file goes via `rename_no_replace` to `payload/<path relative to base>`, creating parent dirs. A file whose rename fails is skipped and listed. The manifest records the list of moved relative paths. Then `Held`.
- **README.txt** (fixed template plus the original path):
  ```
  This folder was moved here by DevAudit on <date>.
  To restore it by hand, move the "payload" folder back to:
    <original>
  It is deleted permanently after <expiry> unless you restore it.
  ```
- **restore** (refused when state is `Purging` or `Orphaned`):
  1. **Target check:** `forbidden(original)` must return None, **ignoring only** the depth and existence parts. Every existing ancestor of `original`, up to its allowed root, must not be a link or mount point.
  2. **Create missing parents** one level at a time, re-checking that each new dir is not a link.
  3. Write state `Restoring`.
  4. `rename_no_replace(payload, original)`. On `AlreadyExists`, retry with `<original>.restored-<yyyyMMdd-HHmmss>`, then `-2`, `-3`… Never overwrite.
  5. Remove the entry dir.
  - **Per kind:**
    - `TempFiles`: per file, `rename_no_replace(payload/<rel>, base/<rel>)`; a collision goes beside the file as `<name>.restored-<date>`. Files already restored are skipped, so a crashed restore can be run again. The entry is removed when the payload is empty.
    - `Worktree`: rename back as above, then `git -C repo worktree repair <original>`. If the target had to be renamed beside, skip `repair` and say so in the message.
    - `DockerVolume`: if a volume named `<name>` exists, restore as `<name>-restored-<yyyyMMdd>`; never write into an existing volume. Then `docker volume create`, `docker create -v <vol>:/v <first local image id> devaudit-noop`, `run_from_file(["docker","cp","-","<cid>:/v"], payload/volume.tar)`, `docker rm <cid>`.
    - `DockerStopped`: `docker start <ids>`, then remove the entry.
- **purge:**
  1. Set state `Purging` (restore is now refused).
  2. `remove_dir_all(<entry>/payload)`, retrying once after clearing read-only attributes on Windows.
  3. For `Worktree`: `git -C repo worktree prune`.
  4. Remove the entry dir.
  - **Partial failure:** the entry stays in `Purging` with note "partly purged"; the next purge continues. It is never restored half-empty.
- **purge_expired:** only entries in state `Held` with `expires_at < now`. Skip entries with an unreadable manifest, and `Orphaned` ones.
- **repair:**
  - `Moving` + payload present → `Held`.
  - `Moving` + payload missing + original present → remove the entry dir (the move never happened).
  - `Moving` + payload missing + original missing → `Orphaned`, with a note. Never delete.
  - `Restoring` + payload present → `Held`.
  - `Restoring` + payload missing → remove the entry dir. For `TempFiles`: run the restore again.
  - `Purging` → resume the purge.
  - Unreadable manifest → leave the entry untouched; `list` shows it as "unreadable — restore by hand".
- **backup_volume:**
  1. `docker create -v <name>:/v <first local image id> devaudit-noop`. A command must be given, because images without CMD/ENTRYPOINT fail with "No command specified". The container is never started, so the command doesn't need to exist.
  2. Manifest `Moving`, then `run_to_file(["docker","cp","<cid>:/v","-"], 600 s, payload/volume.tar)`. Timeout or non-zero exit → Err, and the partial tar is deleted.
  3. `docker rm <cid>`, always, even on error.
  4. **Verify:** the tar reads to its end-of-archive marker (two zero blocks), and its size is ≥ 0.9 × `bytes` (from `docker system df -v`). Failing either → Err, and the entry is removed.
  5. State `Held`. Only the caller (Task 14) runs `docker volume rm` after this returns Ok.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn move_in_then_restore_round_trip() { /* dir with files → move_in → original gone, payload has files → restore → identical tree at original */ }
#[test] fn restore_beside_when_original_exists() { /* recreate original after move_in → restore → "<name>.restored-*" exists, original untouched */ }
#[test] fn restore_never_overwrites_empty_dir_created_meanwhile() { /* original recreated as an EMPTY dir → restored beside, empty dir untouched */ }
#[test] fn restore_of_depth_two_cache_allowed() { /* home/.npm/_cacache moved → restore succeeds even though home/.npm is depth 1 */ }
#[test] fn restore_refused_when_parent_became_link() {}
#[test] fn restore_recreates_missing_parent() {}
#[test] fn restore_refused_while_purging() {}
#[test] fn cross_volume_move_refused_without_copy() { /* platform::fake_volume → Err, source untouched, no entry dir */ }
#[test] fn failed_rename_leaves_no_entry() { /* source path missing → Err, vault has no new entry dir */ }
#[test] fn repair_rolls_forward_and_back() { /* every row of the repair table, hand-written manifests → expected state; the "both missing" case → Orphaned, nothing deleted */ }
#[test] fn purge_frees_and_removes_entry() {}
#[test] fn partial_purge_stays_purging_and_resumes() {}
#[test] fn purge_expired_only_touches_expired_held() { /* expiring yesterday Held, tomorrow Held, yesterday Orphaned, yesterday unreadable → only the first purged */ }
#[test] fn readme_contains_original_path() {}
#[test] fn vault_hidden_from_backup_and_index() {}
#[test] fn project_root_vault_excluded_from_git() { /* root is a repo → .git/info/exclude contains ".devaudit-vault/", `git status --porcelain` empty */ }
#[test] fn unreachable_vault_listed_as_drive_not_connected() { /* index lists a deleted dir → entry note "drive not connected" */ }
#[test] fn list_survives_corrupt_manifest() { /* garbage manifest.json → entry listed as "unreadable — restore by hand", not a crash */ }
#[test] fn long_path_and_unicode_round_trip() {}
#[test] fn temp_files_move_and_restore_per_file() { /* 3 files, one locked (Windows) / one removed mid-way (unix) → skipped listed; restore puts each back at base/<rel>; one collision restored beside */ }
#[test] fn worktree_round_trip() { /* real git: add worktree, move_in(kind Worktree) → `git worktree list` shows prunable; restore → repair → listed normally; .env inside survives */ }
#[test] fn docker_volume_backup_and_restore_with_fake_runner() { /* calls: create … devaudit-noop → cp (to file) → rm; restore: volume create → create → cp (from file) → rm */ }
#[test] fn truncated_volume_backup_rejected() { /* fake tar without end marker, or < 0.9 × bytes → Err, no entry left */ }
#[test] fn mutating_fns_require_lock() { /* compile-level: calling move_in needs &InstanceLock — covered by signatures; this test just acquires and runs one */ }
```

- [ ] **Step 2: Run** `cargo test -p devaudit-core recovery` → expect FAIL. **Step 3: Implement.** **Step 4: Run** on both OSes → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): recovery vault with journal, restore and purge"`

---

### Task 14: Execute and action log

**Files:**
- Modify: `crates/core/src/actions.rs` (part 2)
- Test: same file

**Interfaces:**
- Produces:
  ```rust
  pub struct Outcome { pub id: String, pub ok: bool, pub message: String, pub bytes: u64, pub undo_entry: Option<String> /* vault entry id → UI "Restore" link */ }
  pub struct LogLine { pub ts: u64, pub id: String, pub title: String, pub phase: String /* "intent" | "result" */,
      pub ok: Option<bool>, pub message: String, pub undo_entry: Option<String> }
  pub const PLAN_TTL: Duration = Duration::from_secs(300);
  pub fn execute(ctx: &Ctx, l: &InstanceLock, report: &Report, plan: &Plan, token: &str, ack_irreversible: bool) -> Result<Vec<Outcome>, String>;
  pub fn auto_clean(ctx: &Ctx, l: &InstanceLock, report: &Report) -> Vec<Outcome>;
  pub fn read_log(data_dir: &Path, limit: usize) -> Vec<LogLine>;   // newest first; reads the current and the rotated file
  ```
- **Plan-level refusals:** the token is wrong, the plan has expired, the report is stale, or `ctx.rules.org_overlay_error` is Some.
- **First:** `recovery::repair` runs before anything else. Then a fresh `procs::snapshot` + `Guard::build` is made once for this call and passed to every `validate`.
- **Per item:** validate again, then log the intent, then act, then log the result. One failure doesn't stop the others.
- **Vault:** `recovery::move_in(kind Path)`. If the rename fails: `ok=false`, "in use — skipped (close apps using this folder)", and nothing changes. If `keep_days == 0`: `recovery::purge` straight after, and the message says "not recoverable (retention 0)".
- **WorktreeVault:** `recovery::move_in(kind Worktree { repo, branch })`. Never `git worktree remove`.
- **PruneOlderThan:** gather files as in Task 9 (old, not links, no secret names, not forbidden), then `recovery::move_files_in`. Locked files are skipped and counted in the message.
- **DockerVolumeBackupRm:** `recovery::backup_volume`, and only on Ok, `docker volume rm <name>` (never `-f`). If the rm fails, the backup entry stays and the message says so.
- **DockerStop:** `docker stop <ids>`, then `recovery::record(DockerStopped)`.
- **Command:** 600 s timeout.
- **Signal** (macOS): `start_time_of(pid)` is checked once more immediately before `platform::graceful_stop(pid)` (SIGTERM only, never SIGKILL). The message is "Asked <name> to quit (pid N)". Windows never gets here, because validate refuses.
- **Non-undoable items** (`Command`, `Signal`, and any Vault item with `keep_days == 0`) run only if `execute` received `ack_irreversible: true`; otherwise `ok=false`, "needs confirmation". The CLI asks a second question; the app has a separate checkbox.
- **auto_clean:** selects only findings with tier Safe, category `PackageCache` and `Method::Vault` with `keep_days > 0`. It runs them through `preview` + `execute` with `ack_irreversible = false`, so it can never run a Command, Signal or Docker action.
- **Log:** `actions.jsonl` in the data dir, one `LogLine` per line, rotated at 5 MB to `actions.1.jsonl` (one old file kept). If the intent line can't be written, refuse to start.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn wrong_token_refused() {}
#[test] fn expired_plan_refused() {}
#[test] fn stale_report_refused() {}
#[test] fn bad_org_overlay_refuses_execute() {}
#[test] fn vault_move_logs_and_returns_undo_entry() {}
#[cfg(windows)] #[test] fn open_file_without_share_delete_means_skipped_and_intact() {
    /* open node_modules/x/index.js without FILE_SHARE_DELETE; execute Vault → ok=false, "in use", and every original file still exists */
}
#[cfg(windows)] #[test] fn open_file_with_share_delete_is_caught_by_guard() {
    /* the same file opened WITH FILE_SHARE_DELETE (as VS Code/node do) by a child process whose cwd is the project → validate refuses (project locked) */
}
#[test] fn vault_move_keeps_inner_link_untouched() { /* .next contains link → after move and purge, keep/file survives */ }
#[test] fn vault_move_handles_long_paths_and_reserved_names() {}
#[test] fn worktree_is_vaulted_not_removed() { /* FakeRunner records no "worktree remove"; worktree dir is in the vault with its .env */ }
#[test] fn retention_zero_needs_ack_and_purges() {}
#[test] fn temp_prune_moves_only_old_unlocked_files() {}
#[test] fn irreversible_items_need_ack() { /* plan with Command + Vault, ack=false → Vault ok, Command ok=false "needs confirmation" */ }
#[test] fn auto_clean_only_vault_moves_safe_package_caches() { /* report with Safe Command, Safe build dir, Review cache, Safe cache → only the Safe cache moved; FakeRunner saw no command */ }
#[test] fn volume_rm_only_after_successful_backup() { /* FakeRunner: docker cp fails → no "volume rm" call */ }
#[test] fn repair_runs_before_execute() {}
#[test] fn one_failure_does_not_stop_others() {}
#[test] fn unwritable_log_refuses_execution() {}
#[test] fn log_rotates_at_5_mb() {}
#[cfg(target_os = "macos")] #[test] fn sigterm_only() {}
```

- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** on both OSes → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(core): execute through the recovery vault, with logging"`

---

### Task 15: CLI and notifications

**Files:**
- Create: `crates/cli/{Cargo.toml,src/main.rs}`
- Test: `crates/cli/tests/cli.rs`

**Interfaces:**
- Binary name `devaudit` (`devaudit.exe` on Windows). The app's own executable is named differently (app plan Task 1), so they can share an install folder.
- **CLI** (`std::env::args`, no clap). Every command acquires the `InstanceLock` (exit 2 if held) and runs `recovery::repair` first.
  - **`devaudit scan [--json]`:** run `report::scan` with progress lines on stderr, then `save`.
    - Without `--json`, print one row per finding, grouped by tier: `id  tier  size  title — reason`, then the notes, then the skipped count.
    - With `--json`, print the `Report` JSON on stdout and nothing else.
  - **`devaudit clean <id>...`:**
    - Needs a TTY (`std::io::IsTerminal` on stdin), else exit 1 with "clean needs an interactive terminal".
    - Uses `report::load_last`. If there is none, or it is older than 1 h, exit 1 with "run `devaudit scan` first".
    - `preview`, then print each item's `what_runs`, `undo` and `blocked`.
    - Ask `Type "yes" to continue:`; anything other than exactly `yes` aborts.
    - If the plan has non-undoable items, ask a second question: `These N items can't be undone. Type "yes" to include them:`. The answer sets `ack_irreversible`.
    - `execute`, then print the outcomes. Exit 0 if all are ok, 1 otherwise.
  - **Recovery commands:**
    - `devaudit recovery list [--total]`: id, title, size, kept until, original path, note. `--total` prints only `total_held` in bytes; the Windows uninstaller uses it.
    - `devaudit recovery restore <id>`: needs a TTY and "yes".
    - `devaudit recovery purge <id>`: needs a TTY and "yes".
    - `devaudit recovery purge --expired`: needs no TTY, because the background task uses it.
  - **`devaudit notify-check`** (the background job; no TTY, no prompts):
    1. `scan` + `save` + `growth`.
    2. `purge_expired`.
    3. If `rules.auto_clean` is set: `actions::auto_clean`.
    4. Send at most one notification, only when free % < `free_pct`, swap % > `swap_pct`, growth > `growth_gb`, or Recovery space was freed. When free space is below the threshold and Recovery holds more than 1 GB, the text adds "X GB in Recovery can be freed".
  - **Notifications:** `notify-rust` with app id `com.penglobal.devaudit`, using `fn notification_text(free_pct: u8, swap_pct: u8, growth_gb: u32, recovery_gb: u32, freed_gb: u32) -> String`. The text is built from integers only. On Windows the toast shows only if a Start Menu shortcut carries that AppUserModelID; app plan Task 5 checks this on a real PC.
  - **Exit codes:** 0 ok, 1 error, 2 lock held.

- [ ] **Step 1: Write failing tests**
  - `scan_json_on_empty_home_succeeds`: run the debug binary with `DEVAUDIT_TEST_ROOT` set to a tempdir
  - `scan_json_stdout_is_only_json`
  - `clean_without_tty_refuses`
  - `clean_without_recent_report_refuses`
  - `clean_requires_exact_yes`
  - `notification_text_has_no_paths`
  - `recovery_restore_requires_tty_and_yes`
  - `purge_expired_runs_without_tty`
  - `clean_asks_second_question_for_irreversible`
  - `lock_held_exits_2`
- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** on both OSes → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(cli): scan, clean, recovery, notify-check"`

---

### Task 16: CI matrix, safety gates, real-machine acceptance

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/CODEOWNERS`, `scripts/check-no-network.sh`, `scripts/check-no-network.ps1`, `docs/ACCEPTANCE.md`, `docs/WINDOWS-NOTES.md`

- [ ] **Step 1: Write the no-network checks.** `check-no-network.{sh,ps1}`: `cargo tree -p devaudit-core -p devaudit-cli -e normal --prefix none` must not match the banned crate list, and the source must not contain `TcpStream`, `UdpSocket` or `WinHttp`. Exit 1 on any hit.
- [ ] **Step 2: Write `ci.yml`:**
  - matrix `os: [macos-14, windows-2022]`
  - steps: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, then the no-network check for that OS
- [ ] **Step 3: Write `CODEOWNERS`:** `crates/core/src/never.rs`, `crates/core/src/platform/`, `crates/core/src/actions.rs`, `crates/core/src/guard.rs`, `crates/core/src/recovery.rs` (the only permanent deletes), `crates/core/src/run.rs`, `crates/core/src/lock.rs`, `rules/` → `@pen-global/devaudit-owners`. Require 2 code-owner approvals.
- [ ] **Step 4: macOS acceptance on the maintainer's Mac** (the one surveyed for the spec). Before running, write down in `docs/ACCEPTANCE.md` which projects are idle and which are active. Run `devaudit scan`. Expect:
  - Docker VM advice
  - the unused Docker volumes in Review
  - the idle projects' build dirs as Safe or Review
  - the active projects (open, dirty, or touched within 14 days) as Protected
  - no `.env`, `.ssh` or `.aws` in the output

  Then:
  1. Clean one idle `.next`; `actions.jsonl` has 2 lines.
  2. `devaudit recovery restore <id>`: the folder is back, byte for byte (`diff -r` against a copy made beforehand).
  3. Clean it again, run `devaudit recovery purge <id>`, and check that `npm run build` recreates it.
  4. Kill the CLI with `kill -9` during a large vault move, rerun it, and check that `repair` leaves either the original or a Held entry, never neither.
- [ ] **Step 5: Windows acceptance on a teammate's PC** (one that already ran `scripts/windows-survey.ps1`). Run `devaudit scan`. Expect:
  - findings match the survey's large folders
  - the active project is Protected
  - the WSL allowance advice appears if `.wslconfig` is missing

  Then:
  1. Clean one idle `node_modules` while VS Code has that project closed → `ok`.
  2. Repeat on a project open in VS Code → Protected or "in use — skipped", and the folder intact.
  3. Move a Review item to Recovery, run `npm install` in that project, then restore it: it comes back as `node_modules.restored-*` and the fresh install is untouched.
  4. Back up and remove one unused Docker volume, restore it, and check its files inside a container.
  5. Check the WSL compaction steps and write them into `docs/WINDOWS-NOTES.md`.
- [ ] **Step 6: Record** both runs in `docs/ACCEPTANCE.md`.
- [ ] **Step 7: Commit** `git add -A && git commit -m "ci: cross-platform safety gates and acceptance"`
