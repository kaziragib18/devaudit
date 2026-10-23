# DevAudit Desktop App Implementation Plan (macOS + Windows)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A signed desktop app for macOS and Windows: a main window plus a menu-bar / system-tray icon. It shows the core's report and runs user-confirmed actions through the core.

**Architecture:** Tauri 2 shell around `devaudit-core`. The Rust side exposes the commands listed in Task 2 and nothing else. The React UI only renders and sends finding IDs, entry IDs and plain settings values. Per-OS wording comes from `report.os`. The `devaudit` CLI ships inside the app bundle as a Tauri `externalBin`, for the background job and the Windows uninstaller.

**Tech Stack:**
- Tauri 2.x; React 18 + TypeScript + Vite; plain CSS with tokens in `:root`, light and dark
- Plugins: `notification`, `autostart`, `single-instance` only
- `rfd` crate for the native folder picker (called from Rust; not a Tauri plugin)

**Spec:** `docs/superpowers/specs/2026-10-23-devaudit-design.md`. **Depends on:** `docs/superpowers/plans/2026-10-23-devaudit-core.md` (Tasks 1–15).

## Global Constraints

- **Allowed Tauri plugins:** notification, autostart, single-instance. Banned: updater, http, shell, fs, dialog, opener.
- **CSP:** `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`. devtools off in release builds.
- **IPC:** the UI never sends a path, argv, pid or volume name. Folder choice happens entirely on the Rust side (`pick_project_root`).
- **Instance lock:** every command that scans or changes anything (`scan`, `execute`, `recovery_restore`, `recovery_purge`, `pick_project_root`, `set_retention`, `set_auto_clean`) acquires the core `InstanceLock` for its duration. If the lock is held, it returns "DevAudit is busy (background scan running) — try again in a minute".
- **Workspace:** `app/src-tauri` is **excluded** from the root Cargo workspace (`exclude = ["app/src-tauri"]`) and depends on `devaudit-core` by path. Core CI (`cargo test --workspace`) then doesn't need a built frontend, and the core no-network check isn't affected by Tauri's own dependencies.
- **Idle memory:** under 120 MB on macOS and under 150 MB on Windows (WebView2 is heavier).
- **Per-OS wording:** "Swap" ↔ "Page file"; "menu bar" ↔ "system tray". Removal is always worded "Move to Recovery (kept N days)", never "delete". The Full Disk Access row is macOS only; the WSL rows are Windows only.
- **Accessibility:** full keyboard navigation; every tier has an icon and a text label, never colour alone; follows the OS light/dark setting.
- **Windows installer:** per-user NSIS (`installMode: "currentUser"`), no admin prompt. WebView2 uses `embedBootstrapper`, so no download is needed at install time.

## Review Focus

1. **Rescan between Preview and Confirm:** expect the stale plan to be rejected with "Scan changed — preview again". Pinned in Task 2.
2. **Long scan:** expect visible progress, a working Cancel button, and a responsive tray. Pinned in Tasks 2 and 4.
3. **Second launch** (login item plus a manual open): expect it to focus the existing window. Pinned in Task 1.
4. **An item refused at execution time:** expect it to show as blocked with its reason while the others run. Pinned in Task 3.
5. **Windows path with spaces in the scheduled task:** expect the task to run. Pinned in Task 5.
6. **Background job running while the user clicks Clean:** expect "DevAudit is busy", never two writers. Pinned in Task 2.

---

### Task 1: Tauri shell, single instance, locked-down config, bundled CLI

**Files:**
- Create: `app/` scaffold (`npm create tauri-app@latest -- --template react-ts`), trimmed to `src/`, `src-tauri/{Cargo.toml,build.rs,tauri.conf.json,capabilities/default.json,src/main.rs}`, `app/scripts/build-cli.{sh,ps1}`
- Modify: root `Cargo.toml` (add `exclude = ["app/src-tauri"]`)

**Interfaces:**
- Produces: identifier `com.penglobal.devaudit`, product name `DevAudit`, `mainBinaryName: "devaudit-app"` (so it can't collide with the CLI's `devaudit.exe` on case-insensitive filesystems), window label `main`, tray id `tray`.
- **Bundled CLI:** `bundle.externalBin: ["binaries/devaudit"]`. `build-cli` runs `cargo build -p devaudit-cli --release --target <triple>` and copies the result to `src-tauri/binaries/devaudit-<triple>[.exe]`. It is wired in as `build.beforeBuildCommand` (together with the frontend build). At runtime the app finds the CLI as `std::env::current_exe()?.parent()?.join("devaudit[.exe]")`; no shell plugin is involved.

- [ ] **Step 1: Write failing test** `config_is_locked_down`. It parses `tauri.conf.json` and the capabilities file and asserts:
  - the CSP equals the Global Constraints value
  - `withGlobalTauri == false`
  - permissions ⊆ {`core:default`, `notification:default`, `autostart:default`}
  - `bundle.windows.nsis.installMode == "currentUser"`
  - `bundle.macOS.minimumSystemVersion == "13.0"`
  - `mainBinaryName == "devaudit-app"` and `bundle.externalBin == ["binaries/devaudit"]`
  - no banned plugin crate in `src-tauri/Cargo.toml`
- [ ] **Step 2: Run** `cargo test --manifest-path app/src-tauri/Cargo.toml` → expect FAIL.
- [ ] **Step 3: Implement.** The single-instance callback shows and focuses `main`. Restrict the invokable commands with `tauri_build::AppManifest::new().commands(&[...])` in `build.rs`, listing exactly the Task 2 commands.
- [ ] **Step 4: Run** → expect PASS. Then run `npm run tauri dev` on both OSes: the window opens, and a second launch focuses it.
- [ ] **Step 5: Commit** `git commit -am "feat(app): locked-down tauri shell with bundled cli"`

---

### Task 2: Commands and state

**Files:**
- Create: `app/src-tauri/src/commands.rs`

**Interfaces:**
- Consumes: `devaudit_core::{report, actions, lock, rules, recovery, platform, never, run::SystemRunner}`
- Produces (the complete command list; `build.rs` allows exactly these):
  ```rust
  #[tauri::command] async fn scan(state, app) -> Result<ScanResult, String>;   // ScanResult { report: Report, growth: Vec<Growth>, warnings: Vec<String> }
  #[tauri::command] fn cancel_scan(state);
  #[tauri::command] fn preview(state, ids: Vec<String>) -> Result<Plan, String>;
  #[tauri::command] fn execute(state, token: String, ack_irreversible: bool) -> Result<Vec<Outcome>, String>;
  #[tauri::command] fn quick_stats() -> QuickStats;       // QuickStats { os, free, total, swap_used, swap_total, pressure } — volume_space + sysinfo memory only; defined in this file
  #[tauri::command] fn history() -> Vec<LogLine>;         // actions::read_log(data_dir, 500)
  #[tauri::command] fn recovery_list() -> Vec<Entry>;
  #[tauri::command] fn recovery_restore(id: String) -> Result<String /*restored to*/, String>;
  #[tauri::command] fn recovery_purge(ids: Vec<String>) -> Result<u64 /*bytes freed*/, String>;
  #[tauri::command] fn settings_get() -> UserSettings;
  #[tauri::command] fn pick_project_root() -> Result<Option<String> /*added, for display*/, String>;   // rfd::FileDialog::pick_folder on the Rust side → valid_project_root → rules::save_user
  #[tauri::command] fn remove_project_root(index: usize) -> Result<(), String>;
  #[tauri::command] fn set_retention(safe_days: u32, review_days: u32) -> Result<(), String>;   // range-checked by rules::apply_user
  #[tauri::command] fn set_auto_clean(on: bool) -> Result<(), String>;
  #[tauri::command] fn set_background(on: bool) -> Result<(), String>;   // schedule::enable_background / disable_background (Task 5)
  #[tauri::command] fn open_backup_settings();            // fixed argv only: macOS `open x-apple.systempreferences:com.apple.Time-Machine-Settings.extension`; Windows `control.exe /name Microsoft.FileHistory`
  ```
- `execute` passes `ack_irreversible` straight to core.
- `recovery_*` commands call `recovery::repair` first. `recovery_purge` is permanent, so the UI confirms it in a dialog.
- **State:** `Mutex<AppState { report, plan, cancel: Arc<AtomicBool>, scanning }>`.
- **scan:** runs in `spawn_blocking`; emits `scan-progress` events; holds the `InstanceLock` while running; clears the plan; a failed save becomes a warning. `rules.org_overlay_error`, if set, is added to `warnings` so the UI can show why Clean is disabled.

- [ ] **Step 1: Write failing tests**
  - `rescan_clears_plan`
  - `execute_without_plan_errors`
  - `concurrent_scan_rejected`
  - `execute_while_lock_held_returns_busy` (hold an `InstanceLock` on the test data dir, then call execute)
  - `retention_out_of_range_rejected`
  - `quick_stats_is_fast` (< 50 ms)
- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(app): core commands"`

---

### Task 3: Screens

**Files:**
- Create: `app/src/{types.ts,api.ts,os.ts}`, `app/src/screens/{Overview,Storage,Memory,Docker,AiTools,Recovery,History,Settings}.tsx`, `app/src/components/{FindingList,ConfirmDialog,TierBadge,UsageBar}.tsx`, `app/src/styles.css`
- Test: Vitest + Testing Library in `app/src/components/__tests__/`

**Interfaces:**
- Produces:
  - Screens matching the design prototype (artifact `XnhCVwzmYUKgrJH5MGanUg`). If the prototype can't be opened, follow the spec's UI section: one tab per screen, findings grouped by tier, the largest first.
  - `types.ts` mirrors the core types (`Report`, `Finding`, `Method`, `Plan`, `PlannedItem`, `Outcome`, `Entry`, `LogLine`, `UserSettings`) and `QuickStats`.
  - `os.ts` exports `words(os): { swap, tray }`.
- **ConfirmDialog:**
  - Each item shows its `undo` text.
  - If any item is non-undoable, an unchecked checkbox "I understand N items can't be undone" appears. While it's unchecked, those items are excluded, not blocking the rest, and the button count updates.
- **Recovery screen:**
  - Entries grouped as "Kept 3 days (Safe)", "Kept 30 days (Review)", and "Undo actions" (stopped containers).
  - Each row: title, original location, size, "kept until <date>", a **Restore** button, and a **Free space now** button. Entries with a note ("drive not connected", "unreadable — restore by hand", "partly purged") show it, and Restore is disabled for them.
  - Header: total held, plus "Free all Safe items now".
  - After a restore, a toast shows where the item was restored, including the "restored beside" case.
- **History:** each line has a Restore / Start again link while its entry still exists.
- **Overview:** shows "X GB held in Recovery". If the scan warnings include an org overlay error, a banner says "Cleaning is off: your company's DevAudit rules couldn't be read. Contact IT."
- **Storage:** a project shows "Install Git so DevAudit can check projects" when its reason is git missing.
- **Settings:**
  - Retention sliders (Safe 0–30 days, Review 7–90 days) → `set_retention`. Setting 0 shows a warning: "Items will not be recoverable".
  - Project folders: the list from `settings_get`, an **Add folder…** button that calls `pick_project_root` (rejections are shown with their reason), and Remove per row.
  - Background scans on/off → `set_background`. Auto-clean on/off → `set_auto_clean`, with the text "Only moves Safe package caches to Recovery. Never runs commands."
  - "Files deleted outside DevAudit" → a button calling `open_backup_settings` (Time Machine / File History).

- [ ] **Step 1: Write failing tests**
  - `protected_rows_have_no_checkbox`
  - `confirm_dialog_lists_blocked_items_with_reason`
  - `confirm_button_shows_count_and_size`
  - `default_focus_is_cancel`
  - `windows_wording_uses_page_file_and_tray`
  - `irreversible_items_excluded_until_checkbox_ticked`
  - `recovery_row_has_restore_and_free_now`
  - `recovery_row_with_note_has_restore_disabled`
  - `free_now_asks_for_confirmation`
  - `retention_zero_shows_warning`
  - `org_overlay_error_banner_shown`
  - `types_match_core_fixture`: parses `crates/core/tests/fixtures/report.json` (written by core Task 11) into `types.ts` shapes, and fails on any unknown or missing field
- [ ] **Step 2: Run** `npm test` → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 5: Commit** `git commit -am "feat(app): screens"`

---

### Task 4: Menu bar / system tray

**Files:**
- Create: `app/src-tauri/src/tray.rs`

**Interfaces:**
- **macOS:** the tray title is `"{free} GB · Memory: {High|OK|Critical}"`.
- **Windows:** the tray has an icon only; the same text is its tooltip. The icon has three states: ok, warn, critical.
- **Refresh:** every 60 s through `quick_stats`.
- **Menu:** Open DevAudit / Scan now / Quit.

- [ ] **Step 1: Write failing tests**
  - `tray_text_format`
  - `tray_icon_state_from_pressure_and_free`: free < 10% or Critical → critical; free < 15% or Warn → warn
- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS. Then check by hand on both OSes.
- [ ] **Step 5: Commit** `git commit -am "feat(app): tray status"`

---

### Task 5: Background scans

**Files:**
- Create: `app/src-tauri/src/schedule.rs`, `app/src-tauri/resources/com.penglobal.devaudit.scan.plist`, `app/src-tauri/resources/devaudit-scan-task.xml`

**Interfaces:**
- Produces:
  ```rust
  pub fn cli_path() -> Result<PathBuf, String>;                 // next to current_exe (Task 1)
  pub fn enable_background(cli_path: &Path) -> Result<(), String>;
  pub fn disable_background() -> Result<(), String>;
  pub fn task_xml(cli_path: &Path, user_sid: &str) -> String;   // Windows; SID from devaudit_core::platform::user_sid()
  ```
- **macOS:**
  - Write the plist to `~/Library/LaunchAgents/com.penglobal.devaudit.scan.plist`, so it survives a reboot: `ProgramArguments` [cli, `notify-check`], `StartInterval` 21600, `LowPriorityIO`, `Nice` 10.
  - `launchctl bootstrap gui/<uid> <plist>`. Disable: `launchctl bootout gui/<uid> <plist>`, then delete the plist.
- **Windows:**
  - Task Scheduler XML: `TimeTrigger` with `Repetition Interval PT6H`, `Principal` with `UserId` = the SID, `LogonType InteractiveToken`, `RunLevel LeastPrivilege`, `Exec Command` = the cli path (XML-escaped, no quoting needed), `Arguments` = `notify-check`.
  - The task lives in the root folder, because creating a task subfolder may need admin rights: register with `schtasks /Create /TN "DevAudit Background scan" /XML <tempfile> /F`; remove with `schtasks /Delete /TN "DevAudit Background scan" /F`.
- **Auto-clean** is not part of this task. Core's `notify-check` runs `actions::auto_clean` when user settings have `auto_clean: true`, and Settings toggles it with `set_auto_clean`.

- [ ] **Step 1: Write failing tests**
  - `task_xml_escapes_path_with_spaces_and_ampersand`: `C:\Users\A & B\…` → `&amp;` in Command, and the result parses as XML
  - `task_xml_uses_root_folder_task_name`
  - `plist_has_notify_check_and_interval`
- [ ] **Step 2: Run** → expect FAIL. **Step 3: Implement.** **Step 4: Run** → expect PASS.
- [ ] **Step 4b: Check by hand on a Windows PC, as a standard (non-admin) user.** Do this before Task 6:
  1. Enabling background scans creates the task without a UAC prompt.
  2. The task appears in Task Scheduler and runs at least once (`schtasks /Run /TN "DevAudit Background scan"`).
  3. Its toast appears, which proves the Start Menu shortcut's AppUserModelID matches `com.penglobal.devaudit`. If no toast appears, fix the shortcut AUMID in the NSIS template before moving on.
  4. Repeat steps 1–2 on macOS with `launchctl print gui/<uid>/com.penglobal.devaudit.scan`.
- [ ] **Step 5: Commit** `git commit -am "feat: background scans"`

---

### Task 6: Signing, packaging, CI, team rollout

**Files:**
- Create: `scripts/release-macos.sh`, `scripts/release-windows.ps1`, `app/src-tauri/windows/hooks.nsh`, `docs/INSTALL.md`, `docs/TEAM-ROLLOUT.md`
- Modify: `.github/workflows/ci.yml` (add the app job)

- [ ] **Step 1: macOS release.** `npm run tauri build -- --target universal-apple-darwin` (the bundled CLI is built universal too), then `codesign --options runtime --timestamp` (Developer ID Application) for both the app and the CLI inside it, then `xcrun notarytool submit --wait`, then `stapler staple`. Output a DMG plus its SHA-256. Publish through a cask in the private tap `pen-global/homebrew-tools`.
- [ ] **Step 2: Windows release.** `npm run tauri build -- --target x86_64-pc-windows-msvc`, signing through Tauri's `bundle.windows.signCommand` (Azure Trusted Signing `trusted-signing-cli`, or `signtool` with the company OV certificate). Sign the NSIS installer, `devaudit-app.exe` and `devaudit.exe`. Output the installer plus its SHA-256.
- [ ] **Step 2b: Uninstall.**
  - **Windows:** `hooks.nsh` with `NSIS_HOOK_PREUNINSTALL` (configured via `bundle.windows.nsis.installerHooks`):
    1. `schtasks /Delete /TN "DevAudit Background scan" /F` (ignore "not found").
    2. Run `"$INSTDIR\devaudit.exe" recovery list --total` and ask "DevAudit Recovery holds X GB. Keep it so you can restore later?" (default Yes).
    3. Remove `%LOCALAPPDATA%\DevAudit` only on No. On No, also tell the user that project-folder vaults (`<project>\.devaudit-vault`) listed by `recovery list` stay until deleted by hand.
  - **macOS:** `INSTALL.md` says that dragging the app to the Trash leaves `~/.devaudit`, the LaunchAgent and any `<project>/.devaudit-vault` folders. It gives the commands: turn background scans off first (Settings), or `launchctl bootout gui/$(id -u)/com.penglobal.devaudit.scan` and delete the plist.
- [ ] **Step 3: CI app job** in `ci.yml`, matrix `macos-14`, `windows-2022`: `npm ci`, `npm test` (Vitest), `npm run build`, then `cargo clippy --manifest-path app/src-tauri/Cargo.toml -- -D warnings` and `cargo test --manifest-path app/src-tauri/Cargo.toml`.
- [ ] **Step 4: Verify:**
  - macOS: `spctl -a -vv` → "Notarized Developer ID".
  - Windows: `Get-AuthenticodeSignature` → `Valid` for the installer and both exes; SmartScreen doesn't block it on a clean VM; installs without an admin prompt.
  - Idle memory within the budgets above.
- [ ] **Step 5: Write `TEAM-ROLLOUT.md`:**
  1. **Pilot:** 1 Mac web dev and 2 Windows devs for 1 week, read-only (no Clean).
  2. **Compare:** compare the findings with the Windows survey output; tighten `rules.json` where they disagree.
  3. **Clean:** turn Clean on for the pilot group.
  4. **Everyone:** roll out to the whole team. Windows distribution: company file share, a private winget source, or Intune if available.
  5. **Team rules:** org never-touch paths go in `org-overlay.json`, shipped with the installer and never edited by DevAudit. Users' own settings live in `settings.json`, so reinstalling or updating the org file never wipes them.
- [ ] **Step 6: Commit** `git commit -am "chore: release, ci and rollout for macOS and Windows"`
