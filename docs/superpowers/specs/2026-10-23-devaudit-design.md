# DevAudit — Design Spec

Date: 2026-10-23 (rev 2: macOS + Windows) · Owner: Kazi R · Audience: PEN Global dev team

## Problem

Developer machines run out of memory and disk because of AI-assisted workflows (Claude Code, MCP servers, Docker, browsers, editors). The team is mixed: **most of the software team uses Windows; senior devs and the web team use macOS.** One tool must serve both.

A read-only survey of a typical team Mac found the same pattern in every area:

| Area | Finding |
|---|---|
| Disk | nearly full; a large "System Data" share not visible without admin |
| Swap | mostly used (sustained memory pressure) |
| Docker | VM allowed half the RAM; dozens of containers running, including a monitoring stack (grafana/prometheus/loki/tempo/alloy); a large `Docker.raw`; unused volumes |
| Projects | dozens of `node_modules` and `.next` folders, many in projects idle for months |
| AI tools | several Claude Code sessions, each with its own MCP servers (many duplicate processes); a multi-GB `~/.npm/_npx` from `npx …@latest`; a large `~/.claude/projects` |
| Editors/browsers | VS Code and two Chromium browsers each using GBs of RAM; GBs of browser and Playwright caches |

The Windows survey is still to do. Run `scripts/windows-survey.ps1` on 2–3 Windows teammates' PCs before Task 16 of the core plan, and use the results to adjust the Windows targets in `rules.json`.

## Goal

One desktop app for macOS and Windows that:
- shows every storage and memory problem, explained in plain words
- fixes only what the user selects
- never disrupts active work
- never touches secrets or company data

## Non-goals (v1)

- **No network access** of any kind: no telemetry, no update checks, no cloud.
- **No admin rights.** OS-managed items are advice only: Windows Update cleanup, `hiberfil.sys`, `pagefile.sys`, macOS System Data.
- **No Linux,** and no scanning *inside* WSL distros. v1 reports each distro's disk-image size and gives advice. Upgrade path: run the CLI inside WSL in v2.
- **No changes to other apps' settings** (Docker, WSL, Claude): advice only.
- **No App Store or Microsoft Store.**

## Platform support

- macOS 13+ (Apple Silicon and Intel).
- Windows 10 22H2 and Windows 11 (x64; ARM64 when a teammate needs it).

## Architecture

```
devaudit/
  crates/core   Rust library — ALL safety logic. Platform differences live only in core/src/platform/{macos,windows}.rs
  crates/cli    `devaudit` binary — scan / clean / notify-check; used by background scheduling
  app/          Tauri 2 app (macOS + Windows) — React UI + menu-bar / system-tray icon
  rules/rules.json   Built-in targets, each tagged os: "any" | "macos" | "windows"
```

- Processes and memory come from the `sysinfo` crate on both OSes: pid, parent, exe, command line, cwd, start time, memory. This avoids parsing `ps`/`lsof`/`tasklist` output.
- The UI only sends finding IDs; the core re-validates everything right before it acts.

## Tiers

| Tier | Meaning | Default method |
|---|---|---|
| Safe | Rebuilds itself, nothing active uses it | Move to the Recovery vault (kept 3 days); or prune old files from Temp into the vault; or a non-undoable cache command, labelled as such |
| Review | Probably fine, the user must look | Move to the Recovery vault (kept 30 days; Claude worktrees included — never `git worktree remove`, which deletes ignored files such as `.env`), back up then `docker volume rm <name>`, `docker stop <id>` (restartable), SIGTERM (macOS only, can't be undone) |
| Protected | Active project, secret, or can't be verified | Shown, never actionable |

**Fail closed:** when a check cannot run, the item becomes Protected.

## Hard safety rules (enforced in code)

1. **Never-touch names** (any depth, case-insensitive, both OSes): `.env`, `.env.*`, `.envrc`, `.npmrc`, `.yarnrc.yml`, `.pypirc`, `.netrc`, `_netrc`, `.git-credentials`, `.git`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.ppk`, `*.keychain-db`, `*.kdbx`, `credentials`, `credentials.json`, `service-account*.json`, `token`, `*.sqlite`, `*.sqlite3`, `*.db`, `login data`, `cookies`, `web data`, `local state`.
2. **Never-touch home paths, both OSes** (prefix, case-insensitive, component-wise): `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.config/gh`, `.config/gcloud`, `.config/op`, `.password-store`, `.terraform.d`, `.vault-token`, `.claude.json`, `.claude/settings.json`, `.claude/settings.local.json`, `.claude/.credentials.json`.
   - **macOS adds:** `Library/Keychains`, `Library/CloudStorage`, `Library/Mobile Documents`, `Library/Cookies`, `Library/Mail`, `Library/Messages`, `Library/Group Containers/group.com.docker`, `Library/Containers/com.docker.docker`, `Library/Application Support/com.apple.TCC`.
   - **Windows adds:** `{appdata}/Microsoft/Credentials`, `{localappdata}/Microsoft/Credentials`, `{appdata}/Microsoft/Protect`, `{localappdata}/Microsoft/Vault`, `{appdata}/Microsoft/SystemCertificates`, `{appdata}/gnupg`, `{appdata}/GitHub CLI`, `{localappdata}/Microsoft/OneDrive`, `{localappdata}/Docker/wsl`, `{localappdata}/Packages`, plus every OneDrive / Dropbox / Google Drive sync root (OneDrive roots are read from the registry: `HKCU\Software\Microsoft\OneDrive\Accounts\*\UserFolder`).
3. **Personal folders** (resolved through the OS, which follows OneDrive redirection on Windows): Desktop, Documents, Downloads, Pictures, Movies/Videos, Music. Never actionable, except recognised build dirs inside a configured project root.
4. **Structure:** an actionable path must be:
   - under `home`, or under a **project root the user added**. A project root may not be a drive root, the home folder itself, the Windows folder, Program Files, or ProgramData.
   - at least 2 components below that root
   - on the same volume as that root
   - not a symlink, junction or other reparse point, and not a mount point
5. **Inside a git repo:** a path is actionable only if `git check-ignore` confirms it is ignored.
6. **Content check:** a Review folder is moved to the vault only if a walk finds no never-touch name inside it, because a secret inside would be purged when the entry expires.
7. **TOCTOU:** a file identity is recorded at scan time (macOS: dev + inode; Windows: volume serial + file index) and re-checked right before acting.
8. **Commands:** fixed argv from built-in rules only, never a shell string.
   - Allowed programs: `npm pnpm yarn brew docker git xcrun pip3 uv dotnet`.
   - On Windows, `.cmd` shims are allowed only because their arguments are fixed literals. This requires Rust ≥ 1.77.2 (fix for CVE-2024-24576).
   - Refused while the same tool is already running.
   - The npm cache location comes from `npm config get cache`, because users may move it.
9. **Processes:**
   - macOS: SIGTERM only.
   - Windows: no process actions in v1 (advice only), because console processes have no graceful stop.
   - Both: own user only; never the tool itself or its parents; never GUI apps; pid + start time re-checked before acting.
10. **Docker:** never `down`, `rm` or `-a --volumes` prune. Volumes are removed one at a time by name, only if no container, running or stopped, references them.
11. **Org overlay** (`org-overlay.json`, shipped by IT, never written by DevAudit) can only make rules stricter (add never-paths, raise idle days, raise tiers, add project roots). It can never add commands or loosen a tier. If it can't be parsed, scans still run but every action is refused.
    - **User settings** (`settings.json`, written by the Settings page) are separate: project roots, retention within its ranges, auto-clean on/off. They can't touch never-lists, tiers or commands.
12. **Reading other apps' config:** read only the named keys:
    - Docker settings: `memoryMiB`, `diskSizeMiB`
    - `.wslconfig`: `memory`, `swap`
    - Claude settings: `cleanupPeriodDays`
    - MCP configs: `args`
    Contents are never logged or shown.
13. **Nothing is deleted directly.** Every file or folder action is a same-volume rename into the Recovery vault (see Recovery).
    - **In use:** a failed rename means files are in use (Windows). The item is skipped and nothing changes.
    - **No cross-drive copies:** a rename across volumes is refused, never turned into a copy.
    - **No OS Trash / Recycle Bin.** The vault replaces it, which also removes the Recycle Bin's silent permanent-delete risk for large items.
14. **Permanent removal happens in one place only:** purging a vault entry, either when it expires or when the user presses "Free space now".
15. **Paths:** compared case-insensitively on both OSes after canonicalising (this handles Windows 8.3 short names and `\\?\` paths). Long paths over 260 characters and reserved names (`nul`, `con`) inside `node_modules` must work.

## Recovery

Anything DevAudit removes by mistake can be brought back for a set time.

**Where the vault lives** (always on the same volume as the item, so moving in and out is an instant rename):
- **Home volume:** `<data_dir>/vault/` (`~/.devaudit/vault.noindex/` on macOS). On Windows this is `%LOCALAPPDATA%\DevAudit\vault`, which is not synced by OneDrive.
- **Other volumes** (e.g. project root `D:\work`): `<project_root>/.devaudit-vault/`.
- **Hidden from backups and indexing:** on macOS, `tmutil addexclusion`, and the folder is named `vault.noindex` (Spotlight skips `*.noindex`; `.metadata_never_index` no longer works); on Windows, the `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` attribute. A project-root vault inside a git repo is added to `.git/info/exclude`.
- **Never scanned or actioned:** the vault and the data dir are on the never-touch list for every module except `recovery`.

**Entries** — one folder per action: `vault/<entry-id>/`, containing:
- `payload/` — the moved item
- `manifest.json` — id, original path, file identity, bytes, title, tier, `moved_at`, `expires_at`, `state` (`moving` | `held` | `restoring`), restore notes
- `README.txt` — how to restore by hand

**Journal (crash-safety):**
1. Write the manifest with `state: moving` (fsync).
2. Rename the item into the vault.
3. Set `state: held`.

On startup, an entry still marked `moving` is fixed up:
- payload present → it becomes `held`
- payload missing and the original present → the entry is deleted, because the move never happened

`restoring` is handled the same way in reverse.

**Retention:**
- Safe items: 3 days (adjustable 0–30).
- Review items: 30 days (adjustable 7–90).
- Docker volume backups: 30 days.
- Retention 0 means "purge right after the move", and only the user can choose it in Settings.
- Expired entries are purged by the background scan.
- **No early purge:** nothing is purged before expiry without the user pressing "Free space now".
- **Low disk:** when free space is low, the user gets a notification ("X GB in Recovery can be freed"). The tool never purges on its own.

**Restore:**
- Re-validate first: the original parent must still be allowed (`forbidden` check) and must not have become a link.
- Missing parent folders are recreated.
- **If the original path exists**, restore next to it as `<name>.restored-<date>` and never overwrite.
- If the vault is on a drive that isn't connected, the entry shows "drive not connected".

**What each action can undo:**

| Action | Undo |
|---|---|
| Vault move (build dirs, caches, Temp files, transcripts) | Restore (rename back) |
| `docker volume rm` | First `docker create -v <name>:/v <any local image>`, then `docker cp <container>:/v -` → `vault/<id>/payload/volume.tar`, then remove the temporary container. Restore: `docker volume create` plus `docker cp` back. Refused if free space < 1.1 × the volume size, or if no local image exists |
| `docker stop` | "Start again" → `docker start <ids>` |
| Worktree vault move | Restore (rename back, then `git worktree repair`). Purging runs `git worktree prune`; the branch is never deleted |
| Cache commands (`brew cleanup`, `pnpm store prune`, `docker image prune` dangling, `docker builder prune`, `xcrun simctl delete unavailable`) | **Can't be undone**: re-downloads when needed. Labelled in preview |
| SIGTERM (macOS) | **Can't be undone**: the process ends. Labelled in preview |

**Uninstall:**
- **Windows:** the uninstaller asks "Recovery holds X GB — keep it?" (default: keep).
- **macOS:** `~/.devaudit` stays until the user removes it. `INSTALL.md` says so.

**Limit:** DevAudit can only recover what DevAudit removed. Files deleted outside the tool need Time Machine / File History. The app's Settings page links to those.

## Active-project guard

A project is **locked** when any of these is true:
- a process has its cwd inside it, or a running process's command line contains its path
- a Docker container bind-mounts it. Docker Desktop on Windows may report the mount as `C:\…` or `/run/desktop/mnt/host/c/…`; both forms are normalised.
- `git status --porcelain` is non-empty
- its newest source file (excluding build dirs) or last commit is newer than 14 days
- git or process data is unavailable

Git is located in the usual places, including the copy bundled with GitHub Desktop on Windows. If git is missing, every project is Protected and the UI says "Install Git so DevAudit can check projects".

Build dir tiering for an unlocked project:
- **Safe** (Recovery vault, kept 3 days): idle ≥ 30 days, gitignored, and a lockfile exists.
- **Review** (Recovery vault, kept 30 days): everything else.
- **pnpm projects:** size is marked "estimate — shared with pnpm store", because hardlinks free less space than they appear to.

## Memory

| | macOS | Windows |
|---|---|---|
| Pressure | `kern.memorystatus_vm_pressure_level` | derived: available < 10% or commit > 90% → Critical; available < 20% → Warn |
| Swap | `vm.swapusage` | page file use (sysinfo swap) |
| VM | `com.apple.Virtualization.VirtualMachine` | `vmmem` / `VmmemWSL` = "WSL / Docker VM" |
| VM allowance | Docker `memoryMiB` | `.wslconfig` `memory=` (default 50% of RAM) |

Shared behaviour:
- **App groups:** by `.app` bundle on macOS; on Windows by install dir (`Program Files\X`, `%LOCALAPPDATA%\Programs\X`), then a known exe-name map.
- **Orphans:**
  - macOS: ppid 1.
  - Windows: parent not running, or parent started after the child.
  - Both: own user, dev-tool command, not a known daemon, running > 1 h.
  - macOS → Review (SIGTERM). Windows → Advice.
- **Duplicate MCP servers** under several live Claude sessions → Advice.
- **Docker / WSL allowance** > 50% of RAM and swap or page file > 50% used → Advice.

## Storage targets by OS

| Target | macOS | Windows |
|---|---|---|
| npm cache | `npm config get cache` (default `~/.npm`) | same (default `%LOCALAPPDATA%\npm-cache`) |
| pnpm / yarn / pip / uv | `~/Library/pnpm/store`, `~/Library/Caches/Yarn`, `~/Library/Caches/pip`, `~/.cache/uv` | `%LOCALAPPDATA%\pnpm\store`, `%LOCALAPPDATA%\Yarn\Cache`, `%LOCALAPPDATA%\pip\Cache`, `%LOCALAPPDATA%\uv\cache` |
| NuGet HTTP cache | — | `%LOCALAPPDATA%\NuGet\v3-cache` → `dotnet nuget locals http-cache --clear` |
| Playwright | `~/Library/Caches/ms-playwright(-mcp)` | `%LOCALAPPDATA%\ms-playwright` |
| Browser caches | `~/Library/Caches/Google/Chrome`, `…/Microsoft Edge` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache` |
| VS Code / Cursor old versions | `~/Library/Application Support/{Code,Cursor}/CachedData` | `%APPDATA%\{Code,Cursor}\CachedData` |
| Temp | — (macOS cleans it) | `%TEMP%`: prune files older than 7 days; in-use files are skipped |
| Xcode | DerivedData, unavailable simulators | — |
| Homebrew | `brew cleanup --prune=30` | — |
| Docker disk | `Docker.raw` (report) | `%LOCALAPPDATA%\Docker\wsl\…\*.vhdx` (report + "doesn't shrink by itself" advice) |
| WSL distros | — | each distro's `ext4.vhdx` size (report + advice) |
| OS-managed | System Data (advice) | Windows Update cleanup, hibernation file, Recycle Bin size (advice: Settings › System › Storage) |
| Claude | `~/.claude` | `%USERPROFILE%\.claude` |

## UI

- **Main window tabs:** Overview, Storage, Memory, Docker, AI tools, Recovery, History, Settings.
- **Recovery tab:**
  - lists entries with original location, size, "kept until", and Restore / Free space now buttons
  - "Free all Safe items now" button
  - total size held, also shown on Overview as "X GB held in Recovery"
- **Status icon:** macOS menu bar / Windows system tray, showing free disk and memory pressure, refreshed every 60 s with cheap calls only.
- **Per-OS wording:**
  - "Swap" ↔ "Page file"
  - "Full Disk Access" (macOS only)
  - "WSL" (Windows only)
- **Every action follows one flow:** select → Preview → Confirm → result + History entry with an Undo/Restore link.
  - The Preview shows the exact commands and estimated GB.
  - Each item carries a "Recoverable for N days" or "Can't be undone" label.
  - Confirming non-undoable items requires a separate checkbox.

## Automation

- **Schedulers:**
  - macOS: LaunchAgent.
  - Windows: per-user Task Scheduler task, registered from an XML file, which avoids quoting problems with paths that contain spaces. No admin needed.
- **Schedule:** both run `devaudit notify-check` every 6 h.
- **Notifications:** the `notify-rust` crate (macOS + Windows toasts), with fixed text plus numbers only.
- **Thresholds:** free < 15%, swap / page file > 75%, growth > 5 GB.
- **Auto-clean:** optional, off by default. Safe-tier vault moves of package caches only; it never runs non-undoable commands.
- **Purge:** the background scan also purges expired Recovery entries and reports the freed GB in its notification.

## Data

- **Location:**
  - macOS: `~/.devaudit/` (0700)
  - Windows: `%LOCALAPPDATA%\DevAudit\` (user-only ACL inherited from LocalAppData)
- **Files:**
  - `report.json` (atomic write)
  - `history.csv`
  - `actions.jsonl` (rotated at 5 MB)
  - `vault/` (`vault.noindex/` on macOS; Recovery entries) and `vault-index.json`
  - `org-overlay.json` (IT) and `settings.json` (user)
  - `lock`, held with `std::fs::File::try_lock` (Rust ≥ 1.89)

## Distribution

| | macOS | Windows |
|---|---|---|
| Build | universal binary | x64 (ARM64 later) |
| Signing | Developer ID + notarization (company Apple account) | Authenticode via Azure Trusted Signing or an OV certificate (company). **Unsigned = SmartScreen block** |
| Package | DMG via private Homebrew tap | per-user NSIS installer (no admin); share via company file share or a private winget source; Intune if the company uses it |
| Updates | `brew upgrade` | re-run the installer, or winget/Intune |

**CI:** a matrix of `macos-14` and `windows-2022`. Network crates are blocked in core and cli. CODEOWNERS requires 2 reviewers on `never.rs`, `platform/`, `actions.rs`, `guard.rs`, `recovery.rs`, `run.rs`, `lock.rs` and `rules/`.
