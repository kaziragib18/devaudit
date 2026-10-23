# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DevAudit: a desktop app for macOS and Windows that finds what is filling developer machines' disk and memory (build dirs, caches, Docker, AI tools) and cleans only what the user selects. Removed items are recoverable for a set time, and it must never touch secrets or active projects.

Only `crates/core` (the Rust safety library) exists so far. The CLI (`crates/cli`) and the Tauri 2 app (`app/`, excluded from the Cargo workspace) are planned. The source of truth for behaviour is in `docs/superpowers/`:
- `specs/2026-10-23-devaudit-design.md`: the design spec, including the hard safety rules, tiers, Recovery vault, and per-OS targets
- `plans/2026-10-23-devaudit-core.md`: the task-by-task core + CLI plan (Tasks 1–16), with exact interfaces and the **Global Constraints** section
- `plans/2026-10-23-devaudit-app.md`: the Tauri app plan

Check git history to see which plan task is next (one `feat(core): …` commit per task, followed by `fix(core): …` review fixes). Never-touch lists, the command allowlist, thresholds and target paths must be copied verbatim from the spec, not invented.

## Commands

```sh
cargo build --workspace
cargo test --workspace                      # unit tests + crates/core/tests/runner.rs
cargo test -p devaudit-core guard::         # tests in one module
cargo test -p devaudit-core finding_id_is_stable   # one test by name
cargo fmt --check
cargo clippy --workspace -- -D warnings     # CI gate (planned)
```

Rust ≥ 1.89, edition 2024 (needed for `File::try_lock`). The `fake` feature exposes `run::FakeRunner` outside `cfg(test)`.

## Architecture (core)

- **`Ctx` (`lib.rs`)** carries everything a scan or action needs: OS, `KnownDirs`, data dir, `&dyn Runner`, `&Rules`, `now`, pid, and resolved org never-paths. Functions take a `Ctx` or explicit dirs so tests never touch the real profile. If an org never-path can't be resolved, `ctx_error` is set and every action must fail closed.
- **`platform/`** is the only place allowed to contain `#[cfg(target_os)]`. `mod.rs` holds the shared function set and re-exports `macos.rs` or `windows.rs`. Use `platform::canon`, `platform::inside`, and `platform::eq_ci` for path comparison (canonicalised, component-wise, case-insensitive), never string prefixes. Use `platform::rename_no_replace`, never `std::fs::rename`. Test hooks `fake_volume` / `fake_free_space` override volume info under `cfg(test)`.
- **`run.rs`**: every external tool goes through the `Runner` trait with a fixed argv (no shell strings). `SystemRunner` resolves programs only from `tool_dirs` (never the inherited PATH), clears the env and passes through only a fixed allowlist, and enforces timeouts. Tests use `FakeRunner` (matches by argv prefix and records calls). `src/bin/echo-args.rs` is a test helper for the runner integration test.
- **Safety pipeline:** `never.rs` (secret names, never-touch home paths, personal folders, structural rules, `find_secret_inside`) → `guard.rs` (active-project lock: cwd/cmdline, Docker bind mounts, dirty git, recent activity) → `projects.rs` / `procs.rs` / (planned) `targets.rs`, `docker.rs` produce `model::Finding`s with a `Tier` and `Method` → (planned) `actions.rs` re-validates each finding from scratch before acting → `recovery.rs` moves items into the vault.
- **Fail closed everywhere:** when any check can't run (git missing, process data unavailable, path unresolvable), the item becomes `Tier::Protected` with the failure as its reason.
- **`rules.rs`** loads `rules/rules.json` (embedded via `include_str!`). It merges the IT `org-overlay.json`, which may only make rules stricter, and the user `settings.json`, which is limited to project roots, retention and auto-clean. Targets are tagged `os: Any | Macos | Windows`; paths use placeholders like `{home}` and `{npm_cache}` that `rules::expand` resolves.
- **Nothing is deleted directly.** File actions are same-volume renames into the Recovery vault, journaled via `manifest.json` state (`moving` → `held`). Permanent removal happens only when a vault entry is purged.
- **`lock.rs`**: every function that mutates the vault or acts takes `&InstanceLock` as its first argument after `ctx`, so the compiler stops concurrent writers.
- **IDs:** `model::finding_id` is FNV-1a over `"{category:?}\0{key}"`, and its value is pinned by a test. The UI sends only finding IDs, never paths or argv.

## Constraints to keep in mind

- No network crates in core or CLI (`reqwest`, `hyper`, `ureq`, `curl`, `tokio`, …), and no `TcpStream` / `UdpSocket`.
- Tests must work on both macOS and Windows unless marked with `#[cfg(target_os = …)]`. Watch for paths with spaces, unicode, more than 260 characters, and reserved names like `nul`.
- `DEVAUDIT_TEST_ROOT` redirects `platform::known_dirs()` only in debug builds.
- `scripts/windows-survey.ps1` is a read-only survey for teammates' Windows PCs. Its results feed the Windows targets in `rules.json`.
