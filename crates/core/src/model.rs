use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum Os {
    Macos,
    Windows,
}

impl Os {
    pub fn current() -> Os {
        crate::platform::CURRENT_OS
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Safe,
    Review,
    Protected,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum Category {
    ProjectBuild,
    PackageCache,
    BrowserCache,
    AiTool,
    Docker,
    EditorData,
    Temp,
    Process,
    Advice,
}

/// macOS dev+ino; Windows FILE_ID_INFO (128-bit, correct on ReFS / Dev Drive).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct FileId {
    pub volume: u64,
    pub index: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Method {
    /// Same-volume rename into the Recovery vault.
    Vault {
        path: PathBuf,
        id: FileId,
        keep_days: u32,
    },
    /// Windows %TEMP%: old files go into one vault entry.
    PruneOlderThan {
        path: PathBuf,
        days: u32,
    },
    /// Only the non-undoable cache commands.
    Command {
        argv: Vec<String>,
    },
    /// Back up to the vault, then `docker volume rm`.
    DockerVolumeBackupRm {
        name: String,
    },
    /// Whole worktree folder into the vault; never `git worktree remove`,
    /// which deletes ignored files such as .env.
    WorktreeVault {
        repo: PathBuf,
        worktree: PathBuf,
        id: FileId,
        branch: String,
        keep_days: u32,
    },
    DockerStop {
        container_ids: Vec<String>,
    },
    /// macOS only.
    Signal {
        pid: u32,
        start_time: u64,
    },
    None,
}

impl Method {
    pub fn undoable(&self) -> bool {
        !matches!(self, Method::Command { .. } | Method::Signal { .. })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub title: String,
    pub path: Option<PathBuf>,
    /// Set for build dirs and worktrees; validate re-checks this project.
    pub project: Option<PathBuf>,
    /// From Target.owner_processes; validate refuses while any runs.
    pub owner_processes: Vec<String>,
    pub bytes: u64,
    pub bytes_estimate: bool,
    pub idle_days: Option<u32>,
    pub tier: Tier,
    pub reason: String,
    pub rebuild: Option<String>,
    pub method: Method,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Skipped {
    pub path: PathBuf,
    pub why: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AppGroup {
    pub name: String,
    pub mem: u64,
    pub procs: u32,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum Pressure {
    Normal,
    Warn,
    Critical,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MemInfo {
    pub total: u64,
    pub available: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub pressure: Pressure,
    pub groups: Vec<AppGroup>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DiskInfo {
    pub total: u64,
    pub free: u64,
    pub scanned: u64,
    pub unseen: u64,
    pub trash: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Report {
    pub os: Os,
    pub scanned_at: u64,
    pub disk: DiskInfo,
    pub memory: MemInfo,
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
    pub notes: Vec<String>,
}

/// FNV-1a 64 over "{category:?}\0{key}", formatted "{:016x}".
pub fn finding_id(category: Category, key: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in format!("{category:?}\0{key}").bytes() {
        h = (h ^ b as u64).wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_id_is_stable() {
        // Pinned value computed independently in Python.
        assert_eq!(
            finding_id(Category::Temp, "/tmp/x"),
            finding_id(Category::Temp, "/tmp/x")
        );
        assert_eq!(finding_id(Category::Temp, "/tmp/x").len(), 16);
        assert_ne!(
            finding_id(Category::Temp, "/tmp/x"),
            finding_id(Category::Docker, "/tmp/x")
        );
        assert_eq!(finding_id(Category::Temp, ""), "e380c6af5392e605");
    }

    #[test]
    fn tier_order_and_undoable() {
        assert!(Tier::Safe < Tier::Review && Tier::Review < Tier::Protected);
        assert!(!Method::Command { argv: vec![] }.undoable());
        assert!(
            !Method::Signal {
                pid: 1,
                start_time: 2
            }
            .undoable()
        );
        assert!(Method::None.undoable());
    }

    #[test]
    fn file_id_roundtrips_128_bit() {
        let id = FileId {
            volume: u64::MAX,
            index: u128::MAX,
        };
        let s = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<FileId>(&s).unwrap(), id);
    }
}
