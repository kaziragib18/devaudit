pub mod disk;
pub mod docker;
pub mod guard;
pub mod lock;
pub mod model;
pub mod never;
pub mod platform;
pub mod procs;
pub mod projects;
pub mod rules;
pub mod run;
pub mod targets;

use model::Os;
use run::Runner;
use std::path::PathBuf;
use std::time::SystemTime;

/// Everything a scan or action needs, passed explicitly so tests never touch the real profile.
pub struct Ctx<'a> {
    pub os: Os,
    pub home: PathBuf,
    pub dirs: platform::KnownDirs,
    pub data_dir: PathBuf,
    pub run: &'a dyn Runner,
    pub rules: &'a rules::Rules,
    pub now: SystemTime,
    pub pid: u32,
    /// Built-in and org never-paths, expanded at construction.
    pub extra_never: Vec<PathBuf>,
    /// Some: an org never-path couldn't be resolved; the action path must fail closed.
    pub ctx_error: Option<String>,
}

impl<'a> Ctx<'a> {
    pub fn new(
        os: Os,
        dirs: platform::KnownDirs,
        data_dir: PathBuf,
        run: &'a dyn Runner,
        rules: &'a rules::Rules,
        now: SystemTime,
        pid: u32,
    ) -> Ctx<'a> {
        let mut extra_never = vec![];
        let mut ctx_error = None;
        for e in &rules.extra_never {
            match rules::expand(e, &dirs, None) {
                Some(p) => extra_never.push(p),
                None => {
                    ctx_error.get_or_insert(format!("can't resolve org never-path {e}"));
                }
            }
        }
        Ctx {
            os,
            home: dirs.home.clone(),
            dirs,
            data_dir,
            run,
            rules,
            now,
            pid,
            extra_never,
            ctx_error,
        }
    }

    pub fn never_cfg<'b>(&'b self, project_roots: &'b [PathBuf]) -> never::NeverCfg<'b> {
        never::NeverCfg {
            dirs: &self.dirs,
            data_dir: &self.data_dir,
            project_roots,
            extra_never: &self.extra_never,
        }
    }
}
