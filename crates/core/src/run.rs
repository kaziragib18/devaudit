use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RunError {
    NotFound(String),
    Timeout,
    Io(String),
}

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[&str], timeout: Duration) -> Result<Output, RunError>;
    /// stdout streamed to `out` (created new; deleted on any error).
    /// Non-zero exit gives Err(Io("exit N: <stderr>")).
    fn run_to_file(&self, argv: &[&str], timeout: Duration, out: &Path) -> Result<(), RunError>;
    /// `input` streamed to stdin. Non-zero exit gives Err.
    fn run_from_file(
        &self,
        argv: &[&str],
        timeout: Duration,
        input: &Path,
    ) -> Result<Output, RunError>;
}

/// Parent env vars always passed through (if present).
const ENV_ALWAYS: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "USERNAME",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "SystemRoot",
    "SystemDrive",
    "ComSpec",
    "PATHEXT",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramData",
    // These move tool caches or the Docker endpoint.
    "npm_config_cache",
    "XDG_CACHE_HOME",
    "UV_CACHE_DIR",
    "PIP_CACHE_DIR",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
];

pub struct SystemRunner {
    pub tool_dirs: Vec<PathBuf>,
}

impl SystemRunner {
    /// Looks only in `tool_dirs`, never the inherited PATH.
    pub fn resolve(&self, program: &str) -> Option<PathBuf> {
        let names: Vec<String> = if cfg!(windows) {
            ["exe", "cmd", "bat"]
                .iter()
                .map(|e| format!("{program}.{e}"))
                .collect()
        } else {
            vec![program.to_string()]
        };
        self.tool_dirs
            .iter()
            .flat_map(|d| names.iter().map(move |n| d.join(n)))
            .find(|p| p.is_file())
    }

    fn path_env(&self) -> std::ffi::OsString {
        let mut dirs = self.tool_dirs.clone();
        if cfg!(windows) {
            if let Some(root) = std::env::var_os("SystemRoot") {
                dirs.push(PathBuf::from(root).join("System32"));
            }
        } else {
            dirs.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
        }
        std::env::join_paths(dirs).unwrap_or_default()
    }

    fn exec(
        &self,
        argv: &[&str],
        timeout: Duration,
        stdin_file: Option<&Path>,
        stdout_file: Option<&Path>,
    ) -> Result<Output, RunError> {
        let io = |e: std::io::Error| RunError::Io(e.to_string());
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| RunError::Io("empty argv".into()))?;
        let exe = self
            .resolve(prog)
            .ok_or_else(|| RunError::NotFound((*prog).to_string()))?;

        let mut cmd = Command::new(exe);
        cmd.args(args)
            .env_clear()
            .env("PATH", self.path_env())
            .env("LANG", "C")
            .env("LC_ALL", "C");
        for k in ENV_ALWAYS {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        cmd.stdin(if stdin_file.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let mut out_file = match stdout_file {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(p)
                    .map_err(io)?,
            ),
            None => None,
        };
        let res = (|| {
            let mut child = cmd.spawn().map_err(io)?;
            // Drain pipes on threads so a full pipe can't stall the child.
            let mut so = child.stdout.take().unwrap();
            let mut se = child.stderr.take().unwrap();
            let t_out = thread::spawn(move || -> std::io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                match out_file.as_mut() {
                    Some(f) => {
                        std::io::copy(&mut so, f)?;
                    }
                    None => {
                        so.read_to_end(&mut buf)?;
                    }
                }
                Ok(buf)
            });
            let t_err = thread::spawn(move || {
                let mut b = Vec::new();
                let _ = se.read_to_end(&mut b);
                b
            });
            let t_in = match (stdin_file, child.stdin.take()) {
                (Some(p), Some(mut si)) => {
                    let mut f = std::fs::File::open(p).map_err(io)?;
                    Some(thread::spawn(move || {
                        let _ = std::io::copy(&mut f, &mut si);
                        let _ = si.flush();
                    }))
                }
                _ => None,
            };

            let start = Instant::now();
            let status = loop {
                if let Some(s) = child.try_wait().map_err(io)? {
                    break s;
                }
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::Timeout);
                }
                thread::sleep(Duration::from_millis(20));
            };
            if let Some(t) = t_in {
                let _ = t.join();
            }
            let stdout = t_out.join().unwrap().map_err(io)?;
            let stderr = String::from_utf8_lossy(&t_err.join().unwrap()).into_owned();
            let status = status.code().unwrap_or(-1);
            if status != 0 && (stdout_file.is_some() || stdin_file.is_some()) {
                return Err(RunError::Io(format!(
                    "exit {status}: {}",
                    stderr.trim_end()
                )));
            }
            Ok(Output {
                status,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr,
            })
        })();
        if res.is_err()
            && let Some(p) = stdout_file
        {
            let _ = std::fs::remove_file(p);
        }
        res
    }
}

impl Runner for SystemRunner {
    fn run(&self, argv: &[&str], timeout: Duration) -> Result<Output, RunError> {
        self.exec(argv, timeout, None, None)
    }
    fn run_to_file(&self, argv: &[&str], timeout: Duration, out: &Path) -> Result<(), RunError> {
        self.exec(argv, timeout, None, Some(out)).map(|_| ())
    }
    fn run_from_file(
        &self,
        argv: &[&str],
        timeout: Duration,
        input: &Path,
    ) -> Result<Output, RunError> {
        self.exec(argv, timeout, Some(input), None)
    }
}

#[cfg(any(test, feature = "fake"))]
pub use fake::FakeRunner;

#[cfg(any(test, feature = "fake"))]
mod fake {
    use super::*;
    use std::sync::Mutex;

    type Rule = (Vec<String>, Result<Output, RunError>);

    /// Matches by argv prefix; first matching rule wins; no match is NotFound.
    #[derive(Default)]
    pub struct FakeRunner {
        rules: Mutex<Vec<Rule>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn on(self, prefix: &[&str], result: Result<Output, RunError>) -> Self {
            self.rules
                .lock()
                .unwrap()
                .push((prefix.iter().map(|s| s.to_string()).collect(), result));
            self
        }
        pub fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
        fn answer(&self, argv: &[&str]) -> Result<Output, RunError> {
            let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            self.calls.lock().unwrap().push(argv.clone());
            self.rules
                .lock()
                .unwrap()
                .iter()
                .find(|(p, _)| argv.starts_with(p))
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| {
                    Err(RunError::NotFound(
                        argv.first().cloned().unwrap_or_default(),
                    ))
                })
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, argv: &[&str], _: Duration) -> Result<Output, RunError> {
            self.answer(argv)
        }
        fn run_to_file(&self, argv: &[&str], _: Duration, out: &Path) -> Result<(), RunError> {
            let o = self.answer(argv)?;
            std::fs::write(out, o.stdout).map_err(|e| RunError::Io(e.to_string()))
        }
        fn run_from_file(&self, argv: &[&str], _: Duration, _: &Path) -> Result<Output, RunError> {
            self.answer(argv)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fake_matches_prefix_and_records_calls() {
            let ok = Output {
                status: 0,
                stdout: "hi".into(),
                stderr: String::new(),
            };
            let f = FakeRunner::new().on(&["docker", "ps"], Ok(ok.clone()));
            assert_eq!(
                f.run(&["docker", "ps", "-a"], Duration::from_secs(1)),
                Ok(ok)
            );
            assert!(matches!(
                f.run(&["git"], Duration::from_secs(1)),
                Err(RunError::NotFound(_))
            ));
            assert_eq!(f.calls(), vec![vec!["docker", "ps", "-a"], vec!["git"]]);
        }
    }
}
