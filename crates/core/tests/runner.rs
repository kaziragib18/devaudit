use devaudit_core::run::{RunError, Runner, SystemRunner};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn sys_dirs() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32")]
    } else {
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .map(PathBuf::from)
            .to_vec()
    }
}

#[test]
fn runner_passes_args_with_spaces_and_unicode_verbatim() {
    let helper = Path::new(env!("CARGO_BIN_EXE_echo-args"));
    let r = SystemRunner {
        tool_dirs: vec![helper.parent().unwrap().into()],
    };
    let out = r
        .run(&["echo-args", "All projects/Café app"], secs(5))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<String>>(&out.stdout).unwrap()[1],
        "All projects/Café app"
    );
}

#[test]
fn runner_times_out() {
    let r = SystemRunner {
        tool_dirs: sys_dirs(),
    };
    let argv: &[&str] = if cfg!(windows) {
        &["ping", "-n", "6", "127.0.0.1"]
    } else {
        &["sleep", "5"]
    };
    assert_eq!(
        r.run(argv, Duration::from_millis(200)),
        Err(RunError::Timeout)
    );
}

#[test]
fn runner_missing_binary_is_not_found() {
    let r = SystemRunner {
        tool_dirs: sys_dirs(),
    };
    assert_eq!(
        r.run(&["definitely-not-a-binary"], secs(5)),
        Err(RunError::NotFound("definitely-not-a-binary".into()))
    );
}

#[test]
fn runner_env_is_allowlisted() {
    // SAFETY: no other test in this binary reads FOO_SECRET.
    unsafe { std::env::set_var("FOO_SECRET", "x") };
    let r = SystemRunner {
        tool_dirs: sys_dirs(),
    };
    let argv: &[&str] = if cfg!(windows) {
        &["cmd", "/c", "set"]
    } else {
        &["env"]
    };
    let out = r.run(argv, secs(5)).unwrap();
    assert!(out.stdout.contains("PATH="));
    assert!(!out.stdout.contains("FOO_SECRET"));
}

#[test]
fn run_to_file_deletes_partial_output_on_failure() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("out.txt");
    let helper = Path::new(env!("CARGO_BIN_EXE_echo-args"));
    let mut dirs = sys_dirs();
    dirs.push(helper.parent().unwrap().into());
    let r = SystemRunner { tool_dirs: dirs };
    // prints, then exits 1
    let argv: &[&str] = if cfg!(windows) {
        &["cmd", "/c", "echo partial&exit 1"]
    } else {
        &["sh", "-c", "echo partial; exit 1"]
    };
    let err = r.run_to_file(argv, secs(5), &out).unwrap_err();
    assert!(matches!(err, RunError::Io(m) if m.starts_with("exit 1")));
    assert!(!out.exists());
    // success path writes the file
    let argv: &[&str] = if cfg!(windows) {
        &["cmd", "/c", "echo ok"]
    } else {
        &["sh", "-c", "echo ok"]
    };
    r.run_to_file(argv, secs(5), &out).unwrap();
    assert!(std::fs::read_to_string(&out).unwrap().starts_with("ok"));
}

#[test]
fn run_from_file_streams_stdin() {
    let d = tempfile::tempdir().unwrap();
    let inp = d.path().join("in.txt");
    std::fs::write(&inp, "hello").unwrap();
    let r = SystemRunner {
        tool_dirs: sys_dirs(),
    };
    let argv: &[&str] = if cfg!(windows) {
        &["findstr", "hello"]
    } else {
        &["cat"]
    };
    assert_eq!(
        r.run_from_file(argv, secs(5), &inp).unwrap().stdout.trim(),
        "hello"
    );
}

#[cfg(windows)]
#[test]
fn cmd_shim_resolved_and_metacharacters_not_executed() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("t.cmd"), "@echo %*\r\n").unwrap();
    let mut dirs = sys_dirs();
    dirs.insert(0, d.path().to_path_buf());
    let r = SystemRunner { tool_dirs: dirs };
    assert_eq!(r.resolve("t"), Some(d.path().join("t.cmd")));
    for arg in ["a&echo INJECTED", "a\"&echo INJECTED", "%PATH%"] {
        match r.run(&["t", arg], secs(5)) {
            Err(_) => {}
            Ok(o) => {
                assert!(!o.stdout.lines().any(|l| l.trim() == "INJECTED"));
                assert!(!o.stdout.contains("System32"));
            }
        }
    }
}
