use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

/// Held for the lifetime of any process that mutates the vault or acts.
pub struct InstanceLock(#[allow(dead_code)] File);

pub fn acquire(data_dir: &Path) -> Result<InstanceLock, String> {
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data_dir.join("lock"))
        .map_err(|e| e.to_string())?;
    match f.try_lock() {
        Ok(()) => Ok(InstanceLock(f)),
        Err(TryLockError::WouldBlock) => Err("Another DevAudit is running".into()),
        Err(TryLockError::Error(e)) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_fails() {
        let d = tempfile::tempdir().unwrap();
        let first = acquire(d.path()).unwrap();
        assert_eq!(
            acquire(d.path()).err().unwrap(),
            "Another DevAudit is running"
        );
        drop(first);
        assert!(acquire(d.path()).is_ok());
    }
}
