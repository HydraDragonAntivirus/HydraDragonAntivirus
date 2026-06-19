// fs/enum_fs.rs — Filesystem enumerator.
//
// Ports TinyAntivirus's CFileFsEnum / FileFsEnum.cpp and
// CFileFsEnumContext / FileFsEnumContext.cpp.
//
// The original uses recursive Windows FindFirstFile/FindNextFile.
// This implementation uses std::fs::read_dir and is fully cross-platform.

use super::{EnumContext, FsEnumObserver, FsEnumerator, FsFlags, VirtualFs};
use crate::error::{AvError, AvResult};
use crate::fs::file_fs::FileFs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

// ---------------------------------------------------------------------------
// FileFsEnumerator
// ---------------------------------------------------------------------------

/// Recursive filesystem enumerator (ports CFileFsEnum).
///
/// Calls registered FsEnumObserver callbacks for each file hit.
/// Archives (zip) will be handled separately in a future archiver module.
pub struct FileFsEnumerator {
    observers: Vec<Arc<dyn FsEnumObserver>>,
    stopped: Arc<AtomicBool>,
}

impl FileFsEnumerator {
    pub fn new() -> Self {
        Self {
            observers: Vec::new(),
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Recursive enumeration worker.
    fn walk(&self, dir: &Path, context: &EnumContext, depth: i32) -> AvResult<()> {
        if self.stopped.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Depth guard
        if depth > context.max_depth {
            return Ok(());
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                let code = err.raw_os_error().unwrap_or(0) as u32;
                let msg = err.to_string();
                for obs in &self.observers {
                    obs.on_error(code, Some(&msg));
                }
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err(AvError::EnumAccessDenied);
                }
                return Err(AvError::Io(err));
            }
        };

        for entry in entries {
            if self.stopped.load(Ordering::Relaxed) {
                return Ok(());
            }

            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    for obs in &self.observers {
                        obs.on_error(e.raw_os_error().unwrap_or(0) as u32, Some(&e.to_string()));
                    }
                    continue;
                }
            };

            let path = entry.path();

            // Ignore-list check
            if context
                .ignore_list
                .iter()
                .any(|ignored| path.starts_with(ignored))
            {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_dir() {
                self.walk(&path, context, depth + 1)?;
            } else if metadata.is_file() {
                // Pattern check (simple glob — "*" matches everything)
                let file_name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let pattern = context.search_pattern.as_deref().unwrap_or("*");
                if !glob_match(pattern, &file_name) {
                    continue;
                }

                // Size guard
                if metadata.len() > context.max_file_size {
                    continue;
                }

                // Build a FileFs for this path and notify observers
                let mut fs = FileFs::new();
                if fs
                    .create(&path, FsFlags::READ | FsFlags::OPEN_EXISTING)
                    .is_err()
                {
                    continue;
                }
                let arc_fs: Arc<dyn VirtualFs> = Arc::new(fs);

                for obs in &self.observers {
                    let result = obs.on_file_found(Arc::clone(&arc_fs), context, depth);
                    match result {
                        Ok(_) => {}
                        Err(AvError::ScanAborted) => {
                            self.stopped.store(true, Ordering::Relaxed);
                            return Ok(());
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            obs.on_error(0, Some(&msg));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for FileFsEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl FsEnumerator for FileFsEnumerator {
    fn add_observer(&mut self, observer: Arc<dyn FsEnumObserver>) -> AvResult<()> {
        self.observers.push(observer);
        Ok(())
    }

    fn remove_observer(&mut self, observer: &Arc<dyn FsEnumObserver>) -> AvResult<()> {
        let ptr = Arc::as_ptr(observer) as *const () as usize;
        self.observers.retain(|o| Arc::as_ptr(o) as *const () as usize != ptr);
        Ok(())
    }

    fn enumerate(&self, context: &EnumContext) -> AvResult<()> {
        self.stopped.store(false, Ordering::Relaxed);
        let root = context
            .search_root
            .as_deref()
            .ok_or_else(|| AvError::InvalidArgument)?;
        self.walk(root, context, 0)
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Minimal glob matcher
// ---------------------------------------------------------------------------

/// Very simple pattern matcher supporting `*` (any sequence) and `?` (any char).
/// Sufficient for the typical AV scan patterns like `*.exe`, `*.dll`, `*`.
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    glob_match_inner(&p, &n)
}

fn glob_match_inner(p: &[char], n: &[char]) -> bool {
    match (p.first(), n.first()) {
        (None, None) => true,
        (Some(&'*'), _) => {
            // '*' matches zero or more characters
            glob_match_inner(&p[1..], n) || (!n.is_empty() && glob_match_inner(p, &n[1..]))
        }
        (Some(&'?'), Some(_)) => glob_match_inner(&p[1..], &n[1..]),
        (Some(pc), Some(nc)) if pc == nc => glob_match_inner(&p[1..], &n[1..]),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests (ports FileFsEnum_unittest.cpp)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct CollectObserver {
        found: Mutex<Vec<PathBuf>>,
    }

    impl CollectObserver {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                found: Mutex::new(Vec::new()),
            })
        }

        fn paths(&self) -> Vec<PathBuf> {
            self.found.lock().unwrap().clone()
        }
    }

    impl FsEnumObserver for CollectObserver {
        fn on_file_found(
            &self,
            file: Arc<dyn VirtualFs>,
            _ctx: &EnumContext,
            _depth: i32,
        ) -> AvResult<()> {
            let p = file.full_path().unwrap();
            self.found.lock().unwrap().push(p);
            Ok(())
        }

        fn on_error(&self, _code: u32, _msg: Option<&str>) {}
    }

    fn make_tree(root: &Path) {
        // root/
        //   a.exe
        //   b.dll
        //   subdir/
        //     c.exe
        fs::write(root.join("a.exe"), b"PE32").unwrap();
        fs::write(root.join("b.dll"), b"PE32").unwrap();
        let sub = root.join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("c.exe"), b"PE32").unwrap();
    }

    #[test]
    fn enumerate_all_files() {
        let tmp = TempDir::new().unwrap();
        make_tree(tmp.path());

        let obs = CollectObserver::new();
        let mut enumerator = FileFsEnumerator::new();
        enumerator
            .add_observer(Arc::clone(&obs) as Arc<dyn FsEnumObserver>)
            .unwrap();

        let ctx = EnumContext {
            search_root: Some(tmp.path().to_owned()),
            ..Default::default()
        };
        enumerator.enumerate(&ctx).unwrap();

        let mut paths = obs.paths();
        paths.sort();
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn enumerate_with_pattern() {
        let tmp = TempDir::new().unwrap();
        make_tree(tmp.path());

        let obs = CollectObserver::new();
        let mut enumerator = FileFsEnumerator::new();
        enumerator
            .add_observer(Arc::clone(&obs) as Arc<dyn FsEnumObserver>)
            .unwrap();

        let ctx = EnumContext {
            search_root: Some(tmp.path().to_owned()),
            search_pattern: Some("*.exe".into()),
            ..Default::default()
        };
        enumerator.enumerate(&ctx).unwrap();

        let paths = obs.paths();
        assert_eq!(paths.len(), 2); // a.exe, subdir/c.exe
        assert!(paths.iter().all(|p| p.extension().unwrap() == "exe"));
    }

    #[test]
    fn stop_halts_enumeration() {
        let tmp = TempDir::new().unwrap();
        // Create 10 files
        for i in 0..10 {
            fs::write(tmp.path().join(format!("{i}.bin")), b"x").unwrap();
        }

        struct StopAfterOne {
            count: Mutex<usize>,
            enumerator: Arc<Mutex<Option<Arc<FileFsEnumerator>>>>,
        }

        let stopper_enum: Arc<Mutex<Option<Arc<FileFsEnumerator>>>> = Arc::new(Mutex::new(None));

        struct AbortObs(Arc<Mutex<usize>>);
        impl FsEnumObserver for AbortObs {
            fn on_file_found(
                &self,
                _f: Arc<dyn VirtualFs>,
                _c: &EnumContext,
                _d: i32,
            ) -> AvResult<()> {
                let mut n = self.0.lock().unwrap();
                *n += 1;
                if *n >= 1 {
                    return Err(AvError::ScanAborted);
                }
                Ok(())
            }
            fn on_error(&self, _: u32, _: Option<&str>) {}
        }

        let count = Arc::new(Mutex::new(0usize));
        let obs = Arc::new(AbortObs(Arc::clone(&count)));

        let mut enumerator = FileFsEnumerator::new();
        enumerator
            .add_observer(obs as Arc<dyn FsEnumObserver>)
            .unwrap();

        let ctx = EnumContext {
            search_root: Some(tmp.path().to_owned()),
            ..Default::default()
        };
        enumerator.enumerate(&ctx).unwrap();

        // Exactly 1 file should have been reported before abort
        assert_eq!(*count.lock().unwrap(), 1);
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*", "anything.exe"));
        assert!(glob_match("*.exe", "test.exe"));
        assert!(!glob_match("*.exe", "test.dll"));
        assert!(glob_match("test*", "testfile.txt"));
        assert!(glob_match("*.*", "a.b"));
    }

    #[test]
    fn glob_match_question() {
        assert!(glob_match("t?st.exe", "test.exe"));
        assert!(!glob_match("t?st.exe", "tst.exe"));
    }
}
