// fs/file_fs.rs — Disk-backed virtual filesystem.
//
// Ports TinyAntivirus's CFileFs / FileFs.cpp + FileFsStream.cpp + FileFsAttribute.cpp.
// Uses std::fs::File wrapped in a shared Arc<Mutex<>> so that the stream
// object can outlive the VirtualFs borrow.

use super::{FileAttributes, FsFlags, FsStream, FsType, VirtualFs};
use crate::error::{AvError, AvResult};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// FileFsStream
// ---------------------------------------------------------------------------

/// A seekable stream over a disk file (ports CFileFsStream).
pub struct FileFsStream {
    file: Arc<Mutex<File>>,
}

impl FileFsStream {
    fn new(file: Arc<Mutex<File>>) -> Self {
        Self { file }
    }
}

impl Read for FileFsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.lock().unwrap().read(buf)
    }
}

impl Write for FileFsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.lock().unwrap().flush()
    }
}

impl Seek for FileFsStream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.lock().unwrap().seek(pos)
    }
}

impl FsStream for FileFsStream {
    /// Truncate the file to the current position (ports IFsStream::Shrink).
    fn shrink(&mut self) -> AvResult<()> {
        let mut guard = self.file.lock().unwrap();
        let pos = guard.stream_position()?;
        guard.set_len(pos)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileFs
// ---------------------------------------------------------------------------

/// Disk-based VFS object (ports CFileFs).
pub struct FileFs {
    path: Option<PathBuf>,
    flags: FsFlags,
    file: Option<Arc<Mutex<File>>>,
    container: Option<Arc<dyn VirtualFs>>,
    last_error: u32,
    deferred_delete: bool,
}

impl FileFs {
    pub fn new() -> Self {
        Self {
            path: None,
            flags: FsFlags::empty(),
            file: None,
            container: None,
            last_error: 0,
            deferred_delete: false,
        }
    }

    /// Open an existing path directly (convenience constructor).
    pub fn open(path: &Path) -> AvResult<Self> {
        let mut fs = Self::new();
        fs.create(path, FsFlags::READ | FsFlags::OPEN_EXISTING)?;
        Ok(fs)
    }

    fn build_open_options(flags: FsFlags) -> OpenOptions {
        let mut opts = OpenOptions::new();
        opts.read(flags.contains(FsFlags::READ));
        if flags.contains(FsFlags::WRITE) {
            opts.write(true);
        }
        if flags.contains(FsFlags::CREATE_NEW) {
            opts.create_new(true);
        } else if flags.contains(FsFlags::CREATE_ALWAYS) {
            opts.create(true).truncate(true);
        } else if flags.contains(FsFlags::OPEN_ALWAYS) {
            opts.create(true);
        }
        // OPEN_EXISTING: no extra options needed — default open() behaviour
        opts
    }
}

impl Default for FileFs {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualFs for FileFs {
    fn create(&mut self, path: &Path, flags: FsFlags) -> AvResult<()> {
        let opts = Self::build_open_options(flags);
        let file = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AvError::FileNotFound {
                    path: path.display().to_string(),
                }
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                AvError::AccessDenied
            } else {
                AvError::Io(e)
            }
        })?;
        self.path = Some(path.canonicalize().unwrap_or_else(|_| path.to_owned()));
        self.flags = flags;
        self.file = Some(Arc::new(Mutex::new(file)));
        self.deferred_delete = false;
        Ok(())
    }

    fn close(&mut self) -> AvResult<()> {
        let path = self.path.clone();
        self.file = None; // drop the file handle
        if self.deferred_delete {
            if let Some(p) = path {
                let _ = std::fs::remove_file(p);
            }
        }
        Ok(())
    }

    fn recreate(&mut self, flags: FsFlags) -> AvResult<()> {
        let path = self.path.clone().ok_or(AvError::FileNotOpened)?;
        self.close()?;
        self.create(&path, flags)
    }

    fn is_opened(&self) -> bool {
        self.file.is_some()
    }

    fn full_path(&self) -> AvResult<PathBuf> {
        self.path.clone().ok_or(AvError::FileNotOpened)
    }

    fn file_name(&self) -> AvResult<String> {
        let p = self.path.as_ref().ok_or(AvError::FileNotOpened)?;
        Ok(p.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned())
    }

    fn file_ext(&self) -> AvResult<String> {
        let p = self.path.as_ref().ok_or(AvError::FileNotOpened)?;
        Ok(p.extension()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned())
    }

    fn fs_type(&self) -> FsType {
        FsType::Basic
    }

    fn flags(&self) -> FsFlags {
        self.flags
    }

    fn container(&self) -> Option<Arc<dyn VirtualFs>> {
        self.container.clone()
    }

    fn set_container(&mut self, container: Arc<dyn VirtualFs>) {
        self.container = Some(container);
    }

    fn deferred_delete(&mut self) -> AvResult<()> {
        self.deferred_delete = true;
        Ok(())
    }

    fn last_error(&self) -> u32 {
        self.last_error
    }

    fn attributes(&self) -> AvResult<FileAttributes> {
        let path = self.path.as_ref().ok_or(AvError::FileNotOpened)?;
        let meta = std::fs::metadata(path)?;
        Ok(FileAttributes {
            size: meta.len(),
            is_readonly: meta.permissions().readonly(),
            is_hidden: false, // platform-specific; simplified
            is_system: false,
            created: meta.created().ok(),
            accessed: meta.accessed().ok(),
            modified: meta.modified().ok(),
        })
    }

    fn open_stream(&self) -> AvResult<Box<dyn FsStream>> {
        let arc = self.file.as_ref().ok_or(AvError::FileNotOpened)?;
        Ok(Box::new(FileFsStream::new(Arc::clone(arc))))
    }
}

// ---------------------------------------------------------------------------
// Tests (ports FileFs_unittest.cpp and FileFsStream_unittest.cpp)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    fn temp_file_with_data(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_existing_and_read() {
        let tmp = temp_file_with_data(b"hello rust");
        let mut fs = FileFs::new();
        fs.create(tmp.path(), FsFlags::READ | FsFlags::OPEN_EXISTING)
            .unwrap();
        assert!(fs.is_opened());

        let mut stream = fs.open_stream().unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello rust");
    }

    #[test]
    fn write_and_read_back() {
        let tmp = NamedTempFile::new().unwrap();
        let mut fs = FileFs::new();
        fs.create(
            tmp.path(),
            FsFlags::READ | FsFlags::WRITE | FsFlags::OPEN_ALWAYS,
        )
        .unwrap();

        {
            let mut stream = fs.open_stream().unwrap();
            stream.write_all(b"TESTDATA").unwrap();
        }
        {
            let mut stream = fs.open_stream().unwrap();
            stream.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).unwrap();
            assert_eq!(buf, b"TESTDATA");
        }
    }

    #[test]
    fn seek_and_partial_read() {
        let tmp = temp_file_with_data(b"0123456789");
        let mut fs = FileFs::new();
        fs.create(tmp.path(), FsFlags::READ | FsFlags::OPEN_EXISTING)
            .unwrap();
        let mut stream = fs.open_stream().unwrap();
        stream.seek(SeekFrom::Start(4)).unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"456");
    }

    #[test]
    fn attributes_size() {
        let tmp = temp_file_with_data(b"12345");
        let mut fs = FileFs::new();
        fs.create(tmp.path(), FsFlags::READ | FsFlags::OPEN_EXISTING)
            .unwrap();
        let attrs = fs.attributes().unwrap();
        assert_eq!(attrs.size, 5);
    }

    #[test]
    fn fs_type_is_basic() {
        let tmp = temp_file_with_data(b"x");
        let mut fs = FileFs::new();
        fs.create(tmp.path(), FsFlags::READ | FsFlags::OPEN_EXISTING)
            .unwrap();
        assert_eq!(fs.fs_type(), FsType::Basic);
    }

    #[test]
    fn file_name_and_ext() {
        let tmp = tempfile::Builder::new().suffix(".exe").tempfile().unwrap();
        let mut fs = FileFs::new();
        fs.create(tmp.path(), FsFlags::READ | FsFlags::OPEN_EXISTING)
            .unwrap();
        assert_eq!(fs.file_ext().unwrap(), "exe");
    }

    #[test]
    fn shrink_truncates_file() {
        let tmp = temp_file_with_data(b"0123456789");
        let mut fs = FileFs::new();
        fs.create(
            tmp.path(),
            FsFlags::READ | FsFlags::WRITE | FsFlags::OPEN_EXISTING,
        )
        .unwrap();
        {
            let mut stream = fs.open_stream().unwrap();
            stream.seek(SeekFrom::Start(5)).unwrap();
            stream.shrink().unwrap();
        }
        let attrs = fs.attributes().unwrap();
        assert_eq!(attrs.size, 5);
    }

    #[test]
    fn open_nonexistent_errors() {
        let mut fs = FileFs::new();
        let result = fs.create(
            Path::new("/no/such/path/file.exe"),
            FsFlags::READ | FsFlags::OPEN_EXISTING,
        );
        assert!(matches!(result, Err(AvError::FileNotFound { .. })));
    }
}
