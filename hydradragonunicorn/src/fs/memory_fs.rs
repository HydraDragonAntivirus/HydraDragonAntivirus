// fs/memory_fs.rs — In-memory virtual filesystem.
//
// Ports TinyAntivirus's CMemoryFs / MemoryFs.cpp.
// Implements VirtualFs + MemoryVirtualFs using a Vec<u8> as the backing buffer,
// with a cursor-based stream object that shares the data via Arc<Mutex<…>>.

use super::{FileAttributes, FsFlags, FsStream, FsType, MemoryVirtualFs, VirtualFs};
use crate::error::{AvError, AvResult};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// MemoryFsStream — the cursor returned by MemoryFs::open_stream()
// ---------------------------------------------------------------------------

/// A seekable, readable, writable stream backed by a shared byte buffer.
pub struct MemoryFsStream {
    inner: Arc<Mutex<Vec<u8>>>,
    cursor: u64, // current logical position
}

impl MemoryFsStream {
    fn new(buf: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            inner: buf,
            cursor: 0,
        }
    }
}

impl Read for MemoryFsStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let guard = self.inner.lock().unwrap();
        let available = guard.len().saturating_sub(self.cursor as usize);
        let n = out.len().min(available);
        out[..n].copy_from_slice(&guard[self.cursor as usize..self.cursor as usize + n]);
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for MemoryFsStream {
    fn write(&mut self, src: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.inner.lock().unwrap();
        let pos = self.cursor as usize;
        let end = pos + src.len();
        if end > guard.len() {
            guard.resize(end, 0);
        }
        guard[pos..end].copy_from_slice(src);
        self.cursor = end as u64;
        Ok(src.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for MemoryFsStream {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let len = self.inner.lock().unwrap().len() as i64;
        let new_pos: i64 = match from {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.cursor as i64 + n,
            SeekFrom::End(n) => len + n,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of buffer",
            ));
        }
        self.cursor = new_pos as u64;
        Ok(self.cursor)
    }
}

impl FsStream for MemoryFsStream {
    fn shrink(&mut self) -> AvResult<()> {
        let mut guard = self.inner.lock().unwrap();
        let pos = self.cursor as usize;
        guard.truncate(pos);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemoryFs
// ---------------------------------------------------------------------------

/// In-memory VFS object (ports CMemoryFs).
///
/// Can be created empty, filled with `set_buffer`, or used as a scratch pad
/// by the scanner / emulator.
pub struct MemoryFs {
    path: Option<PathBuf>,
    flags: FsFlags,
    opened: bool,
    data: Arc<Mutex<Vec<u8>>>,
    container: Option<Arc<dyn VirtualFs>>,
    last_error: u32,
}

impl MemoryFs {
    /// Create a new, empty in-memory file system object.
    pub fn new() -> Self {
        Self {
            path: None,
            flags: FsFlags::empty(),
            opened: false,
            data: Arc::new(Mutex::new(Vec::new())),
            container: None,
            last_error: 0,
        }
    }

    /// Create and immediately fill from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut fs = Self::new();
        fs.data = Arc::new(Mutex::new(data.to_vec()));
        fs.opened = true;
        fs
    }
}

impl Default for MemoryFs {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualFs for MemoryFs {
    fn create(&mut self, path: &Path, flags: FsFlags) -> AvResult<()> {
        self.path = Some(path.to_owned());
        self.flags = flags;
        if flags.contains(FsFlags::CREATE_ALWAYS) {
            *self.data.lock().unwrap() = Vec::new();
        }
        self.opened = true;
        Ok(())
    }

    fn close(&mut self) -> AvResult<()> {
        if flags_deferred_delete(&self.flags) {
            *self.data.lock().unwrap() = Vec::new();
        }
        self.opened = false;
        Ok(())
    }

    fn recreate(&mut self, flags: FsFlags) -> AvResult<()> {
        self.flags = flags;
        if flags.contains(FsFlags::CREATE_ALWAYS) {
            *self.data.lock().unwrap() = Vec::new();
        }
        self.opened = true;
        Ok(())
    }

    fn is_opened(&self) -> bool {
        self.opened
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
        FsType::Memory
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
        self.flags |= FsFlags::DEFERRED_DELETION;
        Ok(())
    }

    fn last_error(&self) -> u32 {
        self.last_error
    }

    fn attributes(&self) -> AvResult<FileAttributes> {
        let size = self.data.lock().unwrap().len() as u64;
        Ok(FileAttributes {
            size,
            is_readonly: self.flags.contains(FsFlags::ATTR_READONLY),
            is_hidden: self.flags.contains(FsFlags::ATTR_HIDDEN),
            is_system: self.flags.contains(FsFlags::ATTR_SYSTEM),
            created: None,
            accessed: None,
            modified: None,
        })
    }

    fn open_stream(&self) -> AvResult<Box<dyn FsStream>> {
        if !self.opened {
            return Err(AvError::FileNotOpened);
        }
        Ok(Box::new(MemoryFsStream::new(Arc::clone(&self.data))))
    }
}

impl MemoryVirtualFs for MemoryFs {
    fn set_buffer(&mut self, data: &[u8]) -> AvResult<()> {
        *self.data.lock().unwrap() = data.to_vec();
        Ok(())
    }

    fn get_buffer(&self) -> AvResult<Vec<u8>> {
        Ok(self.data.lock().unwrap().clone())
    }

    fn buffer_size(&self) -> AvResult<u64> {
        Ok(self.data.lock().unwrap().len() as u64)
    }
}

fn flags_deferred_delete(flags: &FsFlags) -> bool {
    flags.contains(FsFlags::DEFERRED_DELETION) || flags.contains(FsFlags::ATTR_DELETE_ON_CLOSE)
}

// ---------------------------------------------------------------------------
// Tests (ports MemoryFs_unittest.cpp)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn create_and_close() {
        let mut fs = MemoryFs::new();
        assert!(!fs.is_opened());
        fs.create(Path::new("test.bin"), FsFlags::READ | FsFlags::WRITE)
            .unwrap();
        assert!(fs.is_opened());
        fs.close().unwrap();
        assert!(!fs.is_opened());
    }

    #[test]
    fn set_and_get_buffer() {
        let mut fs = MemoryFs::new();
        fs.create(Path::new("buf.bin"), FsFlags::READ | FsFlags::WRITE)
            .unwrap();
        fs.set_buffer(b"hello, world").unwrap();
        let out = fs.get_buffer().unwrap();
        assert_eq!(out, b"hello, world");
        assert_eq!(fs.buffer_size().unwrap(), 12);
    }

    #[test]
    fn stream_read_write_seek() {
        let mut fs = MemoryFs::from_bytes(b"ABCDE");
        let mut stream = fs.open_stream().unwrap();

        // read first 3 bytes
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ABC");

        // seek back and overwrite
        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.write_all(b"XY").unwrap();

        // read from start via a fresh stream
        let new_stream = fs.open_stream().unwrap();
        drop(stream);
        let mut out = Vec::new();
        let mut ns = new_stream;
        ns.read_to_end(&mut out).unwrap();
        assert_eq!(&out, b"XYCDE");
    }

    #[test]
    fn stream_shrink() {
        let mut fs = MemoryFs::from_bytes(b"0123456789");
        {
            let mut stream = fs.open_stream().unwrap();
            stream.seek(SeekFrom::Start(5)).unwrap();
            stream.shrink().unwrap();
        }
        assert_eq!(fs.buffer_size().unwrap(), 5);
        assert_eq!(fs.get_buffer().unwrap(), b"01234");
    }

    #[test]
    fn fs_type_and_path() {
        let mut fs = MemoryFs::new();
        fs.create(Path::new("foo/bar.exe"), FsFlags::READ).unwrap();
        assert_eq!(fs.fs_type(), FsType::Memory);
        assert_eq!(fs.file_name().unwrap(), "bar.exe");
        assert_eq!(fs.file_ext().unwrap(), "exe");
        assert_eq!(fs.full_path().unwrap(), PathBuf::from("foo/bar.exe"));
    }

    #[test]
    fn deferred_delete_clears_on_close() {
        let mut fs = MemoryFs::from_bytes(b"secret data");
        fs.deferred_delete().unwrap();
        fs.close().unwrap();
        // After deferred-delete close the buffer is cleared
        // (MemoryFs semantics: wipe the Vec)
        assert_eq!(fs.buffer_size().unwrap(), 0);
    }

    #[test]
    fn read_beyond_eof_returns_partial() {
        let fs = MemoryFs::from_bytes(b"AB");
        let mut stream = fs.open_stream().unwrap();
        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"AB");
    }
}
