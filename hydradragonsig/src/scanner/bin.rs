//! Bounds-checked integer and string reads shared by the structural parsers
//! (`elf`, `macho`, `dotnet`). Every read returns `None` past the end of the
//! buffer or on offset overflow; nothing here panics on hostile input.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reader<'a> {
    pub bytes: &'a [u8],
    pub little: bool,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], little: bool) -> Self {
        Self { bytes, little }
    }

    pub fn slice(&self, off: u64, len: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(off).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.bytes.get(start..end)
    }

    fn array<const N: usize>(&self, off: u64) -> Option<[u8; N]> {
        self.slice(off, N as u64)?.try_into().ok()
    }

    pub fn u8(&self, off: u64) -> Option<u8> {
        self.bytes.get(usize::try_from(off).ok()?).copied()
    }

    pub fn u16(&self, off: u64) -> Option<u16> {
        let a = self.array::<2>(off)?;
        Some(if self.little { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) })
    }

    pub fn u32(&self, off: u64) -> Option<u32> {
        let a = self.array::<4>(off)?;
        Some(if self.little { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }

    pub fn u64(&self, off: u64) -> Option<u64> {
        let a = self.array::<8>(off)?;
        Some(if self.little { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
    }

    /// `u32` or `u64` by `wide`, widened to u64.
    pub fn word(&self, off: u64, wide: bool) -> Option<u64> {
        if wide { self.u64(off) } else { self.u32(off).map(u64::from) }
    }

    /// NUL-terminated string at `off`, at most `max` bytes (lossy UTF-8).
    pub fn cstr(&self, off: u64, max: usize) -> Option<String> {
        let start = usize::try_from(off).ok()?;
        let rest = self.bytes.get(start..)?;
        let rest = &rest[..rest.len().min(max)];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }
}

/// Fixed-width, NUL-padded name (Mach-O segment / section names).
pub fn fixed_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// `name` against a flag word: `flags_all` names must all be set, `flags_none`
/// names must all be clear. `lookup` maps a name to its bit(s); unknown names fail.
pub fn flags_hold(flags: u64, all: &[String], none: &[String], lookup: fn(&str) -> Option<u64>) -> bool {
    all.iter().all(|f| lookup(f).is_some_and(|bit| flags & bit == bit))
        && none.iter().all(|f| lookup(f).is_some_and(|bit| flags & bit == 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let r = Reader::new(&[1, 2, 3, 4, 0x41, 0x42, 0], true);
        assert_eq!(r.u16(0), Some(0x0201));
        assert_eq!(Reader::new(r.bytes, false).u16(0), Some(0x0102));
        assert_eq!(r.u32(4), None);
        assert_eq!(r.u64(u64::MAX), None);
        assert_eq!(r.slice(u64::MAX - 1, 4), None);
        assert_eq!(r.cstr(4, 16).as_deref(), Some("AB"));
        assert_eq!(r.cstr(4, 1).as_deref(), Some("A"));
        assert_eq!(r.cstr(99, 1), None);
        assert_eq!(fixed_name(b"__TEXT\0\0"), "__TEXT");
    }
}
