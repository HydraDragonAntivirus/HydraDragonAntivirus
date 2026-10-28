// unpacker/codecs.rs — decompressors and byte transforms of unpacker recipes.
// Every decoder takes a size limit: a packed stream is attacker data and may
// claim (or expand to) any size.

use serde::Deserialize;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    /// Raw deflate (RFC 1951, no header).
    Deflate,
    /// zlib (RFC 1950).
    Zlib,
    /// gzip (RFC 1952).
    Gzip,
    /// LZMA: 5 property bytes, then the raw stream (7-Zip / NSIS layout).
    Lzma,
    /// LZMA "alone" (`.lzma`): 5 property bytes, 8-byte size, then the stream.
    LzmaAlone,
    /// bzip2 with its `BZh` header.
    Bzip2,
    /// NSIS bzip2 (no `BZh` header). nsis-rs tries the 2.x+ block layout, then
    /// the NSIS 1.x one with its per-block flag.
    NsisBzip2,
    /// aPLib (raw, or with an `AP32` header).
    Aplib,
    /// LZNT1 (RtlDecompressBuffer COMPRESSION_FORMAT_LZNT1).
    Lznt1,
}

/// Decompresses `data`. `size`: the exact output size when the format does not
/// store it (truncates the output there); `max`: the most it may produce.
pub fn decompress(codec: Codec, data: &[u8], size: Option<usize>, max: usize) -> Result<Vec<u8>, String> {
    let limit = size.map_or(max, |s| s.min(max));
    let out = match codec {
        Codec::Deflate => read_limited(flate2::read::DeflateDecoder::new(data), limit)?,
        Codec::Zlib => read_limited(flate2::read::ZlibDecoder::new(data), limit)?,
        Codec::Gzip => read_limited(flate2::read::GzDecoder::new(data), limit)?,
        Codec::Bzip2 => read_limited(bzip2::read::BzDecoder::new(data), limit)?,
        Codec::Lzma => nsis_codec(nsis::decompress::CompressionMethod::Lzma, data, size, limit)?,
        Codec::NsisBzip2 => nsis_codec(nsis::decompress::CompressionMethod::Bzip2, data, size, limit)?,
        Codec::LzmaAlone => {
            let props = data.get(..5).ok_or("lzma_alone: header too short")?;
            let stored = u64::from_le_bytes(data.get(5..13).ok_or("lzma_alone: header too short")?.try_into().unwrap_or([0; 8]));
            let mut raw = props.to_vec();
            raw.extend_from_slice(&data[13..]);
            let known = (stored != u64::MAX).then(|| usize::try_from(stored).unwrap_or(usize::MAX));
            if known.is_some_and(|k| k > max) {
                return Err(format!("lzma_alone: {stored} bytes is over the limit {max}"));
            }
            nsis_codec(nsis::decompress::CompressionMethod::Lzma, &raw, size.or(known), limit)?
        }
        Codec::Aplib => aplib(data, limit)?,
        Codec::Lznt1 => lznt1(data, limit)?,
    };
    if out.is_empty() {
        return Err(format!("{codec:?}: no output"));
    }
    Ok(out)
}

fn read_limited(r: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
    if out.len() > limit {
        out.truncate(limit);
    }
    Ok(out)
}

fn nsis_codec(method: nsis::decompress::CompressionMethod, data: &[u8], size: Option<usize>, limit: usize) -> Result<Vec<u8>, String> {
    use nsis::decompress::{decompress_block, DecodeLimit};
    let bound = match size {
        Some(s) => DecodeLimit::Exact(s.min(limit)),
        None => DecodeLimit::Truncate(limit),
    };
    decompress_block(data, method, bound).map(|d| d.data).map_err(|e| e.to_string())
}

/// aPLib depacker (the reference `aP_depack`), bounded by `limit`.
pub fn aplib(src: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    // "AP32" safe header: magic, header size, packed size, packed crc, original size, crc.
    let src = if src.starts_with(b"AP32") && src.len() >= 8 {
        let hdr = u32::from_le_bytes(src[4..8].try_into().unwrap_or([0; 4])) as usize;
        src.get(hdr..).ok_or("aplib: header past the end")?
    } else {
        src
    };
    struct Bits<'a> {
        src: &'a [u8],
        i: usize,
        tag: u8,
        left: u32,
    }
    impl Bits<'_> {
        fn byte(&mut self) -> Result<u8, String> {
            let b = *self.src.get(self.i).ok_or("aplib: input ends early")?;
            self.i += 1;
            Ok(b)
        }
        fn bit(&mut self) -> Result<usize, String> {
            if self.left == 0 {
                self.tag = self.byte()?;
                self.left = 8;
            }
            self.left -= 1;
            let b = (self.tag >> 7) & 1;
            self.tag <<= 1;
            Ok(b as usize)
        }
        fn gamma(&mut self) -> Result<usize, String> {
            let mut v = 1usize;
            loop {
                v = v.checked_mul(2).ok_or("aplib: bad gamma")? + self.bit()?;
                if self.bit()? == 0 {
                    return Ok(v);
                }
            }
        }
    }
    fn copy(dst: &mut Vec<u8>, offs: usize, len: usize, limit: usize) -> Result<(), String> {
        if offs == 0 || offs > dst.len() {
            return Err("aplib: match before the start".into());
        }
        if dst.len() + len > limit {
            return Err("aplib: output over the limit".into());
        }
        for _ in 0..len {
            dst.push(dst[dst.len() - offs]);
        }
        Ok(())
    }
    let mut b = Bits { src, i: 0, tag: 0, left: 0 };
    let mut dst = vec![b.byte()?];
    let (mut r0, mut lwm) = (0usize, false);
    loop {
        if dst.len() > limit {
            return Err("aplib: output over the limit".into());
        }
        if b.bit()? == 0 {
            dst.push(b.byte()?);
            lwm = false;
            continue;
        }
        if b.bit()? == 0 {
            let mut offs = b.gamma()?;
            if !lwm && offs == 2 {
                let len = b.gamma()?;
                copy(&mut dst, r0, len, limit)?;
            } else {
                offs -= if lwm { 2 } else { 3 };
                offs = (offs << 8) + b.byte()? as usize;
                let mut len = b.gamma()?;
                if offs >= 32000 {
                    len += 1;
                }
                if offs >= 1280 {
                    len += 1;
                }
                if offs < 128 {
                    len += 2;
                }
                copy(&mut dst, offs, len, limit)?;
                r0 = offs;
            }
            lwm = true;
        } else if b.bit()? == 0 {
            let v = b.byte()? as usize;
            let (len, offs) = (2 + (v & 1), v >> 1);
            if offs == 0 {
                return Ok(dst);
            }
            copy(&mut dst, offs, len, limit)?;
            r0 = offs;
            lwm = true;
        } else {
            let mut offs = 0usize;
            for _ in 0..4 {
                offs = (offs << 1) + b.bit()?;
            }
            if offs == 0 {
                dst.push(0);
            } else {
                copy(&mut dst, offs, 1, limit)?;
            }
            lwm = false;
        }
    }
}

/// LZNT1 (MS-XCA 2.5), bounded by `limit`.
pub fn lznt1(src: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= src.len() {
        let hdr = u16::from_le_bytes([src[i], src[i + 1]]);
        i += 2;
        if hdr == 0 {
            break;
        }
        let size = (hdr & 0x0FFF) as usize + 1;
        let chunk = src.get(i..i + size).ok_or("lznt1: chunk past the end")?;
        i += size;
        if hdr & 0x8000 == 0 {
            out.extend_from_slice(chunk);
        } else {
            let start = out.len();
            let mut j = 0;
            while j < chunk.len() {
                let flags = chunk[j];
                j += 1;
                for bit in 0..8 {
                    if j >= chunk.len() {
                        break;
                    }
                    if flags >> bit & 1 == 0 {
                        out.push(chunk[j]);
                        j += 1;
                        continue;
                    }
                    let token = u16::from_le_bytes([chunk[j], *chunk.get(j + 1).ok_or("lznt1: token past the end")?]) as usize;
                    j += 2;
                    let (mut pos, mut len_mask, mut shift) = (out.len() - start - 1, 0x0FFFusize, 12u32);
                    while pos >= 0x10 {
                        pos >>= 1;
                        len_mask >>= 1;
                        shift -= 1;
                    }
                    let (len, disp) = ((token & len_mask) + 3, (token >> shift) + 1);
                    if disp > out.len() - start {
                        return Err("lznt1: match before the chunk".into());
                    }
                    for _ in 0..len {
                        out.push(out[out.len() - disp]);
                    }
                }
            }
        }
        if out.len() > limit {
            return Err("lznt1: output over the limit".into());
        }
    }
    Ok(out)
}

/// RC4 with `key` over `data`.
pub fn rc4(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() || key.len() > 256 {
        return Err("rc4: key must be 1-256 bytes".into());
    }
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    Ok(data
        .iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect())
}

/// Standard base64 (whitespace ignored, `-` / `_` URL-safe letters accepted).
pub fn base64(text: &[u8]) -> Result<Vec<u8>, String> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut n) = (0u32, 0);
    for &c in text {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        acc = acc << 6 | val(c).ok_or_else(|| format!("base64: bad character {:?}", c as char))?;
        n += 1;
        if n == 4 {
            out.extend_from_slice(&acc.to_be_bytes()[1..]);
            (acc, n) = (0, 0);
        }
    }
    match n {
        0 => {}
        2 => out.push((acc >> 4) as u8),
        3 => out.extend_from_slice(&((acc >> 2) as u16).to_be_bytes()),
        _ => return Err("base64: truncated".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn standard_formats_round_trip() {
        let text = b"hello hello hello hello unpacker recipes".repeat(20);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&text).unwrap();
        let z = z.finish().unwrap();
        assert_eq!(decompress(Codec::Zlib, &z, None, 1 << 20).unwrap(), text);
        assert_eq!(decompress(Codec::Deflate, &z[2..], None, 1 << 20).unwrap(), text);
        // The limit truncates instead of growing past it.
        assert_eq!(decompress(Codec::Zlib, &z, None, 10).unwrap(), &text[..10]);
        assert!(decompress(Codec::Zlib, b"not zlib", None, 1 << 20).is_err());
    }

    #[test]
    fn aplib_reference_stream() {
        // Hand-assembled: literal 'a', literals 'b' 'c', then a short match of
        // length 3 at offset 3 ("abc"), then the end marker.
        //   tag 0b0_0_110_11 0..: bits after the first byte:
        //   0 literal b | 0 literal c | 110 short match (byte follows) | 110 end (byte 0)
        let packed = [b'a', 0b0011_0110, b'b', b'c', (3 << 1) | 1, 0x00];
        assert_eq!(aplib(&packed, 100).unwrap(), b"abcabc");
        assert!(aplib(&packed[..3], 100).is_err());
    }

    #[test]
    fn lznt1_literal_and_match() {
        // Compressed chunk: flags 0b100 -> 'a', 'b', then token len 3+1=4? use len 3, disp 2.
        // pos = 2 - 1 = 1 (< 0x10): 12-bit length, 4-bit displacement field.
        let token: u16 = ((2 - 1) << 12) | (3 - 3);
        let mut chunk = vec![0b100, b'a', b'b'];
        chunk.extend_from_slice(&token.to_le_bytes());
        let hdr: u16 = 0xB000 | (chunk.len() as u16 - 1);
        let mut src = hdr.to_le_bytes().to_vec();
        src.extend_from_slice(&chunk);
        assert_eq!(lznt1(&src, 100).unwrap(), b"ababa");
    }

    #[test]
    fn rc4_and_base64_known_values() {
        // RFC 6229-style vector: key "Key", plaintext "Plaintext".
        assert_eq!(rc4(b"Key", b"Plaintext").unwrap(), [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
        assert_eq!(base64(b"aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(base64(b"YQ").unwrap(), b"a");
        assert!(base64(b"a").is_err());
    }
}
