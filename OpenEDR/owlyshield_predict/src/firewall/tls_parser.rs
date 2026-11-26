//! TLS Parser Module - Extracts SNI (Server Name Indication) from TLS Client Hello packets
//!
//! This module parses TLS handshake packets to extract the hostname being connected to,
//! enabling the firewall to filter HTTPS traffic by domain name.

/// Extracts the Server Name Indication (SNI) hostname from a TLS Client Hello packet.
///
/// # Arguments
/// * `data` - Raw packet payload (TCP payload, not including IP/TCP headers)
///
/// # Returns
/// * `Some(String)` - The extracted hostname if this is a valid TLS Client Hello with SNI
/// * `None` - If the packet is not a TLS Client Hello or has no SNI extension
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // Minimum TLS record header size
    if data.len() < 5 {
        return None;
    }

    // Check TLS record header
    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return None;
    }

    // TLS version (we accept 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3)
    let version = u16::from_be_bytes([data[1], data[2]]);
    if version < 0x0301 || version > 0x0303 {
        return None;
    }

    // Record length
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        return None;
    }

    // Handshake header starts at offset 5
    let handshake = &data[5..];
    if handshake.is_empty() {
        return None;
    }

    // Handshake type 0x01 = Client Hello
    if handshake[0] != 0x01 {
        return None;
    }

    // Handshake length (3 bytes)
    if handshake.len() < 4 {
        return None;
    }
    let handshake_length =
        u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    if handshake.len() < 4 + handshake_length {
        return None;
    }

    // Client Hello starts at offset 4
    let client_hello = &handshake[4..];

    // Skip: Version (2) + Random (32) = 34 bytes
    if client_hello.len() < 34 {
        return None;
    }
    let mut offset = 34;

    // Session ID length (1 byte) + Session ID
    if client_hello.len() < offset + 1 {
        return None;
    }
    let session_id_len = client_hello[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher Suites length (2 bytes) + Cipher Suites
    if client_hello.len() < offset + 2 {
        return None;
    }
    let cipher_suites_len =
        u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression Methods length (1 byte) + Compression Methods
    if client_hello.len() < offset + 1 {
        return None;
    }
    let compression_len = client_hello[offset] as usize;
    offset += 1 + compression_len;

    // Extensions length (2 bytes)
    if client_hello.len() < offset + 2 {
        return None;
    }
    let extensions_len =
        u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2;

    // Parse extensions
    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end && offset + 4 <= client_hello.len() {
        let ext_type = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]);
        let ext_len =
            u16::from_be_bytes([client_hello[offset + 2], client_hello[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > client_hello.len() {
            break;
        }

        // SNI extension type = 0x0000
        if ext_type == 0x0000 {
            return parse_sni_extension(&client_hello[offset..offset + ext_len]);
        }

        offset += ext_len;
    }

    None
}

/// Parses the SNI extension data to extract the hostname
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // SNI extension format:
    // - Server Name List Length (2 bytes)
    // - Server Name Type (1 byte, 0x00 = hostname)
    // - Server Name Length (2 bytes)
    // - Server Name (variable)

    if data.len() < 5 {
        return None;
    }

    let _list_len = u16::from_be_bytes([data[0], data[1]]);
    let name_type = data[2];

    // Type 0x00 = DNS hostname
    if name_type != 0x00 {
        return None;
    }

    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return None;
    }

    let hostname_bytes = &data[5..5 + name_len];
    String::from_utf8(hostname_bytes.to_vec()).ok()
}

/// Checks if the packet appears to be a TLS handshake (quick check)
use sha1::{Digest, Sha1};

/// Extracts the SHA-1 fingerprint (lowercase hex, 40 chars) of the first certificate
/// from a TLS Server Certificate handshake message (Handshake type 0x0b).
/// Matches the Abuse.ch SSLBL format.
pub fn extract_server_certificate_sha1(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    // Record type must be Handshake (0x16)
    if data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }
    let mut offset = 5;
    let end = 5 + record_len;

    while offset + 4 <= end {
        let msg_type = data[offset];
        let msg_len =
            u32::from_be_bytes([0, data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + msg_len > end {
            break;
        }
        if msg_type == 0x0b {
            // Certificate message: 3 bytes total chain length
            if msg_len < 3 {
                return None;
            }
            let mut cert_offset = offset + 3;
            if cert_offset + 3 <= offset + msg_len {
                let first_cert_len = u32::from_be_bytes([
                    0,
                    data[cert_offset],
                    data[cert_offset + 1],
                    data[cert_offset + 2],
                ]) as usize;
                cert_offset += 3;
                if cert_offset + first_cert_len <= offset + msg_len {
                    let cert_der = &data[cert_offset..cert_offset + first_cert_len];
                    let mut hasher = Sha1::new();
                    hasher.update(cert_der);
                    let result = hasher.finalize();
                    return Some(hex::encode(result));
                }
            }
        }
        offset += msg_len;
    }
    None
}

pub fn is_tls_handshake(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03
}

/// Checks whether a 16-bit TLS identifier is a GREASE value (RFC 8701).
#[inline]
fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0xff))
}

/// Extracts the Handshake body slice if `data` starts with a TLS Handshake record
/// of `expected_handshake_type` (0x01 ClientHello, 0x02 ServerHello).
fn extract_handshake_body(data: &[u8], expected_handshake_type: u8) -> Option<&[u8]> {
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    let version = u16::from_be_bytes([data[1], data[2]]);
    if version < 0x0300 || version > 0x0304 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record_end = (5 + record_len).min(data.len());
    let handshake = &data[5..record_end];
    if handshake.len() < 4 || handshake[0] != expected_handshake_type {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    let body_end = (4 + hs_len).min(handshake.len());
    if body_end <= 4 {
        return None;
    }
    Some(&handshake[4..body_end])
}

fn join_u16_dash(vals: &[u16]) -> String {
    let mut out = String::new();
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.push_str(&v.to_string());
    }
    out
}

/// Computes Salesforce JA3 fingerprint (MD5 hex) from a TLS ClientHello packet.
pub fn extract_ja3(data: &[u8]) -> Option<String> {
    let body = extract_handshake_body(data, 0x01)?;
    if body.len() < 35 {
        return None;
    }
    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut offset = 34;

    let session_id_len = *body.get(offset)? as usize;
    offset += 1 + session_id_len;

    let cipher_bytes_len =
        u16::from_be_bytes([*body.get(offset)?, *body.get(offset + 1)?]) as usize;
    offset += 2;
    if offset + cipher_bytes_len > body.len() {
        return None;
    }
    let mut ciphers = Vec::new();
    let mut ci = 0;
    while ci + 2 <= cipher_bytes_len {
        let cs = u16::from_be_bytes([body[offset + ci], body[offset + ci + 1]]);
        if !is_grease(cs) {
            ciphers.push(cs);
        }
        ci += 2;
    }
    offset += cipher_bytes_len;

    let comp_len = *body.get(offset)? as usize;
    offset += 1 + comp_len;

    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();

    if offset + 2 <= body.len() {
        let exts_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;
        let exts_end = (offset + exts_len).min(body.len());
        while offset + 4 <= exts_end {
            let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let ext_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_len > exts_end {
                break;
            }
            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }
            let ext_data = &body[offset..offset + ext_len];
            if ext_type == 0x000a && ext_data.len() >= 2 {
                let list_len = (u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize)
                    .min(ext_data.len() - 2);
                let mut i = 2;
                while i + 2 <= 2 + list_len {
                    let g = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
                    if !is_grease(g) {
                        curves.push(g);
                    }
                    i += 2;
                }
            } else if ext_type == 0x000b && !ext_data.is_empty() {
                let list_len = (ext_data[0] as usize).min(ext_data.len() - 1);
                for &pf in &ext_data[1..1 + list_len] {
                    point_formats.push(pf as u16);
                }
            }
            offset += ext_len;
        }
    }

    let ja3_raw = format!(
        "{},{},{},{},{}",
        tls_version,
        join_u16_dash(&ciphers),
        join_u16_dash(&extensions),
        join_u16_dash(&curves),
        join_u16_dash(&point_formats)
    );
    Some(crate::pe_hashes::md5_hex(ja3_raw.as_bytes()))
}

/// Computes Salesforce JA3S fingerprint (MD5 hex) from a TLS ServerHello packet.
pub fn extract_ja3s(data: &[u8]) -> Option<String> {
    let body = extract_handshake_body(data, 0x02)?;
    if body.len() < 38 {
        return None;
    }
    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut offset = 34;

    let session_id_len = *body.get(offset)? as usize;
    offset += 1 + session_id_len;

    let cipher = u16::from_be_bytes([*body.get(offset)?, *body.get(offset + 1)?]);
    offset += 2;
    // Compression method (1 byte)
    let _comp = *body.get(offset)?;
    offset += 1;

    let mut extensions = Vec::new();
    if offset + 2 <= body.len() {
        let exts_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;
        let exts_end = (offset + exts_len).min(body.len());
        while offset + 4 <= exts_end {
            let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let ext_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_len > exts_end {
                break;
            }
            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }
            offset += ext_len;
        }
    }

    let ja3s_raw = format!("{},{},{}", tls_version, cipher, join_u16_dash(&extensions));
    Some(crate::pe_hashes::md5_hex(ja3s_raw.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_server_certificate_sha1() {
        // Construct synthetic TLS record with Certificate handshake (0x0b)
        let dummy_cert = b"MIIB...TEST_CERTIFICATE_PAYLOAD...";
        let cert_len = dummy_cert.len();
        let chain_len = cert_len + 3;
        let msg_len = chain_len + 3;
        let record_len = msg_len + 4;

        let mut packet = vec![0x16, 0x03, 0x03]; // Handshake, TLS 1.2
        packet.extend_from_slice(&(record_len as u16).to_be_bytes()); // Record len
        packet.push(0x0b); // Type: Certificate
        packet.extend_from_slice(&(msg_len as u32).to_be_bytes()[1..4]); // msg len (3 bytes)
        packet.extend_from_slice(&(chain_len as u32).to_be_bytes()[1..4]); // chain len (3 bytes)
        packet.extend_from_slice(&(cert_len as u32).to_be_bytes()[1..4]); // first cert len (3 bytes)
        packet.extend_from_slice(dummy_cert);

        let sha1_opt = extract_server_certificate_sha1(&packet);
        assert!(sha1_opt.is_some());
        let sha1_str = sha1_opt.unwrap();
        assert_eq!(sha1_str.len(), 40);

        let mut expected_hasher = Sha1::new();
        expected_hasher.update(dummy_cert);
        let expected_hex = hex::encode(expected_hasher.finalize());
        assert_eq!(sha1_str, expected_hex);
    }

    #[test]
    fn test_not_tls() {
        assert_eq!(extract_sni(&[0x00, 0x01, 0x02]), None);
    }

    #[test]
    fn test_is_tls_handshake() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x01]));
    }

    #[test]
    fn test_extract_ja3_filters_grease() {
        // Construct ClientHello: version 0x0303 (771), ciphers [0x0a0a (GREASE), 0x1301 (4865), 0xc02f (49199)]
        // extensions: [0x1a1a (GREASE), 0x000a supported_groups [0x2a2a, 0x001d (29)], 0x000b ec_point_formats [0x00]]
        let mut exts = Vec::new();
        // GREASE ext 0x1a1a len 0
        exts.extend_from_slice(&0x1a1au16.to_be_bytes());
        exts.extend_from_slice(&0u16.to_be_bytes());
        // supported_groups 0x000a -> len 6: list_len=4, 0x2a2a, 0x001d
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&6u16.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes());
        exts.extend_from_slice(&0x2a2au16.to_be_bytes());
        exts.extend_from_slice(&0x001du16.to_be_bytes());
        // ec_point_formats 0x000b -> len 2: list_len=1, 0x00
        exts.extend_from_slice(&0x000bu16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.push(1);
        exts.push(0);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // version 771
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&6u16.to_be_bytes()); // cipher suites len (3 * 2)
        body.extend_from_slice(&0x0a0au16.to_be_bytes()); // GREASE
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // 4865
        body.extend_from_slice(&0xc02fu16.to_be_bytes()); // 49199
        body.push(1); // compression len
        body.push(0); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut pkt = vec![0x16, 0x03, 0x01];
        pkt.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        pkt.push(0x01); // ClientHello
        pkt.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        pkt.extend_from_slice(&body);

        let expected = crate::pe_hashes::md5_hex(b"771,4865-49199,10-11,29,0");
        assert_eq!(extract_ja3(&pkt).as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn test_extract_ja3s() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002bu16.to_be_bytes()); // supported_versions (43)
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&0x0304u16.to_be_bytes());
        exts.extend_from_slice(&0x0033u16.to_be_bytes()); // key_share (51)
        exts.extend_from_slice(&0u16.to_be_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // 771
        body.extend_from_slice(&[1u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // 4865
        body.push(0); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut pkt = vec![0x16, 0x03, 0x03];
        pkt.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        pkt.push(0x02); // ServerHello
        pkt.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        pkt.extend_from_slice(&body);

        let expected = crate::pe_hashes::md5_hex(b"771,4865,43-51");
        assert_eq!(extract_ja3s(&pkt).as_deref(), Some(expected.as_str()));
    }
}
