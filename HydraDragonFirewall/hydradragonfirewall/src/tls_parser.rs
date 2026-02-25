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
pub fn is_tls_handshake(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_tls() {
        assert_eq!(extract_sni(&[0x00, 0x01, 0x02]), None);
    }

    #[test]
    fn test_is_tls_handshake() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x01]));
    }
}
