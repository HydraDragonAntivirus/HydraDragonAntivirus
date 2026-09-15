use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlsVerdict {
    Absent = 0,
    Safe = 1,
    Malicious = 2,
    Unknown = 3,
    Fail = 4,
}

impl FlsVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            FlsVerdict::Absent => "Absent",
            FlsVerdict::Safe => "Safe",
            FlsVerdict::Malicious => "Malicious",
            FlsVerdict::Unknown => "Unknown",
            FlsVerdict::Fail => "Fail",
        }
    }
}

pub struct FlsClient {
    host: String,
    port: u16,
    timeout: Duration,
}

impl Default for FlsClient {
    fn default() -> Self {
        Self {
            host: "p10.r11.v7.fls.security.comodo.com".to_string(),
            port: 4447,
            timeout: Duration::from_millis(2500),
        }
    }
}

impl FlsClient {
    pub fn new(host: &str, port: u16, timeout_ms: u64) -> Self {
        Self {
            host: host.to_string(),
            port,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Queries Comodo FLS v7 UDP endpoint for a single SHA-1 hash (40-hex lowercase).
    pub fn query_sha1(&self, sha1_hex: &str) -> FlsVerdict {
        if sha1_hex.len() != 40 {
            return FlsVerdict::Fail;
        }

        let raw_hash = match hex::decode(sha1_hex) {
            Ok(b) if b.len() == 20 => b,
            _ => return FlsVerdict::Fail,
        };

        // Construct FLS v7 SimpleRequest packet
        // Header:
        // marker (0xEF)
        // protocol_version (7)
        // request_type (0 = SimpleRequest)
        // request_type_revision (2)
        // payload_size (u16 LE) = sizeof(payload):
        //   id (u32), app_id (10), app_ver (0: u16), caller_type (1), guid (16 zero bytes), hash_type (0: SHA1), hashes (20 bytes)
        let mut packet = Vec::with_capacity(64);
        packet.push(0xEF); // marker
        packet.push(7);    // nProtocolVersion
        packet.push(0);    // requestType: SimpleRequest = 0
        packet.push(2);    // nRequestTypeRevision = 2

        let payload_len: u16 = 4 + 1 + 2 + 1 + 16 + 1 + 20;
        packet.extend_from_slice(&payload_len.to_le_bytes());

        // Payload
        let req_id: u32 = 0x1337;
        packet.extend_from_slice(&req_id.to_le_bytes());
        packet.push(10); // applicationId: CloudAntivirus = 10
        packet.extend_from_slice(&0u16.to_le_bytes()); // appVersion = 0
        packet.push(1); // callerType: FromOnAccess = 1
        packet.extend_from_slice(&[0u8; 16]); // guid
        packet.push(0); // hashType: SHA1 = 0
        packet.extend_from_slice(&raw_hash);

        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return FlsVerdict::Fail,
        };

        let _ = socket.set_read_timeout(Some(self.timeout));
        let _ = socket.set_write_timeout(Some(self.timeout));

        let remote_addr = format!("{}:{}", self.host, self.port);
        if socket.send_to(&packet, &remote_addr).is_err() {
            return FlsVerdict::Fail;
        }

        let mut buf = [0u8; 1024];
        let bytes_read = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => return FlsVerdict::Fail,
        };

        // Response struct:
        // uint32_t nId (4 bytes)
        // uint8_t nNumOfAnswers (1 byte)
        // uint8_t answers... (each answer is 2 bytes for revision 2)
        if bytes_read < 5 {
            return FlsVerdict::Fail;
        }

        let resp_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if resp_id != req_id {
            return FlsVerdict::Fail;
        }

        let num_answers = buf[4];
        if num_answers < 1 || bytes_read < 6 {
            return FlsVerdict::Unknown;
        }

        let verdict_byte = buf[5];
        match verdict_byte {
            0 => FlsVerdict::Absent,
            1 => FlsVerdict::Safe,
            2 => FlsVerdict::Malicious,
            3 => FlsVerdict::Unknown,
            _ => FlsVerdict::Unknown,
        }
    }
}
