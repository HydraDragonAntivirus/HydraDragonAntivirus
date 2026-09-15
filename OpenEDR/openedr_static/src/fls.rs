use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{
    Mutex,
    atomic::{AtomicU32, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Host fallback chain. `edrcon.cfg` default (`fls.security.comodo.com`, the
/// host the OpenEDR C++ `flsService` actually uses) comes first, then the v7
/// host from `flsproto7.h`. The first host that returns a decodable reply wins.
const FALLBACK_HOSTS: &[&str] = &[
    "fls.security.comodo.com",
    "p10.r11.v7.fls.security.comodo.com",
];

/// Monotonic request-id source, seeded with the current time so concurrent
/// processes don't reuse the same ids.
static NEXT_REQ_ID: AtomicU32 = AtomicU32::new(0);

/// Cooldown after a fully failed chain query: while the cloud is dead every
/// file scan would otherwise stall for `hosts × timeout` seconds doing UDP
/// timeouts. A failed chain arms this timestamp; queries inside the window
/// fail fast with the same `Fail` verdict and no network I/O. Any decodable
/// reply clears it.
static LAST_CHAIN_FAIL: Mutex<Option<Instant>> = Mutex::new(None);
const CHAIN_FAIL_COOLDOWN: Duration = Duration::from_secs(30);

fn next_req_id() -> u32 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_millis() & 0xFFFF_FFFF) as u32)
        .unwrap_or(0);
    t.wrapping_add(NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed))
}

impl Default for FlsClient {
    fn default() -> Self {
        Self {
            // Kept for `FlsClient::new`-style single-host use; `query_sha1`
            // tries the full fallback chain regardless.
            host: FALLBACK_HOSTS[0].to_string(),
            port: 4447,
            // Matches C++ `nSendTimeoutMs/nReceiveTimeoutMs` (2000ms).
            timeout: Duration::from_millis(2000),
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
    /// Tries every host in the fallback chain (all resolved IPs each) and
    /// returns the first decodable reply. Returns `Fail` only when the network
    /// gave no usable answer, so callers can distinguish "cloud unreachable"
    /// from "cloud says Unknown/Absent".
    pub fn query_sha1(&self, sha1_hex: &str) -> FlsVerdict {
        if sha1_hex.len() != 40 {
            return FlsVerdict::Fail;
        }

        let raw_hash = match hex::decode(sha1_hex) {
            Ok(b) if b.len() == 20 => b,
            _ => return FlsVerdict::Fail,
        };

        // A custom single-host client (`FlsClient::new`) queries just that host;
        // the default client walks the whole fallback chain.
        if !FALLBACK_HOSTS.contains(&self.host.as_str()) {
            return self.query_host(&self.host, &raw_hash);
        }

        // Fail fast while a recent chain query already proved the cloud
        // unreachable (same verdict, no per-file UDP stall).
        if let Ok(guard) = LAST_CHAIN_FAIL.lock() {
            if let Some(t) = *guard {
                if t.elapsed() < CHAIN_FAIL_COOLDOWN {
                    return FlsVerdict::Fail;
                }
            }
        }

        for host in FALLBACK_HOSTS {
            let verdict = self.query_host(host, &raw_hash);
            if verdict != FlsVerdict::Fail {
                if let Ok(mut guard) = LAST_CHAIN_FAIL.lock() {
                    *guard = None;
                }
                return verdict;
            }
        }
        if let Ok(mut guard) = LAST_CHAIN_FAIL.lock() {
            *guard = Some(Instant::now());
        }
        FlsVerdict::Fail
    }

    fn query_host(&self, host: &str, raw_hash: &[u8]) -> FlsVerdict {
        // Construct FLS v7 SimpleRequest packet (mirrors `flsproto7.cpp`):
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
        let req_id: u32 = next_req_id();
        packet.extend_from_slice(&req_id.to_le_bytes());
        packet.push(10); // applicationId: CloudAntivirus = 10
        packet.extend_from_slice(&0u16.to_le_bytes()); // appVersion = 0
        packet.push(1); // callerType: FromOnAccess = 1
        packet.extend_from_slice(&[0u8; 16]); // guid (zero, same as C++ client)
        packet.push(0); // hashType: SHA1 = 0
        packet.extend_from_slice(raw_hash);

        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return FlsVerdict::Fail,
        };

        let _ = socket.set_read_timeout(Some(self.timeout));
        let _ = socket.set_write_timeout(Some(self.timeout));

        // Resolve and try every IP; a stale first record must not kill the query.
        let addrs: Vec<_> = match format!("{}:{}", host, self.port).to_socket_addrs() {
            Ok(it) => it.collect(),
            Err(_) => return FlsVerdict::Fail,
        };
        if addrs.is_empty() {
            return FlsVerdict::Fail;
        }

        for addr in addrs {
            if socket.send_to(&packet, addr).is_err() {
                continue;
            }

            let mut buf = [0u8; 1024];
            let bytes_read = match socket.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => continue, // timeout on this IP: try the next one
            };

            match Self::parse_response(&buf[..bytes_read], req_id) {
                Some(v) => return v,
                None => continue, // malformed reply: try next IP/host
            }
        }
        FlsVerdict::Fail
    }

    /// Validates a v7 SimpleRequest/rev2 reply. Each answer is 2 bytes wide
    /// (`getFileVerdict` calls `getVerdict(..., rev 2, answerSize 2)`), so a
    /// single-hash reply must be at least 4 (id) + 1 (count) + 2 = 7 bytes.
    /// Returns `None` on transport-level mismatch (id/count/size) so the
    /// caller keeps failing over instead of reporting a cloud verdict.
    fn parse_response(buf: &[u8], req_id: u32) -> Option<FlsVerdict> {
        // Response struct:
        // uint32_t nId (4 bytes)
        // uint8_t nNumOfAnswers (1 byte)
        // uint8_t answers... (each answer is 2 bytes for revision 2)
        if buf.len() < 7 {
            return None;
        }

        let resp_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if resp_id != req_id {
            return None;
        }

        if buf[4] != 1 {
            return None;
        }

        Some(match buf[5] {
            0 => FlsVerdict::Absent,
            1 => FlsVerdict::Safe,
            2 => FlsVerdict::Malicious,
            3 => FlsVerdict::Unknown,
            _ => FlsVerdict::Unknown,
        })
    }
}
