use crate::models::Hashes;
use digest::Digest;
use md5::Md5;
use sha2::Sha256;

pub fn hashes(bytes: &[u8]) -> Hashes {
    let sha256 = Sha256::digest(bytes);
    let md5 = Md5::digest(bytes);
    Hashes {
        sha256: hex::encode(sha256),
        md5: hex::encode(md5),
    }
}
