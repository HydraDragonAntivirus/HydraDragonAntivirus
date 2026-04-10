# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.crypto.hash160


HASH160 class.
It computes digests using HASH160 algorithm.
aHash160
a__qualname__
data
T Obytes
Ostr
return
uHash160.QuickDigest
D areturn
Oint
uHash160.DigestSize
ubip_utils\utils\crypto\hash160.py
u<module bip_utils.utils.crypto.hash160>
T a__class__
T adata

a__spec__
.bip_utils.utils.crypto.hmac
5
aHMAC_USE_DIGEST
hmac
digest
aAlgoUtils
aEncode
sha256
new
hashlib

Compute the digest (quick version).
Args:
key (str or bytes) : Key
data (str or bytes): Data
Returns:
bytes: Computed digest
digest_size

Get the digest size in bytes.
Returns:
int: Digest size in bytes
sha512
aHmacSha512
aQuickDigest
aDigestSize
l u
Compute the digest and return it split into two halves (quick version).
Args:
key (str or bytes) : Key
data (str or bytes): Data
Returns:
tuple[bytes, bytes]: Computed digest left part (index 0) and right part (index 1)
uModule for SHA-2 algorithms.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aTuple
aUnion
ubip_utils.utils.misc
T aAlgoUtils
