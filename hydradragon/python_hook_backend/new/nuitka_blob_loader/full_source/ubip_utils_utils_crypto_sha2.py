# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.crypto.sha2


SHA256 class.
It computes digests using SHA256 algorithm.
a__qualname__
D areturn
na__init__
uSha256.__init__
D adata_bytes
return
Obytes
naUpdate
uSha256.Update
D areturn
Obytes
aDigest
uSha256.Digest
data
T Obytes
Ostr
return
uSha256.QuickDigest
D areturn
Oint
uSha256.DigestSize

Double SHA256 class.
It computes digests using SHA256 algorithm twice.
aDoubleSha256
uDoubleSha256.QuickDigest
uDoubleSha256.DigestSize

SHA512 class.
It computes digests using SHA512 algorithm.
aSha512
uSha512.QuickDigest
uSha512.DigestSize

SHA512/256 class.
It computes digests using SHA512/256 algorithm.
aSha512_256
uSha512_256.QuickDigest
uSha512_256.DigestSize
ubip_utils\utils\crypto\sha2.py
u<module bip_utils.utils.crypto.sha2>
T aself
T a__class__
T adata
T aself
data_bytes

a__spec__
.bip_utils.utils.crypto.sha3
_
5
keccak
new
aAlgoUtils
aEncode
l  T adata
digest_bits
digest

Compute the digest (quick version).
Args:
data (str or bytes): Data
Returns:
bytes: Computed digest
aHASHLIB_USE_SHA3_256
hashlib
T asha3_256
digest_size
T l  T adigest_bits

Get the digest size in bytes.
Returns:
int: Digest size in bytes
sha3_256
aSHA3_256
uModule for SHA-3 algorithms.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aUnion
uCrypto.Hash
T aSHA3_256
keccak
ubip_utils.utils.misc
T aAlgoUtils
algorithms_available
