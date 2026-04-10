# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.crypto.hmac


HMAC-SHA256 class.
It computes digests using HMAC-SHA256 algorithm.
aHmacSha256
a__qualname__
key
T Obytes
Ostr
data
return
uHmacSha256.QuickDigest
D areturn
Oint
uHmacSha256.DigestSize

HMAC-SHA512 class.
It computes digests using HMAC-SHA512 algorithm.
uHmacSha512.QuickDigest
T Obytes
paQuickDigestHalves
uHmacSha512.QuickDigestHalves
uHmacSha512.DigestSize
ubip_utils\utils\crypto\hmac.py
u<module bip_utils.utils.crypto.hmac>
T a__class__
T akey
data
T akey
data
digest_bytes

a__spec__
.bip_utils.utils.crypto.pbkdf2
5
.
aHASHLIB_USE_PBKDF2_SHA512
hashlib
pbkdf2_hmac
sha512
aAlgoUtils
aEncode
aPBKDF2
aSHA512
digest_size
T acount
hmac_hash_module

Derive a key.
Args:
password (str or bytes): Password
salt (str or bytes)    : Salt
itr_num (int)          : Iteration number
dklen (int, optional)  : Length of the derived key (default: SHA-512 output length)
Returns:
bytes: Computed result
uModule for PBKDF2 algorithm.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aOptional
aUnion
uCrypto.Hash
T aSHA512
uCrypto.Protocol.KDF
T aPBKDF2
ubip_utils.utils.misc
T aAlgoUtils
