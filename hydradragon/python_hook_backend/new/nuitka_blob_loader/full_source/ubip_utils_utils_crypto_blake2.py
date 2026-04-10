# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.crypto.blake2


BLAKE2b class.
It computes digests using BLAKE2b algorithm.
a__qualname__
T c
padata
T Obytes
Ostr
digest_size
key
salt
return
uBlake2b.QuickDigest
a__prepare__
a_Blake2bWithSpecificSize
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uAbstract class for Blake2b with specific digest size.
classmethod
bytes
str
u_Blake2bWithSpecificSize.QuickDigest
staticmethod
int

Get the digest size in bytes.
Returns:
int: Digest size in bytes
u_Blake2bWithSpecificSize.DigestSize
a__orig_bases__
aBlake2b32

BLAKE2b-32 class.
It computes digests using BLAKE2b-32 algorithm.
l uBlake2b32.DigestSize
aBlake2b40

BLAKE2b-40 class.
It computes digests using BLAKE2b-40 algorithm.
l uBlake2b40.DigestSize
aBlake2b160

BLAKE2b-160 class.
It computes digests using BLAKE2b-160 algorithm.
l uBlake2b160.DigestSize
aBlake2b224

BLAKE2b-224 class.
It computes digests using BLAKE2b-224 algorithm.
l uBlake2b224.DigestSize
aBlake2b256

BLAKE2b-256 class.
It computes digests using BLAKE2b-256 algorithm.
l uBlake2b256.DigestSize
aBlake2b512

BLAKE2b-512 class.
It computes digests using BLAKE2b-512 algorithm.
l@uBlake2b512.DigestSize
ubip_utils\utils\crypto\blake2.py
u<module bip_utils.utils.crypto.blake2>
T a__class__
T adata
digest_size
key
salt
T acls
data
key
salt

a__spec__
.bip_utils.utils.crypto.chacha20_poly1305
8
aChaCha20_Poly1305
new
aAlgoUtils
aEncode
T akey
nonce
update
decrypt_and_verify

Decrypt data.
Args:
key (str or bytes)       : Key
nonce (str or bytes)     : Nonce
ssoc_data (str or bytes): Associated data
cipher_text (bytes)      : Cipher text
tag (bytes)              : Tag
Returns:
bytes: Decrypted data
encrypt_and_digest

Encrypt data.
Args:
key (str or bytes)       : Key
nonce (str or bytes)     : Nonce
ssoc_data (str or bytes): Associated data
plain_text (str or bytes): Plain text
Returns:
tuple[bytes, bytes]: Cipher text bytes (index 0) and tag bytes (index 1)
key_size

Get the key size.
Returns:
int: Key size
uModule for ChaCha20-Poly1305 algorithm.
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
aUnion
uCrypto.Cipher
T aChaCha20_Poly1305
ubip_utils.utils.misc
T aAlgoUtils
