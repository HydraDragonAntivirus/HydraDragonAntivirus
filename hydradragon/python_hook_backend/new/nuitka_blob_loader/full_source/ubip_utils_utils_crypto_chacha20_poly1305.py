# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.crypto.chacha20_poly1305


ChaCha20-Poly1305 class.
It decrypts/encrypts data using ChaCha20-Poly1305 algorithm.
aChaCha20Poly1305
a__qualname__
key
T Obytes
Ostr
nonce
assoc_data
cipher_text
tag
return
aDecrypt
uChaCha20Poly1305.Decrypt
plain_text
T Obytes
paEncrypt
uChaCha20Poly1305.Encrypt
D areturn
Oint
aKeySize
uChaCha20Poly1305.KeySize

Get the tag size.
Returns:
int: Tag size
l aTagSize
uChaCha20Poly1305.TagSize
ubip_utils\utils\crypto\chacha20_poly1305.py
u<module bip_utils.utils.crypto.chacha20_poly1305>
T a__class__
T akey
nonce
assoc_data
cipher_text
tag
cipher
T akey
nonce
assoc_data
plain_text
cipher

a__spec__
.bip_utils.utils.crypto
C
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uutils\crypto
T aNUITKA_PACKAGE_bip_utils_utils
u\not_existing
crypto
T aNUITKA_PACKAGE_bip_utils_utils_crypto
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.utils.crypto.aes_ecb
T aAesEcbDecrypter
aAesEcbEncrypter
aAesEcbDecrypter
aAesEcbEncrypter
ubip_utils.utils.crypto.blake2
T aBlake2b
aBlake2b32
aBlake2b40
aBlake2b160
aBlake2b224
aBlake2b256
aBlake2b512
aBlake2b
aBlake2b32
aBlake2b40
aBlake2b160
aBlake2b224
aBlake2b256
aBlake2b512
ubip_utils.utils.crypto.chacha20_poly1305
T aChaCha20Poly1305
aChaCha20Poly1305
ubip_utils.utils.crypto.crc
T aCrc32
aXModemCrc
aCrc32
aXModemCrc
ubip_utils.utils.crypto.hash160
T aHash160
aHash160
ubip_utils.utils.crypto.hmac
T aHmacSha256
aHmacSha512
aHmacSha256
aHmacSha512
ubip_utils.utils.crypto.pbkdf2
T aPbkdf2HmacSha512
aPbkdf2HmacSha512
ubip_utils.utils.crypto.ripemd
T aRipemd160
aRipemd160
ubip_utils.utils.crypto.scrypt
T aScrypt
aScrypt
ubip_utils.utils.crypto.sha2
T aDoubleSha256
aSha256
aSha512
aSha512_256
aDoubleSha256
aSha256
aSha512
aSha512_256
ubip_utils.utils.crypto.sha3
T aKekkak256
aSha3_256
aKekkak256
aSha3_256
ubip_utils\utils\crypto\__init__.py
u<module bip_utils.utils.crypto>

a__spec__
.bip_utils.utils.crypto.crc
6
aIntegerUtils
aToBytes
aCrc32
aQuickIntDigest
aDigestSize
T abytes_num

Compute the digest (quick version).
Args:
data (str or bytes): Data
Returns:
bytes: Computed digest
binascii
crc32
aAlgoUtils
aEncode

Compute the digest as integer (quick version).
Args:
data (str or bytes): Data
Returns:
bytes: Computed digest
aXMODEM_CRC
new
digest
digest_size

Get the digest size in bytes.
Returns:
int: Digest size in bytes
uModule for CRC algorithms.
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
ucrcmod.predefined
crcmod
ubip_utils.utils.misc
T aAlgoUtils
aIntegerUtils
predefined
aCrc
T axmodem
