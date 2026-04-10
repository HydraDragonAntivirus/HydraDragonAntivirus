# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.crypto.aes_ecb


AES-ECB encrypter class.
It encrypts data using AES-ECB algorithm.
aAesEcbEncrypter
a__qualname__
a__annotations__
key
T Ostr
Obytes
return
a__init__
uAesEcbEncrypter.__init__
D avalue
return
Obool
naAutoPad
uAesEcbEncrypter.AutoPad
data
aEncrypt
uAesEcbEncrypter.Encrypt
uAesEcbEncrypter.Pad

AES-ECB decrypter class.
It decrypts data using AES-ECB algorithm.
aAesEcbDecrypter
uAesEcbDecrypter.__init__
aAutoUnPad
uAesEcbDecrypter.AutoUnPad
D adata
return
Obytes
paDecrypt
uAesEcbDecrypter.Decrypt
uAesEcbDecrypter.UnPad
ubip_utils\utils\crypto\aes_ecb.py
u<module bip_utils.utils.crypto.aes_ecb>
T a__class__
T aself
value
T aself
data
dec
T aself
data
padded_data
T adata
T aself
key

a__spec__
.bip_utils.utils.crypto.blake2
S
hashlib
blake2b
aAlgoUtils
aEncode
T adigest_size
key
salt
digest

Compute the digest (quick version).
Args:
data (str or bytes)           : Data
digest_size (int)             : Digest size
key ((str or bytes, optional) : Key (default: empty)
salt ((str or bytes, optional): Salt (default: empty)
Returns:
bytes: Computed digest
aBlake2b
aQuickDigest
aDigestSize

Compute the digest (quick version).
Args:
data (str or bytes)          : Data
key (str or bytes, optional) : Key bytes (default: empty)
salt (str or bytes, optional): Salt bytes (default: empty)
Returns:
bytes: Computed digest
uModule for BLAKE-2 algorithms.
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
aUnion
ubip_utils.utils.misc
T aAlgoUtils
