# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives._cipheralgorithm

aCipherAlgorithm
a__qualname__
property
abstractmethod
D areturn
str

A string naming this mode (e.g. "AES", "Camellia").
uCipherAlgorithm.name
D areturn
ufrozenset[int]

Valid key sizes for this algorithm in bits
uCipherAlgorithm.key_sizes
D areturn
int

The size of the key being used as an integer in bits (e.g. 128, 256).
key_size
uCipherAlgorithm.key_size
aBlockCipherAlgorithm
a__annotations__
bytes

The size of a block as an integer in bits (e.g. 64, 128).
block_size
uBlockCipherAlgorithm.block_size
a__orig_bases__
D aalgorithm
key
return
aCipherAlgorithm
bytes
pa_verify_key_size
ucryptography\hazmat\primitives\_cipheralgorithm.py
u<module cryptography.hazmat.primitives._cipheralgorithm>
T a__class__
T aalgorithm
key
T aself
a__spec__
.cryptography.hazmat.primitives._serialization
k
n
aPrivateFormat
aOpenSSH
aPKCS12
uencryption_builder only supported with PrivateFormat.OpenSSH and PrivateFormat.PKCS12
aKeySerializationEncryptionBuilder
uPassword must be 1 or more bytes.
password
a_format
a_kdf_rounds
a_hmac_hash
a_key_cert_algorithm
ukdf_rounds already set
ukdf_rounds must be an integer
ukdf_rounds must be a positive integer
T a_kdf_rounds
a_hmac_hash
a_key_cert_algorithm
uhmac_hash only supported with PrivateFormat.PKCS12
uhmac_hash already set
ukey_cert_algorithm only supported with PrivateFormat.PKCS12
ukey_cert_algorithm already set
a_KeySerializationEncryption
T akdf_rounds
hmac_hash
key_cert_algorithm
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
cryptography
T autils
utils
ucryptography.hazmat.primitives.hashes
T aHashAlgorithm
aHashAlgorithm
aEnum
a__prepare__
aPBES
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
