# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.ciphers.base

aCipherContext
a__qualname__
abstractmethod
D adata
return
bytes
pu
Processes the provided bytes through the cipher and returns the results
s bytes.
update
uCipherContext.update
D adata
buf
return
bytes
paint

Processes the provided bytes and writes the resulting data into the
provided buffer. Returns the number of bytes written.
update_into
uCipherContext.update_into
D areturn
bytes

Returns the results of processing the final block as bytes.
finalize
uCipherContext.finalize
D anonce
return
bytes
aNone

Resets the nonce for the cipher context to the provided value.
Raises an exception if it does not support reset or if the
provided nonce does not have a valid length.
reset_nonce
uCipherContext.reset_nonce
aAEADCipherContext
D adata
return
bytes
aNone

Authenticates the provided bytes.
authenticate_additional_data
uAEADCipherContext.authenticate_additional_data
a__orig_bases__
aAEADDecryptionContext
D atag
return
bytes
pu
Returns the results of processing the final block as bytes and allows
delayed passing of the authentication tag.
finalize_with_tag
uAEADDecryptionContext.finalize_with_tag
aAEADEncryptionContext
property

Returns tag bytes. This is only available after encryption is
finalized.
uAEADEncryptionContext.tag
aTypeVar
aOptional
T aMode
T abound
covariant
aGeneric
aCipher
T nD aalgorithm
mode
backend
return
aCipherAlgorithm
aMode
utyping.Any
aNone
a__init__
uCipher.__init__
overload
D aself
return
uCipher[modes.ModeWithAuthenticationTag]
aAEADEncryptionContext
encryptor
uCipher.encryptor
D aself
return
a_CIPHER_TYPE
aCipherContext
D aself
return
uCipher[modes.ModeWithAuthenticationTag]
aAEADDecryptionContext
decryptor
uCipher.decryptor
aUnion
aModeWithNonce
aModeWithTweak
aECB
aModeWithInitializationVector
a_CIPHER_TYPE
register
ucryptography\hazmat\primitives\ciphers\base.py
u<module cryptography.hazmat.primitives.ciphers.base>
T a__class__
T aself
algorithm
mode
backend
T aself
data
T aself
T aself
tag
T aself
nonce
T aself
data
buf

a__spec__
.cryptography.hazmat.primitives.ciphers
%
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_cryptography
u\not_existing
uhazmat\primitives\ciphers
T aNUITKA_PACKAGE_cryptography_hazmat
u\not_existing
uprimitives\ciphers
T aNUITKA_PACKAGE_cryptography_hazmat_primitives
u\not_existing
ciphers
T aNUITKA_PACKAGE_cryptography_hazmat_primitives_ciphers
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
annotations
ucryptography.hazmat.primitives._cipheralgorithm
T aBlockCipherAlgorithm
aCipherAlgorithm
aBlockCipherAlgorithm
aCipherAlgorithm
ucryptography.hazmat.primitives.ciphers.base
T aAEADCipherContext
aAEADDecryptionContext
aAEADEncryptionContext
aCipher
aCipherContext
aAEADCipherContext
aAEADDecryptionContext
aAEADEncryptionContext
aCipher
aCipherContext
L aAEADCipherContext
aAEADDecryptionContext
aAEADEncryptionContext
aBlockCipherAlgorithm
aCipher
aCipherAlgorithm
aCipherContext
a__all__
ucryptography\hazmat\primitives\ciphers\__init__.py
u<module cryptography.hazmat.primitives.ciphers>

a__spec__
.cryptography.hazmat.primitives.ciphers.modes
J
key_size
l  aname
aAES
uOnly 128, 192, and 256 bit keys are allowed for this AES mode
initialization_vector
l ablock_size
uInvalid IV size (

u) for
w.aBlockCipherAlgorithm
aUnsupportedAlgorithm
u requires a block cipher algorithm
a_Reasons
aUNSUPPORTED_CIPHER
uInvalid nonce size (
a_check_aes_key_length
a_check_iv_length
utils
a_check_byteslike
a_initialization_vector
tweak
utweak must be 128-bits (16 bytes)
a_tweak
algorithms
aAES128
aAES256
uThe AES128 and AES256 classes do not support XTS, please use the standard AES class instead.
T l  l  uThe XTS specification requires a 256-bit key for AES-128-XTS and 512-bit key for AES-256-XTS
nonce
a_nonce
a_check_nonce_length
uinitialization_vector must be between 8 and 128 bytes (64 and 1024 bits).
a_check_bytes
tag
l umin_tag_length must be >= 4
uAuthentication tag must be
u bytes or longer.
a_tag
a_min_tag_length
uGCM requires a block cipher algorithm
uAuthentication tag cannot be more than
u bytes.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
cryptography
T autils
ucryptography.exceptions
T aUnsupportedAlgorithm
a_Reasons
ucryptography.hazmat.primitives._cipheralgorithm
T aBlockCipherAlgorithm
aCipherAlgorithm
aCipherAlgorithm
ucryptography.hazmat.primitives.ciphers
T aalgorithms
metaclass
aABCMeta
a__prepare__
T aMode
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
