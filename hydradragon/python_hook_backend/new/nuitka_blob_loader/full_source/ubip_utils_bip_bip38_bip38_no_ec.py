# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip38.bip38_no_ec

uClass container for BIP38 no EC constants.
a__qualname__
a__annotations__
l'c B
d d l@l   l uClass container for BIP38 no EC utility functions.
priv_key_bytes
pub_key_mode
return
u_Bip38NoEcUtils.AddressHash
passphrase
address_hash
T Obytes
pu_Bip38NoEcUtils.DeriveKeyHalves

BIP38 encrypter class.
It encrypts a private key using the algorithm specified in BIP38 without EC multiplication.
priv_key
uBip38NoEcEncrypter.Encrypt
derived_half_1
derived_half_2
a__EncryptPrivateKey
uBip38NoEcEncrypter.__EncryptPrivateKey

BIP38 decrypter class.
It decrypts a private key using the algorithm specified in BIP38 without EC multiplication.
priv_key_enc
uBip38NoEcDecrypter.Decrypt
D aencrypted_half_1
encrypted_half_2
derived_half_1
derived_half_2
return
Obytes
ppppa__DecryptAndGetPrivKey
uBip38NoEcDecrypter.__DecryptAndGetPrivKey
ubip_utils\bip\bip38\bip38_no_ec.py
u<module bip_utils.bip.bip38.bip38_no_ec>
T apriv_key_bytes
pub_key_mode
T a__class__
Tapriv_key_enc
passphrase
priv_key_enc_bytes
prefix
flagbyte
address_hash
encrypted_half_1
encrypted_half_2
derived_half_1
derived_half_2
priv_key_bytes
pub_key_mode
address_hash_got
T apassphrase
address_hash
key
derived_half_1
derived_half_2
T apriv_key
passphrase
pub_key_mode
priv_key_bytes
address_hash
derived_half_1
derived_half_2
encrypted_half_1
encrypted_half_2
flagbyte
enc_key_bytes
T aencrypted_half_1
encrypted_half_2
derived_half_1
derived_half_2
aes_dec
decrypted_half_1
decrypted_half_2
T apriv_key_bytes
derived_half_1
derived_half_2
aes_enc
encrypted_half_1
encrypted_half_2
a__spec__
.bip_utils.bip.bip38
\
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip38
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
bip38
T aNUITKA_PACKAGE_bip_utils_bip_bip38
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip38.bip38
T aBip38Decrypter
aBip38Encrypter
aBip38Decrypter
aBip38Encrypter
ubip_utils.bip.bip38.bip38_addr
T aBip38PubKeyModes
aBip38PubKeyModes
ubip_utils.bip.bip38.bip38_ec
T aBip38EcKeysGenerator
aBip38EcKeysGenerator
ubip_utils\bip\bip38\__init__.py
u<module bip_utils.bip.bip38>

a__spec__
.bip_utils.bip.bip39.bip39_entropy_generator
T
E
aIsValidEntropyBitLen
uEntropy bit length is not valid (

w)a__class__
a__init__

Construct class.
Args:
bit_len (int or Bip39EntropyBitLen): Entropy length in bits
Raises:
ValueError: If the bit length is not valid
aBip39EntropyGeneratorConst
aENTROPY_BIT_LEN

Get if the specified entropy bit length is valid.
Args:
bit_len (int or Bip39EntropyBitLen): Entropy length in bits
Returns:
bool: True if valid, false otherwise
aBip39EntropyGenerator
l u
Get if the specified entropy byte length is valid.
Args:
byte_len (int): Entropy length in bytes
Returns:
bool: True if valid, false otherwise
uModule for BIP39 mnemonic entropy generation.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aIntEnum
unique
aIntEnum
unique
aList
aUnion
ubip_utils.utils.mnemonic
T aEntropyGenerator
aEntropyGenerator
a__prepare__
aBip39EntropyBitLen
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
