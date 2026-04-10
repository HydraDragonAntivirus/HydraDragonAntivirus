# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.slip10.bip32_slip10_secp256k1


BIP32 SLIP-0010 secp256k1 v.
It allows master keys generation and keys derivation using secp256k1 curve.
a__qualname__
staticmethod
return
aCurveType
uBip32Slip10Secp256k1.CurveType
a_DefaultKeyNetVersion
uBip32Slip10Secp256k1._DefaultKeyNetVersion
a_KeyDerivator
uBip32Slip10Secp256k1._KeyDerivator
a_MasterKeyGenerator
uBip32Slip10Secp256k1._MasterKeyGenerator
a__orig_bases__
aBip32Secp256k1
ubip_utils\bip\bip32\slip10\bip32_slip10_secp256k1.py
u<module bip_utils.bip.bip32.slip10.bip32_slip10_secp256k1>
T a__class__

a__spec__
.bip_utils.bip.bip32.slip10
0
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip32\slip10
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
ubip32\slip10
T aNUITKA_PACKAGE_bip_utils_bip_bip32
u\not_existing
slip10
T aNUITKA_PACKAGE_bip_utils_bip_bip32_slip10
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip32.slip10.bip32_slip10_ed25519
T aBip32Ed25519Slip
aBip32Slip10Ed25519
aBip32Ed25519Slip
aBip32Slip10Ed25519
ubip_utils.bip.bip32.slip10.bip32_slip10_ed25519_blake2b
T aBip32Ed25519Blake2bSlip
aBip32Slip10Ed25519Blake2b
aBip32Ed25519Blake2bSlip
aBip32Slip10Ed25519Blake2b
ubip_utils.bip.bip32.slip10.bip32_slip10_key_derivator
T aBip32Slip10EcdsaDerivator
aBip32Slip10Ed25519Derivator
aBip32Slip10EcdsaDerivator
aBip32Slip10Ed25519Derivator
ubip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator
T aBip32Slip10Ed2519MstKeyGenerator
aBip32Slip10Nist256p1MstKeyGenerator
aBip32Slip10Secp256k1MstKeyGenerator
aBip32Slip10Ed2519MstKeyGenerator
aBip32Slip10Nist256p1MstKeyGenerator
aBip32Slip10Secp256k1MstKeyGenerator
ubip_utils.bip.bip32.slip10.bip32_slip10_nist256p1
T aBip32Nist256p1
aBip32Slip10Nist256p1
aBip32Nist256p1
aBip32Slip10Nist256p1
ubip_utils.bip.bip32.slip10.bip32_slip10_secp256k1
T aBip32Secp256k1
aBip32Slip10Secp256k1
aBip32Secp256k1
aBip32Slip10Secp256k1
ubip_utils\bip\bip32\slip10\__init__.py
u<module bip_utils.bip.bip32.slip10>

a__spec__
.bip_utils.bip.bip38.bip38
F
>
aBip38NoEcEncrypter
aEncrypt

Encrypt the specified private key without EC multiplication.
Args:
priv_key (bytes or IPrivateKey)          : Private key bytes or object
passphrase (str)                         : Passphrase
pub_key_mode (Bip38PubKeyModes, optional): Public key mode
Returns:
str: Encrypted private key
Raises:
TypeError: If the private key is not a Secp256k1PrivateKey
ValueError: If the private key bytes are not valid
aBip38EcKeysGenerator
aGenerateIntermediatePassphrase
aGeneratePrivateKey

Generate a random encrypted private key with EC multiplication, using the specified parameters.
This will generate the intermediate passphrase and use it immediately for generating the private key.
Args:
passphrase (str)                         : Passphrase
pub_key_mode (Bip38PubKeyModes, optional): Public key mode
lot_num (int, optional)                  : Lot number
sequence_num (int, optional)             : Sequence number
Returns:
str: Encrypted private key
aBip38NoEcDecrypter
aDecrypt

Decrypt the specified private key without EC multiplication.
Args:
priv_key_enc (str): Encrypted private key bytes
passphrase (str)  : Passphrase
Returns:
tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)
Raises:
Base58ChecksumError: If base58 checksum is not valid
ValueError: If the encrypted key is not valid
aBip38EcDecrypter

Decrypt the specified private key with EC multiplication.
Args:
priv_key_enc (str): Encrypted private key bytes
passphrase (str)  : Passphrase
Returns:
tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)
Raises:
Base58ChecksumError: If base58 checksum is not valid
ValueError: If the encrypted key is not valid

Module for BIP38 encryption/decryption.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aTuple
aUnion
ubip_utils.bip.bip38.bip38_addr
T aBip38PubKeyModes
aBip38PubKeyModes
ubip_utils.bip.bip38.bip38_ec
T aBip38EcDecrypter
aBip38EcKeysGenerator
ubip_utils.bip.bip38.bip38_no_ec
T aBip38NoEcDecrypter
aBip38NoEcEncrypter
ubip_utils.ecc
T aIPrivateKey
aIPrivateKey
