# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.bip32.cardano_icarus_mst_key_generator

uClass container for Cardano Icarus master key generator constants.
a__qualname__
a__annotations__
l  l`a__prepare__
aCardanoIcarusMstKeyGenerator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Cardano Icarus master key generator class.
It allows master keys generation in according to Cardano Icarus.
classmethod
seed_bytes
bytes
return
aGenerateFromSeed
uCardanoIcarusMstKeyGenerator.GenerateFromSeed
staticmethod
key_bytes
a__TweakMasterKeyBits
uCardanoIcarusMstKeyGenerator.__TweakMasterKeyBits
a__orig_bases__
ubip_utils\cardano\bip32\cardano_icarus_mst_key_generator.py
u<module bip_utils.cardano.bip32.cardano_icarus_mst_key_generator>
T a__class__
T acls
seed_bytes
key_bytes
T akey_bytes
a__spec__
.bip_utils.cardano.bip32
A
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ucardano\bip32
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
bip32
T aNUITKA_PACKAGE_bip_utils_cardano_bip32
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.cardano.bip32.cardano_byron_legacy_bip32
T aCardanoByronLegacyBip32
aCardanoByronLegacyBip32
ubip_utils.cardano.bip32.cardano_icarus_bip32
T aCardanoIcarusBip32
aCardanoIcarusBip32
ubip_utils\cardano\bip32\__init__.py
u<module bip_utils.cardano.bip32>

a__spec__
.bip_utils.cardano.byron.cardano_byron_legacy
|
aCardanoByronLegacyBip32
aFromSeed

Construct class from seed bytes.
Args:
seed_bytes (bytes): Seed bytes
Returns:
CardanoByronLegacy object: CardanoByronLegacy object
uThe Bip32 object shall be a CardanoByronLegacyBip32 instance
aDepth
uThe Bip32 object shall be a master key (i.e. depth equal to 0)
m_bip32_obj

Construct class.
Args:
bip32_obj (Bip32Base object): Bip32Base object
Raises:
ValueError: If the bip32 object is not a master key
TypeError: If the bip32 object is not a CardanoByronLegacyBip32 class instance

Return the BIP32 object.
Returns:
Bip32Base object: Bip32Base object
aPbkdf2HmacSha512
aDeriveKey
aPublicKey
aRawCompressed
aToBytes
:l nnaChainCode
aCardanoByronLegacyConst
aHD_PATH_KEY_PBKDF2_SALT
aHD_PATH_KEY_PBKDF2_ROUNDS
aHD_PATH_KEY_PBKDF2_OUT_BYTE_LEN

Get the key used for HD path decryption/encryption.
Returns:
bytes: Key bytes
aAdaByronAddrDecoder
aDecodeAddr
aDecryptHdPath
aSplitDecodedBytes
aHdPathKey

Get the HD path from an address by decrypting it.
The address shall be derived from the current object master key (i.e. self.m_bip32_obj) in order to
successfully decrypt the path.
Args:
ddress (str): Address string
Returns:
Bip32Path object: Bip32Path object
Raises:
ValueError: If the address encoding is not valid or the path cannot be decrypted
aPrivateKey

Get the master private key.
Returns:
Bip32PrivateKey object: Bip32PrivateKey object

Get the master public key.
Returns:
Bip32PublicKey object: Bip32PublicKey object
a_CardanoByronLegacy__DeriveKey

Get the private key with the specified indexes.
Derivation path: m/first_idx'/second_idx'
The indexes will be automatically hardened if not (e.g. 0, 1' -> 0', 1').
Args:
first_idx (int or Bip32KeyIndex object) : First index
second_idx (int or Bip32KeyIndex object): Second index
Returns:
IPrivateKey object: IPrivateKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid

Get the public key with the specified indexes.
Derivation path: m/first_idx'/second_idx'
The indexes will be automatically hardened if not (e.g. 0, 1' -> 0', 1').
Args:
first_idx (int or Bip32KeyIndex object) : First index
second_idx (int or Bip32KeyIndex object): Second index
Returns:
IPublicKey object: IPublicKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
aGetPublicKey
aAdaByronLegacyAddrEncoder
aEncodeKey
aKeyObject
a_CardanoByronLegacy__GetDerivationPath
T achain_code
hd_path
hd_path_key

Get the address with the specified indexes.
Derivation path: m/first_idx'/second_idx'
The indexes will be automatically hardened if not (e.g. 0, 1' -> 0', 1').
Args:
first_idx (int or Bip32KeyIndex object) : First index
second_idx (int or Bip32KeyIndex object): Second index
Returns:
str: Address
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
aDerivePath

Derive the key with the specified change and address indexes.
Derivation path: m/first_idx'/second_idx'
Args:
first_idx (int or Bip32KeyIndex object) : First index
second_idx (int or Bip32KeyIndex object): Second index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
um/

u'/
w'u
Get the derivation path from the specified indexes.
Args:
first_idx (int or Bip32KeyIndex object) : First index
second_idx (int or Bip32KeyIndex object): Second index
Returns:
str: Derivation path
uModule for Cardano Byron legacy keys derivation.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
lru_cache
aUnion
ubip_utils.addr
T aAdaByronAddrDecoder
aAdaByronLegacyAddrEncoder
ubip_utils.bip.bip32
T aBip32Base
aBip32KeyIndex
aBip32Path
aBip32PrivateKey
aBip32PublicKey
aBip32Base
aBip32KeyIndex
aBip32Path
aBip32PrivateKey
aBip32PublicKey
ubip_utils.cardano.bip32
T aCardanoByronLegacyBip32
ubip_utils.utils.crypto
T aPbkdf2HmacSha512
