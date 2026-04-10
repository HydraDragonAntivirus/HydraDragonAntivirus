# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip44.bip44

uClass container for BIP44 constants.
a__qualname__
a__annotations__
uBIP-0044
aHardenIndex
T l,a__prepare__
aBip44
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

BIP44 class.
It allows master key generation and children keys derivation in according to BIP-0044.
classmethod
seed_bytes
bytes
coin_type
return
aFromSeed
uBip44.FromSeed
ex_key_str
str
aFromExtendedKey
uBip44.FromExtendedKey
priv_key
key_data
aFromPrivateKey
uBip44.FromPrivateKey
aACCOUNT
T adepth
pub_key
aFromPublicKey
uBip44.FromPublicKey
aPurpose
uBip44.Purpose
aCoin
uBip44.Coin
acc_idx
int
aAccount
uBip44.Account
change_type
aChange
uBip44.Change
addr_idx
aAddressIndex
uBip44.AddressIndex
staticmethod
aSpecName
uBip44.SpecName
a__orig_bases__
ubip_utils\bip\bip44\bip44.py
u<module bip_utils.bip.bip44.bip44>
T aself
acc_idx
T aself
addr_idx
T a__class__
T aself
change_type
T aself
T acls
ex_key_str
coin_type
T acls
priv_key
coin_type
key_data
T acls
pub_key
coin_type
key_data
T acls
seed_bytes
coin_type

a__spec__
.bip_utils.bip.bip44
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip44
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
bip44
T aNUITKA_PACKAGE_bip_utils_bip_bip44
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip44.bip44
T aBip44
aBip44
ubip_utils\bip\bip44\__init__.py
u<module bip_utils.bip.bip44>

a__spec__
.bip_utils.bip.bip44_base.bip44_base
:
aBip32Class
aFromSeed
aKeyNetVersions

Create a Bip44Base object from the specified seed (e.g. BIP39 seed).
Args:
seed_bytes (bytes)     : Seed bytes
coin_conf (BipCoinConf): BipCoinConf object
Returns:
Bip44Base object: Bip44Base object
Raises:
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
aFromExtendedKey

Create a Bip44Base object from the specified extended key.
Args:
ex_key_str (str)       : Extended key string
coin_conf (BipCoinConf): BipCoinConf object
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip32KeyError: If the extended key is not valid
aFromPrivateKey

Create a Bip44Base object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey): Private key
coin_conf (BipCoinConf)        : BipCoinConf object
key_data (Bip32KeyData object) : Key data
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip32KeyError: If the key is not valid
aFromPublicKey

Create a Bip44Base object from the specified public key and derivation data.
If only the public key bytes are specified, the key will be considered an account key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
pub_key (bytes or IPublicKey)  : Public key
coin_conf (BipCoinConf)        : BipCoinConf object
key_data (Bip32KeyData object) : Key data
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip32KeyError: If the key is not valid
aDepth
aIsPublicOnly
aBip44Levels
aACCOUNT
aADDRESS_INDEX
aBip44DepthError
uDepth of the public-only Bip object (

u) is below account level or beyond address index level
uDepth of the Bip object (
u) is invalid or beyond address index level
m_bip32_obj
m_coin_conf

Construct class.
Args:
bip32_obj (Bip32Base object): Bip32Base object
coin_conf (BipCoinConf)     : BipCoinConf object
Returns:
Bip44DepthError: If the Bip32 object depth is not valid
aBip44PublicKey
aPublicKey

Return the public key.
Returns:
Bip44PublicKey object: Bip44PublicKey object
aBip44PrivateKey
aPrivateKey

Return the private key.
Returns:
Bip44PrivateKey object: Bip44PrivateKey object
Raises:
Bip32KeyError: If the Bip32 object is public-only

Return the BIP32 object.
Returns:
Bip32Base object: Bip32Base object

Get coin configuration.
Returns:
BipCoinConf object: BipCoinConf object

Get if it's public-only.
Returns:
bool: True if public-only, false otherwise
aToInt

Return the current level.
Returns:
Bip44Levels: Current level
uLevel is not an enumerative of Bip44Levels

Return if the current level is the specified one.
Args:
level (Bip44Levels): Level to be checked
Returns:
bool: True if it's the specified level, false otherwise
Raises:
TypeError: If the level index is not a Bip44Levels enum
aPurpose
aCoin
aDerivePath
aDefaultPath

Derive the default coin path and return a new Bip44Base object.
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If the current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aIsLevel
aMASTER
uCurrent depth (
u) is not suitable for deriving purpose
aChildKey

Derive a child key from the purpose and return a new Bip44Base object.
It shall be called from a child class.
Args:
purpose (int): Purpose
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If the current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aPURPOSE
u) is not suitable for deriving coin
aCoinIndex
aBip32KeyIndex
aHardenIndex

Derive a child key from the coin type specified at construction and return a new Bip44Base object.
It shall be called from a child class.
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If the current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aCOIN
u) is not suitable for deriving account

Derive a child key from the specified account index and return a new Bip44Base object.
It shall be called from a child class.
Args:
cc_idx (int): Account index
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If the current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aBip44Changes
uChange index is not an enumerative of Bip44Changes
u) is not suitable for deriving change
aIsPublicDerivationSupported

Derive a child key from the specified change type and return a new Bip44Base object.
It shall be called from a child class.
Args:
change_type (Bip44Changes): Change type, must a Bip44Changes enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If change type is not a Bip44Changes enum
Bip44DepthError: If the current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aCHANGE
u) is not suitable for deriving address

Derive a child key from the specified address index and return a new Bip44Base object.
It shall be called from a child class.
Args:
ddr_idx (int): Address index
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If the current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
uModule with BIP44 base class.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aABC
abstractmethod
aABC
abstractmethod
enum
T aIntEnum
unique
aIntEnum
unique
lru_cache
aUnion
ubip_utils.bip.bip32
T aBip32Base
aBip32KeyData
aBip32KeyIndex
aBip32Base
aBip32KeyData
ubip_utils.bip.bip44_base.bip44_base_ex
T aBip44DepthError
ubip_utils.bip.bip44_base.bip44_keys
T aBip44PrivateKey
aBip44PublicKey
ubip_utils.bip.conf.common
T aBipCoinConf
aBipCoins
aBipCoinConf
aBipCoins
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
