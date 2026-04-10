# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip84.bip84

uClass container for BIP84 constants.
a__qualname__
a__annotations__
uBIP-0084
aHardenIndex
T lTa__prepare__
aBip84
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

BIP84 class.
It allows master key generation and children keys derivation in according to BIP-0084.
classmethod
seed_bytes
bytes
coin_type
return
aFromSeed
uBip84.FromSeed
ex_key_str
str
aFromExtendedKey
uBip84.FromExtendedKey
priv_key
key_data
aFromPrivateKey
uBip84.FromPrivateKey
aACCOUNT
T adepth
pub_key
aFromPublicKey
uBip84.FromPublicKey
aPurpose
uBip84.Purpose
aCoin
uBip84.Coin
acc_idx
int
aAccount
uBip84.Account
change_type
aChange
uBip84.Change
addr_idx
aAddressIndex
uBip84.AddressIndex
staticmethod
aSpecName
uBip84.SpecName
a__orig_bases__
ubip_utils\bip\bip84\bip84.py
u<module bip_utils.bip.bip84.bip84>
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
.bip_utils.bip.bip84
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip84
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
bip84
T aNUITKA_PACKAGE_bip_utils_bip_bip84
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip84.bip84
T aBip84
aBip84
ubip_utils\bip\bip84\__init__.py
u<module bip_utils.bip.bip84>

a__spec__
.bip_utils.bip.bip86.bip86
s
a_FromSeed
aBip86ConfGetter
aGetConfig

Create a Bip44Base object from the specified seed (e.g. BIP39 seed).
Args:
seed_bytes (bytes)  : Seed bytes
coin_type (BipCoins): Coin type, shall be a Bip86Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip86Coins enum
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
a_FromExtendedKey

Create a Bip44Base object from the specified extended key.
Args:
ex_key_str (str)    : Extended key string
coin_type (BipCoins): Coin type, shall be a Bip86Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip86Coins enum
Bip32KeyError: If the extended key is not valid
a_FromPrivateKey

Create a Bip44Base object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey)         : Private key
coin_type (BipCoins)                    : Coin type, shall be a Bip86Coins enum
key_data (Bip32KeyData object, optional): Key data (default: all zeros)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip86Coins enum
Bip32KeyError: If the key is not valid
a_FromPublicKey

Create a Bip44Base object from the specified public key and derivation data.
If only the public key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
pub_key (bytes or IPublicKey)           : Public key
coin_type (BipCoins)                    : Coin type, shall be a Bip44Coins enum
key_data (Bip32KeyData object, optional): Key data (default: all zeros with account depth)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip44Coins enum
Bip32KeyError: If the key is not valid
a_PurposeGeneric
aBip86Const
aPURPOSE

Derive a child key from the purpose and return a new Bip44Base object.
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
a_CoinGeneric

Derive a child key from the coin type specified at construction and return a new Bip44Base object.
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
a_AccountGeneric

Derive a child key from the specified account index and return a new Bip44Base object.
Args:
cc_idx (int): Account index
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
a_ChangeGeneric

Derive a child key from the specified change type and return a new Bip44Base object.
Args:
change_type (Bip44Changes): Change type, must a Bip44Changes enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If change type is not a Bip44Changes enum
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
a_AddressIndexGeneric

Derive a child key from the specified address index and return a new Bip44Base object.
Args:
ddr_idx (int): Address index
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aSPEC_NAME

Get specification name.
Returns:
str: Specification name

Module for BIP86 keys derivation.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
ubip_utils.bip.bip32
T aBip32KeyData
aBip32KeyIndex
aBip32KeyData
aBip32KeyIndex
ubip_utils.bip.bip44_base
T aBip44Base
aBip44Changes
aBip44Levels
aBip44Base
aBip44Changes
aBip44Levels
ubip_utils.bip.conf.bip86
T aBip86ConfGetter
ubip_utils.bip.conf.common
T aBipCoins
aBipCoins
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
