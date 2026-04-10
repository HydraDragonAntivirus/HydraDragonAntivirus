# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip44_base.bip44_keys


BIP44 public key class.
It contains Bip32PublicKey and add the possibility to compute the address from the coin type.
a__qualname__
a__annotations__
pub_key
coin_conf
return
a__init__
uBip44PublicKey.__init__
aBip32Key
uBip44PublicKey.Bip32Key
D areturn
Ostr
uBip44PublicKey.ToExtended
uBip44PublicKey.ChainCode
uBip44PublicKey.RawCompressed
uBip44PublicKey.RawUncompressed
aToAddress
uBip44PublicKey.ToAddress

BIP44 private key class.
It contains Bip32PrivateKey and add the possibility to compute the WIF from the coin type.
aBip44PrivateKey
priv_key
uBip44PrivateKey.__init__
uBip44PrivateKey.Bip32Key
uBip44PrivateKey.ToExtended
uBip44PrivateKey.ChainCode
uBip44PrivateKey.Raw
uBip44PrivateKey.PublicKey
aCOMPRESSED
pub_key_mode
aToWif
uBip44PrivateKey.ToWif
ubip_utils\bip\bip44_base\bip44_keys.py
u<module bip_utils.bip.bip44_base.bip44_keys>
T aself
T a__class__
T aself
addr_cls
pub_key_obj
T aself
pub_key_mode
wif_net_ver
T aself
priv_key
coin_conf
T aself
pub_key
coin_conf
a__spec__
.bip_utils.bip.bip44_base
!
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip44_base
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
bip44_base
T aNUITKA_PACKAGE_bip_utils_bip_bip44_base
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip44_base.bip44_base
T aBip44Base
aBip44Changes
aBip44Levels
aBip44Base
aBip44Changes
aBip44Levels
ubip_utils.bip.bip44_base.bip44_base_ex
T aBip44DepthError
aBip44DepthError
ubip_utils.bip.bip44_base.bip44_keys
T aBip44PrivateKey
aBip44PublicKey
aBip44PrivateKey
aBip44PublicKey
ubip_utils\bip\bip44_base\__init__.py
u<module bip_utils.bip.bip44_base>

a__spec__
.bip_utils.bip.bip49.bip49
s
a_FromSeed
aBip49ConfGetter
aGetConfig

Create a Bip44Base object from the specified seed (e.g. BIP39 seed).
Args:
seed_bytes (bytes)  : Seed bytes
coin_type (BipCoins): Coin type, shall be a Bip49Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip49Coins enum
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
a_FromExtendedKey

Create a Bip44Base object from the specified extended key.
Args:
ex_key_str (str)    : Extended key string
coin_type (BipCoins): Coin type, shall be a Bip49Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip49Coins enum
Bip32KeyError: If the extended key is not valid
a_FromPrivateKey

Create a Bip44Base object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey)         : Private key
coin_type (BipCoins)                    : Coin type, shall be a Bip49Coins enum
key_data (Bip32KeyData object, optional): Key data (default: all zeros)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip49Coins enum
Bip32KeyError: If the key is not valid
a_FromPublicKey

Create a Bip44Base object from the specified public key and derivation data.
If only the public key bytes are specified, the key will be considered an account key with
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
aBip49Const
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

Module for BIP49 keys derivation.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
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
ubip_utils.bip.conf.bip49
T aBip49ConfGetter
ubip_utils.bip.conf.common
T aBipCoins
aBipCoins
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
