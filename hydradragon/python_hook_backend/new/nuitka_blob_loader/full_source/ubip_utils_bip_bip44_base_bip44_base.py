# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip44_base.bip44_base

uEnumerative for BIP44 changes.
a__qualname__
aCHAIN_EXT
aCHAIN_INT
a__orig_bases__
uEnumerative for BIP44 levels.
l l l l aBip44Base

BIP44 base class.
It allows coin, account, chain and address keys generation in according to BIP44 or its extensions.
The class is meant to be derived by classes implementing BIP44 or its extensions.
a__annotations__
classmethod
D aseed_bytes
coin_conf
return
bytes
aBipCoinConf
aBip44Base
a_FromSeed
uBip44Base._FromSeed
D aex_key_str
coin_conf
return
str
aBipCoinConf
aBip44Base
a_FromExtendedKey
uBip44Base._FromExtendedKey
D apriv_key
coin_conf
key_data
return
uUnion[bytes, IPrivateKey]
aBipCoinConf
aBip32KeyData
aBip44Base
a_FromPrivateKey
uBip44Base._FromPrivateKey
D apub_key
coin_conf
key_data
return
uUnion[bytes, IPublicKey]
aBipCoinConf
aBip32KeyData
aBip44Base
a_FromPublicKey
uBip44Base._FromPublicKey
D abip32_obj
coin_conf
return
aBip32Base
aBipCoinConf
aNone
a__init__
uBip44Base.__init__
D areturn
aBip44PublicKey
uBip44Base.PublicKey
D areturn
aBip44PrivateKey
uBip44Base.PrivateKey
D areturn
aBip32Base
aBip32Object
uBip44Base.Bip32Object
D areturn
aBipCoinConf
aCoinConf
uBip44Base.CoinConf
D areturn
bool
uBip44Base.IsPublicOnly
D areturn
aBip44Levels
aLevel
uBip44Base.Level
D alevel
return
aBip44Levels
bool
uBip44Base.IsLevel
D areturn
aBip44Base
aDeriveDefaultPath
uBip44Base.DeriveDefaultPath
D apurpose
return
int
aBip44Base
a_PurposeGeneric
uBip44Base._PurposeGeneric
a_CoinGeneric
uBip44Base._CoinGeneric
D aacc_idx
return
int
aBip44Base
a_AccountGeneric
uBip44Base._AccountGeneric
D achange_type
return
aBip44Changes
aBip44Base
a_ChangeGeneric
uBip44Base._ChangeGeneric
D aaddr_idx
return
int
aBip44Base
a_AddressIndexGeneric
uBip44Base._AddressIndexGeneric
D aseed_bytes
coin_type
return
bytes
aBipCoins
aBip44Base

Create a Bip44Base object from the specified seed (e.g. BIP39 seed).
The test net flag is automatically set when the coin is derived. However, if you want to get the correct master
or purpose keys, you have to specify here if it's a test net.
Args:
seed_bytes (bytes)  : Seed bytes
coin_type (BipCoins): Coin type (the type depends on the specific child class)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not of the correct type
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
uBip44Base.FromSeed
D aex_key_str
coin_type
return
str
aBipCoins
aBip44Base

Create a Bip44Base object from the specified extended key.
Args:
ex_key_str (str)    : Extended key string
coin_type (BipCoins): Coin type (the type depends on the specific child class)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not of the correct type
Bip32KeyError: If the extended key is not valid
uBip44Base.FromExtendedKey
D apriv_key
coin_type
key_data
return
uUnion[bytes, IPrivateKey]
aBipCoins
aBip32KeyData
aBip44Base

Create a Bip44Base object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey): Private key
coin_type (BipCoins)           : Coin type, shall be a Bip44Coins enum
key_data (Bip32KeyData object) : Key data
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip44Coins enum
Bip32KeyError: If the key is not valid
uBip44Base.FromPrivateKey
D apub_key
coin_type
key_data
return
uUnion[bytes, IPublicKey]
aBipCoins
aBip32KeyData
aBip44Base

Create a Bip44Base object from the specified public key and derivation data.
If only the public key bytes are specified, the key will be considered an account key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
pub_key (bytes or IPublicKey) : Public key
coin_type (BipCoins)          : Coin type, shall be a Bip44Coins enum
key_data (Bip32KeyData object): Key data
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip44Coins enum
Bip32KeyError: If the key is not valid
uBip44Base.FromPublicKey

Derive a child key from the purpose and return a new Bip44Base object.
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
uBip44Base.Purpose

Derive a child key from the coin type specified at construction and return a new Bip44Base object.
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
uBip44Base.Coin

Derive a child key from the specified account index and return a new Bip44Base object.
Args:
cc_idx (int): Account index
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aAccount
uBip44Base.Account

Derive a child key from the specified change type and return a new Bip44Base object.
Args:
change_type (Bip44Changes): Change type, must a Bip44Changes enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If change type is not a Bip44Changes enum
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aChange
uBip44Base.Change

Derive a child key from the specified address index and return a new Bip44Base object.
Args:
ddr_idx (int): Address index
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aAddressIndex
uBip44Base.AddressIndex
staticmethod
D areturn
str

Get specification name.
Returns:
str: Specification name
aSpecName
uBip44Base.SpecName
ubip_utils\bip\bip44_base\bip44_base.py
u<module bip_utils.bip.bip44_base.bip44_base>
T aself
acc_idx
T aself
addr_idx
T aself
T a__class__
T aself
change_type
T aself
bip_obj
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
T aself
level
T aself
change_type
change_idx
T aself
coin_idx
T acls
ex_key_str
coin_conf
bip32_cls
T acls
priv_key
coin_conf
key_data
bip32_cls
T acls
pub_key
coin_conf
key_data
bip32_cls
T acls
seed_bytes
coin_conf
bip32_cls
T aself
purpose
T aself
bip32_obj
coin_conf
depth
a__spec__
.bip_utils.bip.bip44_base.bip44_base_ex
uModule for BIP44 exceptions.
a__doc__
a__file__
origin
has_location
a__cached__
T EException
a__prepare__
aBip44DepthError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
