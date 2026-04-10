# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.byron.cardano_byron_legacy

uClass container for Cardano Byron legacy constants.
a__qualname__
a__annotations__
uaddress-hashing
str
l  aint
l u
Cardano Byron legacy class.
It allows master key generation, children keys derivation and addresses computation like the old Daedalus wallet.
Addresses are in the Ddz... format, which contains the encrypted derivation path.
aCardanoByronLegacy
D aseed_bytes
return
bytes
aCardanoByronLegacy
uCardanoByronLegacy.FromSeed
D abip32_obj
return
aBip32Base
aNone
a__init__
uCardanoByronLegacy.__init__
D areturn
aBip32Base
aBip32Object
uCardanoByronLegacy.Bip32Object
D areturn
bytes
uCardanoByronLegacy.HdPathKey
D aaddress
return
str
aBip32Path
aHdPathFromAddress
uCardanoByronLegacy.HdPathFromAddress
D areturn
aBip32PrivateKey
aMasterPrivateKey
uCardanoByronLegacy.MasterPrivateKey
D areturn
aBip32PublicKey
aMasterPublicKey
uCardanoByronLegacy.MasterPublicKey
D afirst_idx
second_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
aBip32PrivateKey
aGetPrivateKey
uCardanoByronLegacy.GetPrivateKey
D afirst_idx
second_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
aBip32PublicKey
uCardanoByronLegacy.GetPublicKey
D afirst_idx
second_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
str
aGetAddress
uCardanoByronLegacy.GetAddress
D afirst_idx
second_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
aBip32Base
a__DeriveKey
uCardanoByronLegacy.__DeriveKey
a__GetDerivationPath
uCardanoByronLegacy.__GetDerivationPath
ubip_utils\cardano\byron\cardano_byron_legacy.py
u<module bip_utils.cardano.byron.cardano_byron_legacy>
T aself
T a__class__
T acls
seed_bytes
T aself
first_idx
second_idx
pub_key
T aself
first_idx
second_idx
T aself
address
addr_dec_bytes
hd_path_dec_bytes
T afirst_idx
second_idx
T aself
bip32_obj
a__spec__
.bip_utils.cardano.byron
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ucardano\byron
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
byron
T aNUITKA_PACKAGE_bip_utils_cardano_byron
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.cardano.byron.cardano_byron_legacy
T aCardanoByronLegacy
aCardanoByronLegacy
ubip_utils\cardano\byron\__init__.py
u<module bip_utils.cardano.byron>

a__spec__
.bip_utils.cardano.cip1852.cip1852
s
a_FromSeed
aCip1852ConfGetter
aGetConfig

Create a Bip44Base object from the specified seed (e.g. BIP39 seed).
Args:
seed_bytes (bytes)  : Seed bytes
coin_type (BipCoins): Coin type, shall be a Cip1852Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Cip1852Coins enum
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
a_FromExtendedKey

Create a Bip44Base object from the specified extended key.
Args:
ex_key_str (str)    : Extended key string
coin_type (BipCoins): Coin type, shall be a Cip1852Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Cip1852Coins enum
Bip32KeyError: If the extended key is not valid
a_FromPrivateKey

Create a Bip44Base object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey)         : Private key
coin_type (BipCoins)                    : Coin type, shall be a Cip1852Coins enum
key_data (Bip32KeyData object, optional): Key data (default: all zeros)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Cip1852Coins enum
Bip32KeyError: If the key is not valid
a_FromPublicKey

Create a Bip44Base object from the specified public key and derivation data.
If only the public key bytes are specified, the key will be considered an account key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
pub_key (bytes or IPublicKey)           : Public key
coin_type (BipCoins)                    : Coin type, shall be a Cip1852Coins enum
key_data (Bip32KeyData object, optional): Key data (default: all zeros with account depth)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Cip1852Coins enum
Bip32KeyError: If the key is not valid
a_PurposeGeneric
aCip1852Const
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

Module for CIP-1852 keys derivation.
Reference: https://cips.cardano.org/cips/cip1852
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
ubip_utils.bip.conf.common
T aBipCoins
aBipCoins
ubip_utils.cardano.cip1852.conf
T aCip1852ConfGetter
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
