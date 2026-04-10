# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip39.ibip39_seed_generator

uBIP39 seed generator interface.
a__qualname__
mnemonic
str
lang
return

Construct class.
Args:
mnemonic (str or Mnemonic object): Mnemonic
lang (Bip39Languages, optional)  : Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid
a__init__
uIBip39SeedGenerator.__init__
passphrase
bytes

Generate the seed using the specified passphrase.
Args:
passphrase (str, optional): Passphrase, empty if not specified
Returns:
bytes: Generated seed
aGenerate
uIBip39SeedGenerator.Generate
a__orig_bases__
ubip_utils\bip\bip39\ibip39_seed_generator.py
u<module bip_utils.bip.bip39.ibip39_seed_generator>
T aself
passphrase
T a__class__
T aself
mnemonic
lang

a__spec__
.bip_utils.bip.bip44.bip44
s
a_FromSeed
aBip44ConfGetter
aGetConfig

Create a Bip44Base object from the specified seed (e.g. BIP39 seed).
Args:
seed_bytes (bytes)  : Seed bytes
coin_type (BipCoins): Coin type, shall be a Bip44Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip44Coins enum
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
a_FromExtendedKey

Create a Bip44Base object from the specified extended key.
Args:
ex_key_str (str)    : Extended key string
coin_type (BipCoins): Coin type, shall be a Bip44Coins enum
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip44Coins enum
Bip32KeyError: If the extended key is not valid
a_FromPrivateKey

Create a Bip44Base object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey)         : Private key
coin_type (BipCoins)                    : Coin type, shall be a Bip44Coins enum
key_data (Bip32KeyData object, optional): Key data (default: all zeros)
Returns:
Bip44Base object: Bip44Base object
Raises:
TypeError: If coin type is not a Bip44Coins enum
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
aBip44Const
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

Module for BIP44 keys derivation.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
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
ubip_utils.bip.conf.bip44
T aBip44ConfGetter
ubip_utils.bip.conf.common
T aBipCoins
aBipCoins
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
