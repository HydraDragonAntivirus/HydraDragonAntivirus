# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.substrate.scale.substrate_scale_enc_uint

uSubstrate SCALE encoding class for unsigned integers.
a__qualname__
staticmethod
value
bytes_len
int
return
bytes
uSubstrateScaleUintEncoder._EncodeWithBytesLength
a__orig_bases__
aSubstrateScaleU8Encoder
uSubstrate SCALE encoding class for 8-bit unsigned integers.
classmethod
aEncode
uSubstrateScaleU8Encoder.Encode
aSubstrateScaleU16Encoder
uSubstrate SCALE encoding class for 16-bit unsigned integers.
uSubstrateScaleU16Encoder.Encode
aSubstrateScaleU32Encoder
uSubstrate SCALE encoding class for 32-bit unsigned integers.
uSubstrateScaleU32Encoder.Encode
aSubstrateScaleU64Encoder
uSubstrate SCALE encoding class for 64-bit unsigned integers.
uSubstrateScaleU64Encoder.Encode
aSubstrateScaleU128Encoder
uSubstrate SCALE encoding class for 128-bit unsigned integers.
uSubstrateScaleU128Encoder.Encode
aSubstrateScaleU256Encoder
uSubstrate SCALE encoding class for 256-bit unsigned integers.
uSubstrateScaleU256Encoder.Encode
ubip_utils\substrate\scale\substrate_scale_enc_uint.py
u<module bip_utils.substrate.scale.substrate_scale_enc_uint>
T acls
value
T a__class__
T avalue
bytes_len
max_val
a__spec__
.bip_utils.substrate.substrate
aSubstrateConst
aSEED_MIN_BYTE_LEN
uSeed length is too small, it shall be at least

u bytes
sr25519
pair_from_seed
aSubstratePath
aSubstrateConfGetter
aGetConfig
T apriv_key
pub_key
path
coin_conf

Create a Substrate object from the specified seed.
Args:
seed_bytes (bytes)        : Seed bytes
coin_type (SubstrateCoins): Coin type
Returns:
Substrate object: Substrate object
Raises:
TypeError: If coin_type is not of SubstrateCoins enum
ValueError: If the seed length is not valid
aFromSeed
aDerivePath

Create a Substrate object from the specified seed and path.
Args:
seed_bytes (bytes)                : Seed bytes
path (str or SubstratePath object): Path
coin_type (SubstrateCoins)        : Coin type
Returns:
Substrate object: Substrate object
Raises:
TypeError: If coin_type is not of SubstrateCoins enum
ValueError: If the seed length is not valid
SubstratePathError: If the path is not valid

Create a Substrate object from the specified private key.
Args:
priv_key (bytes or IPrivateKey): Private key
coin_type (SubstrateCoins)     : Coin type
Returns:
Substrate object: Substrate object
Raises:
TypeError: If coin_type is not of SubstrateCoins enum
SubstrateKeyError: If the key is not valid
aSubstrateCoins
uCoin is not an enumerative of SubstrateCoins

Create a Substrate object from the specified public key.
Args:
pub_key (bytes or IPublicKey): Public key
coin_type (SubstrateCoins)   : Coin type
Returns:
Substrate object: Substrate object
Raises:
TypeError: If coin_type is not of SubstrateCoins enum
SubstrateKeyError: If the key is not valid
aSubstratePrivateKey
aFromBytesOrKeyObject
m_priv_key
aSubstratePublicKey
aPublicKey
m_pub_key
aIPublicKey
T uPublic key shall be specified for public-only objects
self
m_path
coin_conf
m_coin_conf

Construct class.
Args:
priv_key (bytes or IPrivateKey)     : Private key, if None a public-only object will be created
pub_key (bytes or IPublicKey)       : Public key
path (SubstratePath object)         : Path
coin_conf (SubstrateCoinConf object): SubstrateCoinConf object
Raises:
SubstrateKeyError: If one of the key is not valid
aSubstratePathElem
aIsPublicOnly
a_Substrate__CkdPriv
a_Substrate__CkdPub

Create and return a child key of the current one with the specified path element.
Args:
path_elem (str or SubstratePathElem object): Path element
Returns:
Substrate object: Substrate object
Raises:
SubstrateKeyError: If the index results in invalid keys
aSubstratePathParser
aParse
substrate_obj
aChildKey

Derive children keys from the specified path.
Args:
path (str or SubstratePath object): Path
Returns:
Substrate object: Substrate object
Raises:
SubstratePathError: If the path is not valid
uConvert a private Substrate object into a public one.

Get if it's public-only.
Returns:
bool: True if public-only, false otherwise

Return coin configuration.
Returns:
SubstrateCoinConf object: SubstrateCoinConf object

Return path.
Returns:
SubstratePath object: SubstratePath object
aSubstrateKeyError
T uPublic-only deterministic keys have no private half

Return private key object.
Returns:
SubstratePrivateKey object: SubstratePrivateKey object
Raises:
SubstrateKeyError: If internal key is public-only

Return public key object.
Returns:
SubstratePublicKey object: SubstratePublicKey object
aChainCode
aRawCompressed
aToBytes
aRaw
aIsHard
hard_derive_keypair
c
derive_keypair
aSubstrate
aAddElem

Create a child key of the specified path element using private derivation.
Args:
path_elem (SubstratePathElem object): Path element
Returns:
Substrate object: Substrate object
T uPublic child derivation cannot be used to create a hardened child key
derive_pubkey

Create a child key of the specified index using public derivation.
Args:
path_elem (SubstratePathElem object): Path element
Returns:
Substrate object: Substrate object
Raises:
SubstrateKeyError: If the path element is hard
uModule for Substrate keys computation and derivation.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aOptional
aUnion
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
ubip_utils.substrate.conf
T aSubstrateCoinConf
aSubstrateCoins
aSubstrateConfGetter
aSubstrateCoinConf
ubip_utils.substrate.substrate_ex
T aSubstrateKeyError
ubip_utils.substrate.substrate_keys
T aSubstratePrivateKey
aSubstratePublicKey
ubip_utils.substrate.substrate_path
T aSubstratePath
aSubstratePathElem
aSubstratePathParser
