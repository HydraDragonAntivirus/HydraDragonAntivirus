# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bech32.segwit_bech32

uClass container for Segwit Bech32 constants.
a__qualname__
a__annotations__
l l(l T l l T Oint
pa__prepare__
aSegwitBech32Encoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Segwit Bech32 encoder class.
It provides methods for encoding to Segwit Bech32 format.
classmethod
hrp
str
wit_ver
int
wit_prog
bytes
return
aEncode
uSegwitBech32Encoder.Encode
staticmethod
data
a_ComputeChecksum
uSegwitBech32Encoder._ComputeChecksum
a__orig_bases__
aSegwitBech32Decoder

Segwit Bech32 decoder class.
It provides methods for decoding Segwit Bech32 format.
addr
aDecode
uSegwitBech32Decoder.Decode
bool
a_VerifyChecksum
uSegwitBech32Decoder._VerifyChecksum
ubip_utils\bech32\segwit_bech32.py
u<module bip_utils.bech32.segwit_bech32>
T acls
hrp
addr
hrp_got
data
conv_data
wit_ver
T acls
hrp
wit_ver
wit_prog
T a__class__
T ahrp
data
encoding
a__spec__
.bip_utils.bip.bip32.base.bip32_base
6
a_MasterKeyGenerator
aGenerateFromSeed
aBip32KeyData
T achain_code
a_DefaultKeyNetVersion
T apriv_key
pub_key
key_data
key_net_ver

Create a Bip32 object from the specified seed (e.g. BIP39 seed).
Args:
seed_bytes (bytes)                                : Seed bytes
key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
(default: specific class key net version)
Returns:
Bip32Base object: Bip32Base object
Raises:
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
aFromSeed
aDerivePath

Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.
Args:
seed_bytes (bytes)                                : Seed bytes
path (str or Bip32Path object)                    : Path
key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
(default: specific class key net version)
Returns:
Bip32Base object: Bip32Base object
Raises:
ValueError: If the seed length is too short
Bip32PathError: If the path is not valid
Bip32KeyError: If the seed is not suitable for master key generation
aBip32KeyDeserializer
aDeserializeKey
aKeyBytes
aKeyData
aIsPublic
aDepth
aParentFingerPrint
aIsMasterKey
aBip32KeyError
uInvalid extended master key (wrong fingerprint:
aToHex

w)aIndex
uInvalid extended master key (wrong child index:
aToInt

Create a Bip32 object from the specified extended key.
Args:
ex_key_str (str)                                  : Extended key string
key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
(default: specific class key net version)
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the key is not valid

Create a Bip32 object from the specified private key and derivation data.
If only the private key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
priv_key (bytes or IPrivateKey)                   : Private key
key_data (Bip32KeyData object, optional)          : Key data (default: all zeros)
key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
(default: specific class key net version)
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the key is not valid

Create a Bip32 object from the specified public key and derivation data.
If only the public key bytes are specified, the key will be considered a master key with
the chain code set to zero, since there is no way to recover the key derivation data.
Args:
pub_key (bytes, IPoint or IPublicKey)             : Public key
key_data (Bip32KeyData object, optional)          : Key data (default: all zeros)
key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
(default: specific class key net version)
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the key is not valid
aCurve
aPrivateKeyClass
uInvalid private key class, a
aName
u key is required
aBip32PrivateKey
aFromBytesOrKeyObject
aCurveType
m_priv_key
aPublicKey
m_pub_key
aPointClass
aPublicKeyClass
uInvalid public key class, a
u key or point is required
aBip32PublicKey

Construct class.
Args:
priv_key (bytes or IPrivateKey)         : Private key (None for a public-only object)
pub_key (bytes, IPoint or IPublicKey)   : Public key (only needed for a public-only object)
If priv_key is not None, it'll be discarded
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object
Raises:
Bip32KeyError: If the constructed key is not valid
a_Bip32Base__GetIndex
aIsPublicOnly
a_Bip32Base__ValidateAndCkdPriv
a_Bip32Base__ValidateAndCkdPub

Create and return a child key of the current one with the specified index.
The index shall be hardened using HardenIndex method to use the private derivation algorithm.
Args:
index (int or Bip32KeyIndex object): Index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the index results in an invalid key
a_Bip32Base__GetPath
aIsAbsolute
uAbsolute paths can only be derived from a master key, not child ones
bip32_obj
aChildKey

Derive children keys from the specified path.
Args:
path (str or Bip32Path object): Path
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the index results in an invalid key
Bip32PathError: If the path is not valid
ValueError: If the path is a master path and the key is a child key
uConvert the object into a public one.

Get if it's public-only.
Returns:
bool: True if public-only, false otherwise
T uPublic-only deterministic keys have no private half

Return private key object.
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
Raises:
Bip32KeyError: If internal key is public-only

Return public key object.
Returns:
Bip32PublicKey object: Bip32PublicKey object
aKeyNetVersions

Get key net versions.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
aData

Get current depth.
Returns:
Bip32Depth object: Current depth

Get current index.
Returns:
Bip32KeyIndex object: Current index
aChainCode

Get chain code.
Returns:
Bip32ChainCode: Chain code
aFingerPrint

Get public key fingerprint.
Returns:
Bip32FingerPrint object: Public key fingerprint bytes

Get parent fingerprint.
Returns:
Bip32FingerPrint object: Parent fingerprint bytes
aEllipticCurveGetter
aFromType

Return the elliptic curve.
Returns:
EllipticCurve object: EllipticCurve object
a_KeyDerivator
aIsPublicDerivationSupported

Get if public derivation is supported.
Returns:
bool: True if supported, false otherwise.
a_Bip32Base__CkdPriv

Check the key index validity and create a child key with the specified index using private derivation.
Args:
index (Bip32KeyIndex object): Key index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the index results in an invalid key
aIsHardened
T uPublic child derivation cannot be used to create a hardened child key
a_Bip32Base__CkdPub

Check the key index validity and create a child key with the specified index using public derivation.
Args:
index (Bip32KeyIndex object): Key index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the index results in an invalid key
aCkdPriv
aIncrease
T achain_code
depth
index
parent_fprint

Derive a child key with the specified index using private derivation.
Args:
index (Bip32KeyIndex object): Key index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the index results in an invalid key
aCkdPub

Derive a child key with the specified index using public derivation.
Args:
index (Bip32KeyIndex object): Key index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the index results in an invalid key
aBip32KeyIndex

Get index object.
Args:
index (int or Bip32KeyIndex): Index
Returns:
Bip32KeyIndex object: Bip32KeyIndex object
aBip32PathParser
aParse

Get path object.
Args:
path (str or Bip32Path): Path
Returns:
Bip32Path object: Bip32Path object
uModule with BIP32 base class.
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
aOptional
aType
aUnion
ubip_utils.bip.bip32.base.ibip32_key_derivator
T aIBip32KeyDerivator
aIBip32KeyDerivator
ubip_utils.bip.bip32.base.ibip32_mst_key_generator
T aIBip32MstKeyGenerator
aIBip32MstKeyGenerator
ubip_utils.bip.bip32.bip32_ex
T aBip32KeyError
ubip_utils.bip.bip32.bip32_key_data
T aBip32ChainCode
aBip32Depth
aBip32FingerPrint
aBip32KeyData
aBip32KeyIndex
aBip32ChainCode
aBip32Depth
aBip32FingerPrint
ubip_utils.bip.bip32.bip32_key_net_ver
T aBip32KeyNetVersions
aBip32KeyNetVersions
ubip_utils.bip.bip32.bip32_key_ser
T aBip32KeyDeserializer
ubip_utils.bip.bip32.bip32_keys
T aBip32PrivateKey
aBip32PublicKey
ubip_utils.bip.bip32.bip32_path
T aBip32Path
aBip32PathParser
aBip32Path
ubip_utils.ecc
T aEllipticCurve
aEllipticCurveGetter
aEllipticCurveTypes
aIPoint
aIPrivateKey
aIPublicKey
aEllipticCurve
aEllipticCurveTypes
aIPoint
aIPrivateKey
aIPublicKey
a__prepare__
aBip32Base
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
