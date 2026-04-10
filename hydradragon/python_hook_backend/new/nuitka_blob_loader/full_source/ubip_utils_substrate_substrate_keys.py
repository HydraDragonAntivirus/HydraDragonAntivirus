# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.substrate.substrate_keys

uSubstrate public key class.
a__qualname__
a__annotations__
D apub_key
coin_conf
return
uUnion[bytes, IPublicKey]
aSubstrateCoinConf
aSubstratePublicKey
aFromBytesOrKeyObject
uSubstratePublicKey.FromBytesOrKeyObject
D akey_bytes
coin_conf
return
bytes
aSubstrateCoinConf
aSubstratePublicKey
uSubstratePublicKey.FromBytes
D apub_key
coin_conf
return
aIPublicKey
aSubstrateCoinConf
aNone
a__init__
uSubstratePublicKey.__init__
D areturn
aIPublicKey
aKeyObject
uSubstratePublicKey.KeyObject
D areturn
aDataBytes
uSubstratePublicKey.RawCompressed
uSubstratePublicKey.RawUncompressed
D areturn
str
aToAddress
uSubstratePublicKey.ToAddress
D akey_bytes
return
bytes
aIPublicKey
a__KeyFromBytes
uSubstratePublicKey.__KeyFromBytes
uSubstrate private key class.
aSubstratePrivateKey
D apriv_key
coin_conf
return
uUnion[bytes, IPrivateKey]
aSubstrateCoinConf
aSubstratePrivateKey
uSubstratePrivateKey.FromBytesOrKeyObject
D akey_bytes
coin_conf
return
bytes
aSubstrateCoinConf
aSubstratePrivateKey
uSubstratePrivateKey.FromBytes
D apriv_key
coin_conf
return
aIPrivateKey
aSubstrateCoinConf
aNone
uSubstratePrivateKey.__init__
D areturn
aIPrivateKey
uSubstratePrivateKey.KeyObject
uSubstratePrivateKey.Raw
D areturn
aSubstratePublicKey
uSubstratePrivateKey.PublicKey
D akey_bytes
return
bytes
aIPrivateKey
uSubstratePrivateKey.__KeyFromBytes
ubip_utils\substrate\substrate_keys.py
u<module bip_utils.substrate.substrate_keys>
T acls
key_bytes
coin_conf
T acls
priv_key
coin_conf
T acls
pub_key
coin_conf
T aself
T a__class__
T akey_bytes
ex
T aself
priv_key
coin_conf
T aself
pub_key
coin_conf

a__spec__
.bip_utils.substrate.substrate_path
?
a_SubstratePathElem__IsElemValid
aSubstratePathError
uInvalid path element (

w)areplace
T w/u
m_elem
startswith
aSubstratePathConst
aHARD_PATH_PREFIX
m_is_hard

Construct class.
Args:
elem (str): Path element
Raises:
SubstratePathError: If the path element is not valid

Get if the element is hard.
Returns:
bool: True if hard, false otherwise
aIsHard

Get if the element is soft.
Returns:
bool: True if soft, false otherwise
a_SubstratePathElem__ComputeChainCode

Return the chain code.
Returns:
bytes: Chain code
aSOFT_PATH_PREFIX

Get the path element as a string.
Returns:
str: Path element as a string
aToStr
isnumeric
bit_length
aSCALE_INT_ENCODERS
items
uInvalid integer bit length (
aSubstrateScaleBytesEncoder
aEncode
aENCODED_ELEM_MAX_BYTE_LEN
aBlake2b256
aQuickDigest
ljust
d

Compute chain code.
Returns:
bytes: Chain code
Raises:
SubstratePathError: If path is a number bigger than 256-bit
rfind
T w/l u
Get a path element is valid.
Args:
elem (str): Path element
Returns:
bool: True if valid, false otherwise
aSubstratePathElem
m_elems

Construct class.
Args:
elems (list, optional): Path elements (default: empty)
Raises:
SubstratePathError: If the path element is not valid
aSubstratePath

Return a new path object with the specified element added.
Args:
elem (str or SubstratePathElem): Path element
Returns:
SubstratePath object: SubstratePath object
Raises:
SubstratePathError: If the path element is not valid

Get the number of elements of the path.
Returns:
int: Number of elements

Get the path as a list of strings.
Returns:
list[str]: Path as a list of strings
aToList

Get the path as a string.
Returns:
str: Path as a string

Get the path as a string.
Returns:
str: Path as a list of integers

Get the specified element index.
Args:
idx (int): Element index
Returns:
SubstratePathElem object: SubstratePathElem object

Get the iterator to the current element.
Returns:
Iterator object: Iterator to the current element
self
a__iter__
uSubstratePath.__iter__
uInvalid path (
re
findall
aRE_PATH

Parse a path and return a SubstratePath object.
Args:
path (str): Path
Returns:
SubstratePath object: SubstratePath object
Raises:
SubstratePathError: If the path element is not valid
uModule for Substrate paths parsing and handling.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
lru_cache
aDict
aIterator
aList
aOptional
aSequence
aType
aUnion
ubip_utils.substrate.scale
T aSubstrateScaleBytesEncoder
aSubstrateScaleEncoderBase
aSubstrateScaleU8Encoder
aSubstrateScaleU16Encoder
aSubstrateScaleU32Encoder
aSubstrateScaleU64Encoder
aSubstrateScaleU128Encoder
aSubstrateScaleU256Encoder
aSubstrateScaleEncoderBase
aSubstrateScaleU8Encoder
aSubstrateScaleU16Encoder
aSubstrateScaleU32Encoder
aSubstrateScaleU64Encoder
aSubstrateScaleU128Encoder
aSubstrateScaleU256Encoder
ubip_utils.substrate.substrate_ex
T aSubstratePathError
ubip_utils.utils.crypto
T aBlake2b256
