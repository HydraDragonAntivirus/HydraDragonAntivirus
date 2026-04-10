# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.bip32_keys

uBase class for a generic BIP32 key.
a__qualname__
a__annotations__
D akey_data
key_net_ver
curve_type
return
aBip32KeyData
aBip32KeyNetVersions
aEllipticCurveTypes
aNone
u_Bip32KeyBase.__init__
D areturn
aEllipticCurve
aCurve
u_Bip32KeyBase.Curve
D areturn
aEllipticCurveTypes
u_Bip32KeyBase.CurveType
D areturn
aBip32KeyData
u_Bip32KeyBase.Data
D areturn
aBip32ChainCode
u_Bip32KeyBase.ChainCode
D areturn
aBip32KeyNetVersions
aKeyNetVersions
u_Bip32KeyBase.KeyNetVersions
D areturn
str
aToExtended
u_Bip32KeyBase.ToExtended
a__orig_bases__

BIP32 public key class.
It represents a public key used by BIP32 with all the related data (e.g. depth, chain code, etc...).
classmethod
D apub_key
key_data
key_net_ver
curve_type
return
uUnion[bytes, IPoint, IPublicKey]
aBip32KeyData
aBip32KeyNetVersions
aEllipticCurveTypes
aBip32PublicKey
aFromBytesOrKeyObject
uBip32PublicKey.FromBytesOrKeyObject
D akey_bytes
key_data
key_net_ver
curve_type
return
bytes
aBip32KeyData
aBip32KeyNetVersions
aEllipticCurveTypes
aBip32PublicKey
uBip32PublicKey.FromBytes
D akey_point
key_data
key_net_ver
return
aIPoint
aBip32KeyData
aBip32KeyNetVersions
aBip32PublicKey
uBip32PublicKey.FromPoint
D apub_key
key_data
key_net_ver
return
aIPublicKey
aBip32KeyData
aBip32KeyNetVersions
aNone
uBip32PublicKey.__init__
D areturn
aIPublicKey
aKeyObject
uBip32PublicKey.KeyObject
D areturn
aDataBytes
uBip32PublicKey.RawCompressed
uBip32PublicKey.RawUncompressed
D areturn
aIPoint
uBip32PublicKey.Point
D areturn
aBip32FingerPrint
aFingerPrint
uBip32PublicKey.FingerPrint
D areturn
bytes
uBip32PublicKey.KeyIdentifier
uBip32PublicKey.ToExtended
staticmethod
D akey_bytes
curve_type
return
bytes
aEllipticCurveTypes
aIPublicKey
a__KeyFromBytes
uBip32PublicKey.__KeyFromBytes
D akey_point
return
aIPoint
aIPublicKey
a__KeyFromPoint
uBip32PublicKey.__KeyFromPoint
aBip32PrivateKey

BIP32 private key class.
It represents a private key used by BIP32 with all the related data (e.g. depth, chain code, etc...).
D apriv_key
key_data
key_net_ver
curve_type
return
uUnion[bytes, IPrivateKey]
aBip32KeyData
aBip32KeyNetVersions
aEllipticCurveTypes
aBip32PrivateKey
uBip32PrivateKey.FromBytesOrKeyObject
D akey_bytes
key_data
key_net_ver
curve_type
return
bytes
aBip32KeyData
aBip32KeyNetVersions
aEllipticCurveTypes
aBip32PrivateKey
uBip32PrivateKey.FromBytes
D apriv_key
key_data
key_net_ver
return
aIPrivateKey
aBip32KeyData
aBip32KeyNetVersions
aNone
uBip32PrivateKey.__init__
D areturn
aIPrivateKey
uBip32PrivateKey.KeyObject
uBip32PrivateKey.Raw
D areturn
aBip32PublicKey
uBip32PrivateKey.PublicKey
uBip32PrivateKey.ToExtended
D akey_bytes
curve_type
return
bytes
aEllipticCurveTypes
aIPrivateKey
uBip32PrivateKey.__KeyFromBytes
ubip_utils\bip\bip32\bip32_keys.py
u<module bip_utils.bip.bip32.bip32_keys>
T a__class__
T aself
T acls
key_bytes
key_data
key_net_ver
curve_type
T acls
priv_key
key_data
key_net_ver
curve_type
T acls
pub_key
key_data
key_net_ver
curve_type
T acls
key_point
key_data
key_net_ver
T akey_bytes
curve_type
curve
ex
T akey_point
curve
ex
T aself
priv_key
key_data
key_net_ver
a__class__
T aself
pub_key
key_data
key_net_ver
a__class__
T aself
key_data
key_net_ver
curve_type

a__spec__
.bip_utils.bip.bip32.bip32_path
;
z
aBip32KeyIndex
m_elems
aBip32PathError
T uThe path contains some invalid key indexes
m_is_absolute

Construct class.
Args:
elems (list, optional)      : Path elements (default: empty)
is_absolute (bool, optional): True if path is an absolute one, false otherwise (default: True)
aBip32Path

Return a new path object with the specified element added.
Args:
elem (str or Bip32KeyIndex): Path element
Returns:
Bip32Path object: Bip32Path object
Raises:
Bip32PathError: If the path element is not valid

Get if absolute path.
Returns:
bool: True if absolute path, false otherwise

Get the number of elements of the path.
Returns:
int: Number of elements

Get the path as a list of integers.
Returns:
list[int]: Path as a list of integers

aBip32PathConst
aMASTER_CHAR
w/aIsHardened
path_str
aToInt
aUnhardenIndex
u'/
:nq nu
Get the path as a string.
Returns:
str: Path as a string
aToStr

Get the specified element index.
Args:
idx (int): Element index
Returns:
Bip32KeyIndex object: Bip32KeyIndex object

Get the iterator to the current element.
Returns:
Iterator object: Iterator to the current element
self
a__iter__
uBip32Path.__iter__
endswith
T w/aBip32PathParser
a_Bip32PathParser__ParseElements
path
split

Parse a path and return a Bip32Path object.
Args:
path (str): Path
Returns:
Bip32Path object: Bip32Path object
Raises:
Bip32PathError: If the path is not valid
:l nna_Bip32PathParser__ParseElem
path_elems

Parse path elements and return a Bip32Path object.
Args:
path_elems (list[str]): Path elements
Returns:
Bip32Path object: Bip32Path object
Raises:
Bip32PathError: If the path is not valid
strip
aHARDENED_CHARS
path_elem
isnumeric
uInvalid path element (
w)aHardenIndex

Parse path element and get the correspondent index.
Args:
path_elem (str): Path element
Returns:
int: Index of the element, None if the element is not a valid index
Raises:
Bip32PathError: If the path is not valid
uModule for BIP32 paths parsing and handling.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aIterator
aList
aOptional
aSequence
aTuple
aUnion
ubip_utils.bip.bip32.bip32_ex
T aBip32PathError
ubip_utils.bip.bip32.bip32_key_data
T aBip32KeyIndex
