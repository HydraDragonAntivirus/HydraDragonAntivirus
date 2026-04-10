# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.common.ikeys


Interface for a generic elliptic curve public key.
Verify method is missing because not needed.
a__qualname__
classmethod
D akey_bytes
return
bytes
aIPublicKey

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key bytes are not valid
uIPublicKey.FromBytes
D akey_point
return
aIPoint
aIPublicKey

Construct class from key point.
Args:
key_point (IPoint object): Key point
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key point is not valid
uIPublicKey.FromPoint
staticmethod
D areturn
aEllipticCurveTypes

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aCurveType
uIPublicKey.CurveType
D akey_bytes
return
bytes
bool
aIsValidBytes
uIPublicKey.IsValidBytes
D akey_point
return
aIPoint
bool
aIsValidPoint
uIPublicKey.IsValidPoint
D areturn
int

Get the compressed key length.
Returns:
int: Compressed key length
aCompressedLength
uIPublicKey.CompressedLength

Get the uncompressed key length.
Returns:
int: Uncompressed key length
aUncompressedLength
uIPublicKey.UncompressedLength
D areturn
aAny

Get the underlying object.
Returns:
Any: Underlying object
aUnderlyingObject
uIPublicKey.UnderlyingObject
D areturn
aDataBytes

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
aRawCompressed
uIPublicKey.RawCompressed

Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
aRawUncompressed
uIPublicKey.RawUncompressed
D areturn
aIPoint

Return the public key point.
Returns:
IPoint object: IPoint object
aPoint
uIPublicKey.Point
a__orig_bases__
aIPrivateKey

Interface for a generic elliptic curve private key.
Sign method is missing because not needed.
D akey_bytes
return
bytes
aIPrivateKey

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey: IPrivateKey object
Raises:
ValueError: If key bytes are not valid
uIPrivateKey.FromBytes
uIPrivateKey.CurveType
uIPrivateKey.IsValidBytes

Get the key length.
Returns:
int: Key length
aLength
uIPrivateKey.Length
uIPrivateKey.UnderlyingObject

Return raw private key.
Returns:
DataBytes object: DataBytes object
aRaw
uIPrivateKey.Raw
D areturn
aIPublicKey

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
aPublicKey
uIPrivateKey.PublicKey
ubip_utils\ecc\common\ikeys.py
u<module bip_utils.ecc.common.ikeys>
T acls
key_bytes
T acls
key_point
T a__class__
T aself

a__spec__
.bip_utils.ecc.common.ipoint
a
def Y
uModule with interfaces for point classes.
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
aAny
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
aEllipticCurveTypes
ubip_utils.utils.misc
T aDataBytes
aDataBytes
a__prepare__
aIPoint
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
