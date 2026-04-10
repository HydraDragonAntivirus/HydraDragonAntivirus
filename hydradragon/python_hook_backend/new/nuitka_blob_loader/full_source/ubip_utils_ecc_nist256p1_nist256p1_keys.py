# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.nist256p1.nist256p1_keys

uNist256p1 public key class.
a__qualname__
a__annotations__
classmethod
key_bytes
bytes
return
aFromBytes
uNist256p1PublicKey.FromBytes
key_point
aFromPoint
uNist256p1PublicKey.FromPoint
key_obj
a__init__
uNist256p1PublicKey.__init__
staticmethod
aCurveType
uNist256p1PublicKey.CurveType
int
aCompressedLength
uNist256p1PublicKey.CompressedLength
aUncompressedLength
uNist256p1PublicKey.UncompressedLength
aUnderlyingObject
uNist256p1PublicKey.UnderlyingObject
aRawCompressed
uNist256p1PublicKey.RawCompressed
aRawUncompressed
uNist256p1PublicKey.RawUncompressed
uNist256p1PublicKey.Point
a__orig_bases__
aNist256p1PrivateKey
uNist256p1 private key class.
uNist256p1PrivateKey.FromBytes
uNist256p1PrivateKey.__init__
uNist256p1PrivateKey.CurveType
aLength
uNist256p1PrivateKey.Length
uNist256p1PrivateKey.UnderlyingObject
aRaw
uNist256p1PrivateKey.Raw
aPublicKey
uNist256p1PrivateKey.PublicKey
ubip_utils\ecc\nist256p1\nist256p1_keys.py
u<module bip_utils.ecc.nist256p1.nist256p1_keys>
T acls
key_bytes
ex
T acls
key_point
ex
T a__class__
T aself
T aself
key_obj

a__spec__
.bip_utils.ecc.nist256p1.nist256p1_point
z
ellipticcurve
aPointJacobi
from_bytes
curve_256
keys
aMalformedPointError
uInvalid point key bytes
aFromCoordinates
aBytesUtils
aToInteger
aEcdsaKeysConst
aPOINT_COORD_BYTE_LEN

Construct class from point bytes.
Args:
point_bytes (bytes): Point bytes
Returns:
IPoint: IPoint object
from_affine
aPoint

Construct class from point coordinates.
Args:
x (int): X coordinate of the point
y (int): Y coordinate of the point
Returns:
IPoint: IPoint object
m_point

Construct class from point object.
Args:
point_obj (ellipticcurve.PointJacobi): Point object
aEllipticCurveTypes
aNIST256P1

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type

Get the coordinate length.
Returns:
int: Coordinate key length

Get the underlying object.
Returns:
Any: Underlying object
wxu
Get point X coordinate.
Returns:
int: Point X coordinate
wyu
Get point Y coordinate.
Returns:
int: Point Y coordinate
aRawDecoded

Return the point raw bytes.
Returns:
DataBytes object: DataBytes object
aDataBytes
to_bytes
T acompressed
aIntegerUtils
aToBytes
d d u
Return the encoded point raw bytes.
Returns:
DataBytes object: DataBytes object

Return the decoded point raw bytes.
Returns:
DataBytes object: DataBytes object
aUnderlyingObject

Add point to another point.
Args:
point (IPoint object): IPoint object
Returns:
IPoint object: IPoint object

Multiply point by a scalar.
Args:
scalar (int): scalar
Returns:
IPoint object: IPoint object
uModule for nist256p1 point.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
ecdsa
T aellipticcurve
keys
uecdsa.ecdsa
T acurve_256
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
ubip_utils.ecc.ecdsa.ecdsa_keys
T aEcdsaKeysConst
ubip_utils.utils.misc
T aBytesUtils
aDataBytes
aIntegerUtils
a__prepare__
aNist256p1Point
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
