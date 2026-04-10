# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.secp256k1.secp256k1_point_coincurve


Secp256k1 point class.
In coincurve library, all the point functions (e.g. add, multiply) are coded inside the
PublicKey class. For this reason, a PublicKey is used as underlying object.
a__qualname__
a__annotations__
classmethod
point_bytes
bytes
return
aFromBytes
uSecp256k1PointCoincurve.FromBytes
wxaint
wyaFromCoordinates
uSecp256k1PointCoincurve.FromCoordinates
point_obj
a__init__
uSecp256k1PointCoincurve.__init__
staticmethod
aCurveType
uSecp256k1PointCoincurve.CurveType
aCoordinateLength
uSecp256k1PointCoincurve.CoordinateLength
uSecp256k1PointCoincurve.UnderlyingObject
wXuSecp256k1PointCoincurve.X
wYuSecp256k1PointCoincurve.Y
aRaw
uSecp256k1PointCoincurve.Raw
aRawEncoded
uSecp256k1PointCoincurve.RawEncoded
uSecp256k1PointCoincurve.RawDecoded
a__add__
uSecp256k1PointCoincurve.__add__
a__radd__
uSecp256k1PointCoincurve.__radd__
scalar
a__mul__
uSecp256k1PointCoincurve.__mul__
a__rmul__
uSecp256k1PointCoincurve.__rmul__
a__orig_bases__
ubip_utils\ecc\secp256k1\secp256k1_point_coincurve.py
u<module bip_utils.ecc.secp256k1.secp256k1_point_coincurve>
T acls
point_bytes
T acls
wxwyaex
T aself
T a__class__
T aself
point
T aself
point_obj
T aself
scalar

a__spec__
.bip_utils.ecc.secp256k1.secp256k1_point_ecdsa
&
z
ellipticcurve
aPointJacobi
from_bytes
curve_secp256k1
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
aSECP256K1

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
uModule for secp256k1 point based on ecdsa library.
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
T acurve_secp256k1
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
aSecp256k1PointEcdsa
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
