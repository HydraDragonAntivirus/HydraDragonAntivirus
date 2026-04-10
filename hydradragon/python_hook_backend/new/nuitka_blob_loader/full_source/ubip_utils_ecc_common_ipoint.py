# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.common.ipoint

uInterface for a generic elliptic curve point.
a__qualname__
classmethod
D apoint_bytes
return
bytes
aIPoint

Construct class from point bytes.
Args:
point_bytes (bytes): Point bytes
Returns:
IPoint: IPoint object
aFromBytes
uIPoint.FromBytes
D wxwyareturn
int
paIPoint

Construct class from point coordinates.
Args:
x (int): X coordinate of the point
y (int): Y coordinate of the point
Returns:
IPoint: IPoint object
aFromCoordinates
uIPoint.FromCoordinates
staticmethod
D areturn
aEllipticCurveTypes

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aCurveType
uIPoint.CurveType
D areturn
int

Get the coordinate length.
Returns:
int: Coordinate key length
aCoordinateLength
uIPoint.CoordinateLength
D areturn
aAny

Get the underlying object.
Returns:
Any: Underlying object
aUnderlyingObject
uIPoint.UnderlyingObject

Return X coordinate of the point.
Returns:
int: X coordinate of the point
wXuIPoint.X

Return Y coordinate of the point.
Returns:
int: Y coordinate of the point
wYuIPoint.Y
D areturn
aDataBytes

Return the point raw bytes.
Returns:
DataBytes object: DataBytes object
aRaw
uIPoint.Raw

Return the encoded point raw bytes.
Returns:
DataBytes object: DataBytes object
aRawEncoded
uIPoint.RawEncoded

Return the decoded point raw bytes.
Returns:
DataBytes object: DataBytes object
aRawDecoded
uIPoint.RawDecoded
D apoint
return
aIPoint
pu
Add point to another point.
Args:
point (IPoint object): IPoint object
Returns:
IPoint object: IPoint object
a__add__
uIPoint.__add__
a__radd__
uIPoint.__radd__
D ascalar
return
int
aIPoint

Multiply point by a scalar.
Args:
scalar (int): scalar
Returns:
IPoint object: IPoint object
a__mul__
uIPoint.__mul__
a__rmul__
uIPoint.__rmul__
a__orig_bases__
ubip_utils\ecc\common\ipoint.py
u<module bip_utils.ecc.common.ipoint>
T acls
point_bytes
T acls
wxwyT a__class__
T aself
T aself
point
T aself
scalar

a__spec__
.bip_utils.ecc.conf
uModule for ECC configuration.
a__doc__
a__file__
origin
has_location
a__cached__
