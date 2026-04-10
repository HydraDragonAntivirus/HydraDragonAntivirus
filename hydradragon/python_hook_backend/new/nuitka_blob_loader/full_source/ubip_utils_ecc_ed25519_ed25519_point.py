# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519.ed25519_point

uClass container for ed25519 point constants.
a__qualname__
a__annotations__
l a__prepare__
aEd25519Point
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uEd25519 point class.
bool
bytes
int
classmethod
return
uEd25519Point.FromBytes
wxwyaFromCoordinates
uEd25519Point.FromCoordinates
a__init__
uEd25519Point.__init__
staticmethod
aCurveType
uEd25519Point.CurveType
aCoordinateLength
uEd25519Point.CoordinateLength
uEd25519Point.UnderlyingObject
uEd25519Point.X
uEd25519Point.Y
aRaw
uEd25519Point.Raw
aRawEncoded
uEd25519Point.RawEncoded
uEd25519Point.RawDecoded
point
a__add__
uEd25519Point.__add__
a__radd__
uEd25519Point.__radd__
scalar
a__mul__
uEd25519Point.__mul__
a__rmul__
uEd25519Point.__rmul__
a__orig_bases__
ubip_utils\ecc\ed25519\ed25519_point.py
u<module bip_utils.ecc.ed25519.ed25519_point>
T a__class__
T acls
point_bytes
T acls
wxwyT aself
T aself
point
T aself
point_bytes
T aself
scalar

a__spec__
.bip_utils.ecc.ed25519.ed25519_utils
(
ed25519_lib
int_decode

Decode int from bytes.
Args:
int_bytes (bytes): Integer bytes
Returns:
int: Decoded integer
int_encode

Encode int to bytes.
Args:
int_val (int): Integer value
Returns:
bytes: Encoded integer
scalar_reduce

Convert the specified bytes to integer and return its lowest 32-bytes modulo ed25519-order.
Args:
scalar (bytes or int): Scalar
Returns:
bytes: Lowest 32-bytes modulo ed25519-order
uModule for ed25519 utility functions.
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
ubip_utils.ecc.ed25519.lib
T aed25519_lib
