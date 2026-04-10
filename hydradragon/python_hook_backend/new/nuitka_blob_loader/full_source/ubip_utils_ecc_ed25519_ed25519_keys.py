# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519.ed25519_keys

uClass container for ed25519 keys constants.
a__qualname__
a__annotations__
d
l a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uEd25519 public key class.
classmethod
bytes
return
uEd25519PublicKey.FromBytes
key_point
aFromPoint
uEd25519PublicKey.FromPoint
key_obj
a__init__
uEd25519PublicKey.__init__
staticmethod
aCurveType
uEd25519PublicKey.CurveType
int
uEd25519PublicKey.CompressedLength
aUncompressedLength
uEd25519PublicKey.UncompressedLength
aUnderlyingObject
uEd25519PublicKey.UnderlyingObject
uEd25519PublicKey.RawCompressed
aRawUncompressed
uEd25519PublicKey.RawUncompressed
aPoint
uEd25519PublicKey.Point
a__orig_bases__
aEd25519PrivateKey
uEd25519 private key class.
uEd25519PrivateKey.FromBytes
uEd25519PrivateKey.__init__
uEd25519PrivateKey.CurveType
aLength
uEd25519PrivateKey.Length
uEd25519PrivateKey.UnderlyingObject
aRaw
uEd25519PrivateKey.Raw
aPublicKey
uEd25519PrivateKey.PublicKey
ubip_utils\ecc\ed25519\ed25519_keys.py
u<module bip_utils.ecc.ed25519.ed25519_keys>
T a__class__
T acls
key_bytes
ex
T acls
key_point
T aself
T aself
key_obj

a__spec__
.bip_utils.ecc.ed25519.ed25519_point
]
w
ed25519_lib
point_is_on_curve
uInvalid point bytes
point_is_decoded_bytes
point_encode
point_bytes_to_coord
point_bytes

Construct class from point bytes.
Args:
point_bytes (bytes): Point bytes
Returns:
IPoint: IPoint object
aFromBytes
point_coord_to_bytes

Construct class from point coordinates.
Args:
x (int): X coordinate of the point
y (int): Y coordinate of the point
Returns:
IPoint: IPoint object
point_is_encoded_bytes
m_enc_bytes
point_is_generator
m_is_generator
T nnam_x
m_y

Construct class from point object.
Args:
point_bytes (bytes): Point bytes
aEllipticCurveTypes
aED25519

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aEd25519PointConst
aPOINT_COORD_BYTE_LEN

Get the coordinate length.
Returns:
int: Coordinate key length

Get the underlying object.
Returns:
Any: Underlying object

Get point X coordinate.
Returns:
int: Point X coordinate

Get point Y coordinate.
Returns:
int: Point Y coordinate
aRawDecoded

Return the point encoded to raw bytes.
Returns:
DataBytes object: DataBytes object
aDataBytes

Return the encoded point raw bytes.
Returns:
DataBytes object: DataBytes object
int_encode
wXwYu
Return the decoded point raw bytes.
Returns:
DataBytes object: DataBytes object
point_add
aUnderlyingObject

Add point to another point.
Args:
point (IPoint object): IPoint object
Returns:
IPoint object: IPoint object
point_scalar_mul_base
point_scalar_mul

Multiply point by a scalar.
Args:
scalar (int): scalar
Returns:
IPoint object: IPoint object
uModule for ed25519 point.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aOptional
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
ubip_utils.ecc.ed25519.lib
T aed25519_lib
ubip_utils.utils.misc
T aDataBytes
