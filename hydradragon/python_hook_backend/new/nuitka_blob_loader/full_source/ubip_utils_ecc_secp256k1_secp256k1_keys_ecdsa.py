# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.secp256k1.secp256k1_keys_ecdsa

uSecp256k1 public key class.
a__qualname__
a__annotations__
classmethod
key_bytes
bytes
return
aFromBytes
uSecp256k1PublicKeyEcdsa.FromBytes
key_point
aFromPoint
uSecp256k1PublicKeyEcdsa.FromPoint
key_obj
a__init__
uSecp256k1PublicKeyEcdsa.__init__
staticmethod
aCurveType
uSecp256k1PublicKeyEcdsa.CurveType
int
aCompressedLength
uSecp256k1PublicKeyEcdsa.CompressedLength
aUncompressedLength
uSecp256k1PublicKeyEcdsa.UncompressedLength
aUnderlyingObject
uSecp256k1PublicKeyEcdsa.UnderlyingObject
aRawCompressed
uSecp256k1PublicKeyEcdsa.RawCompressed
aRawUncompressed
uSecp256k1PublicKeyEcdsa.RawUncompressed
uSecp256k1PublicKeyEcdsa.Point
a__orig_bases__
aSecp256k1PrivateKeyEcdsa
uSecp256k1 private key class.
uSecp256k1PrivateKeyEcdsa.FromBytes
uSecp256k1PrivateKeyEcdsa.__init__
uSecp256k1PrivateKeyEcdsa.CurveType
aLength
uSecp256k1PrivateKeyEcdsa.Length
uSecp256k1PrivateKeyEcdsa.UnderlyingObject
aRaw
uSecp256k1PrivateKeyEcdsa.Raw
aPublicKey
uSecp256k1PrivateKeyEcdsa.PublicKey
ubip_utils\ecc\secp256k1\secp256k1_keys_ecdsa.py
u<module bip_utils.ecc.secp256k1.secp256k1_keys_ecdsa>
T acls
key_bytes
ex
T acls
key_point
ex
T aself
T a__class__
T aself
key_obj

a__spec__
.bip_utils.ecc.secp256k1.secp256k1_point_coincurve
s
aEcdsaKeysConst
aPUB_KEY_UNCOMPRESSED_BYTE_LEN
coincurve
aPublicKey
aPUB_KEY_UNCOMPRESSED_PREFIX
aPUB_KEY_COMPRESSED_BYTE_LEN
uInvalid point bytes

Construct class from point bytes.
Args:
point_bytes (bytes): Point bytes
Returns:
IPoint: IPoint object
from_point
uInvalid point coordinates

Construct class from point coordinates.
Args:
x (int): X coordinate of the point
y (int): Y coordinate of the point
Returns:
IPoint: IPoint object
m_pub_key

Construct class from point object.
Args:
point_obj (coincurve.PublicKey): Point object
aEllipticCurveTypes
aSECP256K1

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aPOINT_COORD_BYTE_LEN

Get the coordinate length.
Returns:
int: Coordinate key length

Get the underlying object.
Returns:
Any: Underlying object
point

Get point X coordinate.
Returns:
int: Point X coordinate

Get point Y coordinate.
Returns:
int: Point Y coordinate
aRawDecoded

Return the point raw bytes.
Returns:
DataBytes object: DataBytes object
aDataBytes
format
T tu
Return the encoded point raw bytes.
Returns:
DataBytes object: DataBytes object
T F:l nnu
Return the decoded point raw bytes.
Returns:
DataBytes object: DataBytes object
combine
aUnderlyingObject

Add point to another point.
Args:
point (IPoint object): IPoint object
Returns:
IPoint object: IPoint object
multiply
aIntegerUtils
aToBytes

Multiply point by a scalar.
Args:
scalar (int): scalar
Returns:
IPoint object: IPoint object
uModule for secp256k1 point based on coincurve library.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
ubip_utils.ecc.ecdsa.ecdsa_keys
T aEcdsaKeysConst
ubip_utils.utils.misc
T aDataBytes
aIntegerUtils
a__prepare__
aSecp256k1PointCoincurve
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
