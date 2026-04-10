# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.secp256k1.secp256k1_keys_coincurve

uSecp256k1 public key class.
a__qualname__
a__annotations__
classmethod
key_bytes
bytes
return
aFromBytes
uSecp256k1PublicKeyCoincurve.FromBytes
key_point
aFromPoint
uSecp256k1PublicKeyCoincurve.FromPoint
key_obj
a__init__
uSecp256k1PublicKeyCoincurve.__init__
staticmethod
aCurveType
uSecp256k1PublicKeyCoincurve.CurveType
int
aCompressedLength
uSecp256k1PublicKeyCoincurve.CompressedLength
aUncompressedLength
uSecp256k1PublicKeyCoincurve.UncompressedLength
aUnderlyingObject
uSecp256k1PublicKeyCoincurve.UnderlyingObject
aRawCompressed
uSecp256k1PublicKeyCoincurve.RawCompressed
aRawUncompressed
uSecp256k1PublicKeyCoincurve.RawUncompressed
aPoint
uSecp256k1PublicKeyCoincurve.Point
a__orig_bases__
aSecp256k1PrivateKeyCoincurve
uSecp256k1 private key class.
uSecp256k1PrivateKeyCoincurve.FromBytes
uSecp256k1PrivateKeyCoincurve.__init__
uSecp256k1PrivateKeyCoincurve.CurveType
uSecp256k1PrivateKeyCoincurve.Length
uSecp256k1PrivateKeyCoincurve.UnderlyingObject
aRaw
uSecp256k1PrivateKeyCoincurve.Raw
uSecp256k1PrivateKeyCoincurve.PublicKey
ubip_utils\ecc\secp256k1\secp256k1_keys_coincurve.py
u<module bip_utils.ecc.secp256k1.secp256k1_keys_coincurve>
T acls
key_bytes
ex
T acls
key_point
ex
T aself
point
T aself
T a__class__
T aself
key_obj

a__spec__
.bip_utils.ecc.secp256k1.secp256k1_keys_ecdsa
Y
ecdsa
aVerifyingKey
from_string
curves
aSECP256k1
T acurve
keys
aMalformedPointError
uInvalid public key bytes

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key bytes are not valid
from_public_point
ellipticcurve
aPoint
curve_secp256k1
wXwYuInvalid public key point

Construct class from key point.
Args:
key_point (IPoint object): Key point
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key point is not valid
m_ver_key

Construct class from key object.
Args:
key_obj (ecdsa.VerifyingKey): Key object
aEllipticCurveTypes
aSECP256K1

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aEcdsaKeysConst
aPUB_KEY_COMPRESSED_BYTE_LEN

Get the compressed key length.
Returns:
int: Compressed key length
aPUB_KEY_UNCOMPRESSED_BYTE_LEN

Get the uncompressed key length.
Returns:
int: Uncompressed key length

Get the underlying object.
Returns:
Any: Underlying object
aDataBytes
to_string
T acompressed

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
T auncompressed

Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
aSecp256k1PointEcdsa
pubkey
point

Get public key point.
Returns:
IPoint object: IPoint object
aSigningKey
uInvalid private key bytes

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey: IPrivateKey object
Raises:
ValueError: If key bytes are not valid
m_sign_key

Construct class from key object.
Args:
key_obj (ecdsa.SigningKey): Key object
aPRIV_KEY_BYTE_LEN

Get the key length.
Returns:
int: Key length

Return raw private key.
Returns:
DataBytes object: DataBytes object
aSecp256k1PublicKeyEcdsa
get_verifying_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for secp256k1 keys based on ecdsa library.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
T acurves
ellipticcurve
keys
uecdsa.ecdsa
T acurve_secp256k1
ubip_utils.ecc.common.ikeys
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
ubip_utils.ecc.ecdsa.ecdsa_keys
T aEcdsaKeysConst
ubip_utils.ecc.secp256k1.secp256k1_point_ecdsa
T aSecp256k1PointEcdsa
ubip_utils.utils.misc
T aDataBytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
