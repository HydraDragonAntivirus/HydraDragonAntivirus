# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.secp256k1.secp256k1_const

uClass container for Secp256k1 constants.
aSecp256k1Const
a__qualname__
aSecp256k1
aNAME
aCURVE_ORDER
aGENERATOR
ubip_utils\ecc\secp256k1\secp256k1_const.py
u<module bip_utils.ecc.secp256k1.secp256k1_const>
T a__class__

a__spec__
.bip_utils.ecc.secp256k1.secp256k1_keys_coincurve
|
coincurve
aPublicKey
uInvalid public key bytes

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key bytes are not valid
from_point
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
key_obj (coincurve.PublicKey): Key object
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
format
T tu
Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
T Fu
Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
point
aSecp256k1PointCoincurve
aFromCoordinates

Get public key point.
Returns:
IPoint object: IPoint object
aLength
uInvalid private key bytes
aPrivateKey

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
key_obj (coincurve.PrivateKey): Key object
aPRIV_KEY_BYTE_LEN

Get the key length.
Returns:
int: Key length
secret

Return raw private key.
Returns:
DataBytes object: DataBytes object
aSecp256k1PublicKeyCoincurve
public_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for secp256k1 keys based on coincurve library.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
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
ubip_utils.ecc.secp256k1.secp256k1_point_coincurve
T aSecp256k1PointCoincurve
ubip_utils.utils.misc
T aDataBytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
