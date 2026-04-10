# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.sr25519.sr25519_const

uClass container for Sr25519 constants.
aSr25519Const
a__qualname__
a__annotations__
aSr25519
aNAME
aCURVE_ORDER
aFromCoordinates
T l
paGENERATOR
ubip_utils\ecc\sr25519\sr25519_const.py
u<module bip_utils.ecc.sr25519.sr25519_const>
T a__class__

a__spec__
.bip_utils.ecc.sr25519.sr25519_keys
m

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key bytes are not valid
uConstrution from point not supported

Construct class from key point.
Args:
key_point (IPoint object): Key point
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key point is not valid
aCompressedLength
uInvalid public key
m_ver_key

Construct class from key object.
Args:
key_bytes (bytes): Key bytes
Raises:
ValueError: If key is not valid
aEllipticCurveTypes
aSR25519

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aSr25519KeysConst
aPUB_KEY_BYTE_LEN

Get the compressed key length.
Returns:
int: Compressed key length
aSr25519PublicKey

Get the uncompressed key length.
Returns:
int: Uncompressed key length

Get the underlying object.
Returns:
Any: Underlying object
aDataBytes

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
aRawCompressed

Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
uGetting point from public key not supported

Get public key point.
Returns:
IPoint object: IPoint object

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey: IPrivateKey object
Raises:
ValueError: If key bytes are not valid
aLength
uInvalid private key
m_sign_key
aPRIV_KEY_BYTE_LEN

Get the key length.
Returns:
int: Key length

Return raw private key.
Returns:
DataBytes object: DataBytes object
sr25519
public_from_secret_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for sr25519 keys.
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
ubip_utils.utils.misc
T aDataBytes
