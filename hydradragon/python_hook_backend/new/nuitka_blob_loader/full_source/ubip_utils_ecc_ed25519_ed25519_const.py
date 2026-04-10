# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519.ed25519_const

uClass container for Ed25519 constants.
aEd25519Const
a__qualname__
a__annotations__
aEd25519
aNAME
l l  g          ^          aCURVE_ORDER
aFromCoordinates
T g	!                                      yg	f                                        aGENERATOR
ubip_utils\ecc\ed25519\ed25519_const.py
u<module bip_utils.ecc.ed25519.ed25519_const>
T a__class__

a__spec__
.bip_utils.ecc.ed25519.ed25519_keys
aEd25519KeysConst
aPUB_KEY_BYTE_LEN
aPUB_KEY_PREFIX
aBytesUtils
aToInteger
:l nnaed25519_lib
point_is_on_curve
key_bytes
uInvalid public key bytes
signing
aVerifyKey
exceptions
aRuntimeError
aValueError

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key bytes are not valid
aFromBytes
aRawEncoded
aToBytes

Construct class from key point.
Args:
key_point (IPoint object): Key point
Returns:
IPublicKey: IPublicKey object
Raises:
ValueError: If key point is not valid
m_ver_key

Construct class.
Args:
key_obj (signing.VerifyKey): Key object
aEllipticCurveTypes
aED25519

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type

Get the compressed key length.
Returns:
int: Compressed key length
aEd25519PublicKey
aCompressedLength

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
aEd25519Point

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

Construct class.
Args:
key_obj (signing.SigningKey): Key object
aPRIV_KEY_BYTE_LEN

Get the key length.
Returns:
int: Key length

Return raw private key.
Returns:
DataBytes object: DataBytes object
verify_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for ed25519 keys.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
nacl
T aexceptions
signing
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
ubip_utils.ecc.ed25519.ed25519_point
T aEd25519Point
ubip_utils.ecc.ed25519.lib
T aed25519_lib
ubip_utils.utils.misc
T aBytesUtils
aDataBytes
