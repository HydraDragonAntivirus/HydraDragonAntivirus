# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519_kholaw.ed25519_kholaw_const

uClass container for Ed25519-Kholaw constants.
aEd25519KholawConst
a__qualname__
a__annotations__
uEd25519-Kholaw
aNAME
aCURVE_ORDER
aGENERATOR
ubip_utils\ecc\ed25519_kholaw\ed25519_kholaw_const.py
u<module bip_utils.ecc.ed25519_kholaw.ed25519_kholaw_const>
T a__class__

a__spec__
.bip_utils.ecc.ed25519_kholaw.ed25519_kholaw_keys
e
aEllipticCurveTypes
aED25519_KHOLAW

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aEd25519KholawPoint
m_ver_key

Get public key point.
Returns:
IPoint object: IPoint object
aEd25519PrivateKey
aFromBytes
aLength

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey: IPrivateKey object
Raises:
ValueError: If key bytes are not valid
uInvalid private key object type
uInvalid extended key length
m_sign_key
m_ext_key

Construct class.
Args:
key_obj (IPrivateKey object): Key object, shall be an Ed25519PrivateKey private key
key_ex_bytes (bytes)        : Key extended bytes
Raises:
TypeError: If key object is not of the correct type
ValueError: If extended key is not valid
aEd25519KholawKeysConst
aPRIV_KEY_BYTE_LEN

Get the key length.
Returns:
int: Key length
aUnderlyingObject

Get the underlying object.
Returns:
Any: Underlying object
aDataBytes
aRaw
aToBytes

Return raw private key.
Returns:
DataBytes object: DataBytes object
aEd25519KholawPublicKey
signing
aVerifyKey
ed25519_lib
point_scalar_mul_base

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object

Module for ed25519-kholaw keys.
With respect to ed25519, the private key has a length of 64-byte (left 32-byte of the ed25519 private key and a
right 32-byte extension part).
a__doc__
a__file__
origin
has_location
a__cached__
aAny
nacl
T asigning
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
ubip_utils.ecc.ed25519.ed25519_keys
T aEd25519PrivateKey
aEd25519PublicKey
aEd25519PublicKey
ubip_utils.ecc.ed25519.lib
T aed25519_lib
ubip_utils.ecc.ed25519_kholaw.ed25519_kholaw_point
T aEd25519KholawPoint
ubip_utils.utils.misc
T aDataBytes
