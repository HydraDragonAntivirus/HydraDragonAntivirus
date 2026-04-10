# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519_monero.ed25519_monero_const

uClass container for Ed25519-Monero constants.
aEd25519MoneroConst
a__qualname__
a__annotations__
uEd25519-Monero
aNAME
aCURVE_ORDER
aFromCoordinates
aGENERATOR
wXwYubip_utils\ecc\ed25519_monero\ed25519_monero_const.py
u<module bip_utils.ecc.ed25519_monero.ed25519_monero_const>
T a__class__

a__spec__
.bip_utils.ecc.ed25519_monero.ed25519_monero_keys
h
Z
aEllipticCurveTypes
aED25519_MONERO

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aEd25519KeysConst
aPUB_KEY_BYTE_LEN

Get the compressed key length.
Returns:
int: Compressed key length
aEd25519MoneroPublicKey
aCompressedLength

Get the uncompressed key length.
Returns:
int: Uncompressed key length
aDataBytes
m_ver_key

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
aEd25519MoneroPoint

Get public key point.
Returns:
IPoint object: IPoint object
ed25519_lib
scalar_is_valid
uInvalid private key bytes
a__class__
aFromBytes

Construct class from key bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey: IPrivateKey object
Raises:
ValueError: If key bytes are not valid
signing
aVerifyKey
point_scalar_mul_base
m_sign_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for ed25519-monero keys.
a__doc__
a__file__
origin
has_location
a__cached__
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
T aEd25519KeysConst
aEd25519PrivateKey
aEd25519PublicKey
aEd25519PrivateKey
aEd25519PublicKey
ubip_utils.ecc.ed25519.lib
T aed25519_lib
ubip_utils.ecc.ed25519_monero.ed25519_monero_point
T aEd25519MoneroPoint
ubip_utils.utils.misc
T aDataBytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
