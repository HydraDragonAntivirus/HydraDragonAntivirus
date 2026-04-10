# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_const

uClass container for Ed25519-Blake2b constants.
aEd25519Blake2bConst
a__qualname__
a__annotations__
uEd25519-Blake2b
aNAME
aCURVE_ORDER
aGENERATOR
ubip_utils\ecc\ed25519_blake2b\ed25519_blake2b_const.py
u<module bip_utils.ecc.ed25519_blake2b.ed25519_blake2b_const>
T a__class__

a__spec__
.bip_utils.ecc.ed25519_blake2b.ed25519_blake2b_keys
5
~
aEd25519KeysConst
aPUB_KEY_BYTE_LEN
aPUB_KEY_PREFIX
aBytesUtils
aToInteger
:l nnuInvalid public key bytes
ed25519_lib
point_is_on_curve
key_bytes
ed25519_blake2b
aVerifyingKey

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

Construct class from key object.
Args:
key_obj (ed25519_blake2b.VerifyingKey): Key object
aEllipticCurveTypes
aED25519_BLAKE2B

Get the elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type
aEd25519PublicKey
aCompressedLength

Get the compressed key length.
Returns:
int: Compressed key length
aUncompressedLength

Get the uncompressed key length.
Returns:
int: Uncompressed key length

Get the underlying object.
Returns:
Any: Underlying object
aDataBytes
to_bytes

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
aRawCompressed

Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
aEd25519Blake2bPoint

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
key_obj (ed25519_blake2b.SigningKey): Key object
aPRIV_KEY_BYTE_LEN

Get the key length.
Returns:
int: Key length

Return raw private key.
Returns:
DataBytes object: DataBytes object
aEd25519Blake2bPublicKey
get_verifying_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for ed25519-blake2b keys.
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
ubip_utils.ecc.ed25519.ed25519_keys
T aEd25519KeysConst
aEd25519PublicKey
ubip_utils.ecc.ed25519.lib
T aed25519_lib
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_point
T aEd25519Blake2bPoint
ubip_utils.utils.misc
T aBytesUtils
aDataBytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
