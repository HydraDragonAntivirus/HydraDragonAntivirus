# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.nist256p1.nist256p1_const

uClass container for Nist256p1 constants.
aNist256p1Const
a__qualname__
a__annotations__
aNist256p1
aNAME
order
aCURVE_ORDER
aGENERATOR
ubip_utils\ecc\nist256p1\nist256p1_const.py
u<module bip_utils.ecc.nist256p1.nist256p1_const>
T a__class__

a__spec__
.bip_utils.ecc.nist256p1.nist256p1_keys
ecdsa
aVerifyingKey
from_string
curves
aNIST256p
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
curve_256
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
aNIST256P1

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
aNist256p1Point
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
aNist256p1PublicKey
get_verifying_key

Get the public key correspondent to the private one.
Returns:
IPublicKey object: IPublicKey object
uModule for nist256p1 keys.
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
T acurve_256
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
ubip_utils.ecc.nist256p1.nist256p1_point
T aNist256p1Point
ubip_utils.utils.misc
T aDataBytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
