# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.ec

aEllipticCurveOID
a__qualname__
T u1.2.840.10045.3.1.1
aSECP192R1
T u1.3.132.0.33
aSECP224R1
T u1.3.132.0.10
aSECP256K1
T u1.2.840.10045.3.1.7
aSECP256R1
T u1.3.132.0.34
aSECP384R1
T u1.3.132.0.35
aSECP521R1
T u1.3.36.3.3.2.8.1.1.7
aBRAINPOOLP256R1
T u1.3.36.3.3.2.8.1.1.11
aBRAINPOOLP384R1
T u1.3.36.3.3.2.8.1.1.13
aBRAINPOOLP512R1
T u1.3.132.0.1
aSECT163K1
T u1.3.132.0.15
aSECT163R2
T u1.3.132.0.26
aSECT233K1
T u1.3.132.0.27
aSECT233R1
T u1.3.132.0.16
aSECT283K1
T u1.3.132.0.17
aSECT283R1
T u1.3.132.0.36
aSECT409K1
T u1.3.132.0.37
aSECT409R1
T u1.3.132.0.38
aSECT571K1
T u1.3.132.0.39
aSECT571R1
metaclass
aABCMeta
a__prepare__
T aEllipticCurve
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
aEllipticCurve
property
abstractmethod
D areturn
str

The name of the curve. e.g. secp256r1.
name
uEllipticCurve.name
D areturn
int

Bit size of a secret scalar for the curve.
key_size
uEllipticCurve.key_size
T aEllipticCurveSignatureAlgorithm
T
aEllipticCurveSignatureAlgorithm
D areturn
uasym_utils.Prehashed | hashes.HashAlgorithm

The digest algorithm used with this signature.
algorithm
uEllipticCurveSignatureAlgorithm.algorithm
T aEllipticCurvePrivateKey
T
aEllipticCurvePrivateKey
D aalgorithm
peer_public_key
return
aECDH
aEllipticCurvePublicKey
bytes

Performs a key exchange operation using the provided algorithm with the
provided peer's public key.
exchange
uEllipticCurvePrivateKey.exchange
D areturn
aEllipticCurvePublicKey

The EllipticCurvePublicKey for this private key.
public_key
uEllipticCurvePrivateKey.public_key
D areturn
aEllipticCurve

The EllipticCurve that this key is on.
curve
uEllipticCurvePrivateKey.curve
uEllipticCurvePrivateKey.key_size
D adata
signature_algorithm
return
bytes
aEllipticCurveSignatureAlgorithm
bytes

Signs the data
sign
uEllipticCurvePrivateKey.sign
D areturn
aEllipticCurvePrivateNumbers

Returns an EllipticCurvePrivateNumbers.
private_numbers
uEllipticCurvePrivateKey.private_numbers
D aencoding
format
encryption_algorithm
return
u_serialization.Encoding
u_serialization.PrivateFormat
u_serialization.KeySerializationEncryption
bytes

Returns the key serialized as bytes.
private_bytes
uEllipticCurvePrivateKey.private_bytes
aEllipticCurvePrivateKeyWithSerialization
register
aECPrivateKey
T aEllipticCurvePublicKey
T
aEllipticCurvePublicKey
uEllipticCurvePublicKey.curve
uEllipticCurvePublicKey.key_size
D areturn
aEllipticCurvePublicNumbers

Returns an EllipticCurvePublicNumbers.
public_numbers
uEllipticCurvePublicKey.public_numbers
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes
public_bytes
uEllipticCurvePublicKey.public_bytes
D asignature
data
signature_algorithm
return
bytes
paEllipticCurveSignatureAlgorithm
aNone

Verifies the signature of the data.
verify
uEllipticCurvePublicKey.verify
classmethod
D acurve
data
return
aEllipticCurve
bytes
aEllipticCurvePublicKey
from_encoded_point
uEllipticCurvePublicKey.from_encoded_point
D aother
return
object
bool

Checks equality.
a__eq__
uEllipticCurvePublicKey.__eq__
aEllipticCurvePublicKeyWithSerialization
aECPublicKey
aEllipticCurvePrivateNumbers
aEllipticCurvePublicNumbers
sect571r1
l  a__orig_bases__
sect409r1
l  asect283r1
l  asect233r1
l  asect163r2
l  asect571k1
l  asect409k1
sect283k1
sect233k1
sect163k1
secp521r1
l  asecp384r1
l  asecp256r1
l  asecp256k1
secp224r1
l  asecp192r1
l  aBrainpoolP256R1
brainpoolP256r1
aBrainpoolP384R1
brainpoolP384r1
aBrainpoolP512R1
brainpoolP512r1
l  aprime192v1
prime256v1
a_CURVE_TYPES
udict[str, EllipticCurve]
aECDSA
T FD aalgorithm
deterministic_signing
uasym_utils.Prehashed | hashes.HashAlgorithm
bool
a__init__
uECDSA.__init__
uECDSA.algorithm
D areturn
bool
deterministic_signing
uECDSA.deterministic_signing
generate_private_key
T nD aprivate_value
curve
backend
return
int
aEllipticCurve
utyping.Any
aEllipticCurvePrivateKey
aECDH
D aoid
return
aObjectIdentifier
utype[EllipticCurve]
get_curve_for_oid
ucryptography\hazmat\primitives\asymmetric\ec.py
u<module cryptography.hazmat.primitives.asymmetric.ec>
T a__class__
T aself
other
T aself
algorithm
deterministic_signing
backend
T aself
T aprivate_value
curve
backend
T aself
algorithm
peer_public_key
T acls
curve
data
T aoid
T aself
encoding
format
encryption_algorithm
T aself
encoding
format
T aself
data
signature_algorithm
T aself
signature
data
signature_algorithm

a__spec__
.cryptography.hazmat.primitives.asymmetric.ed25519
D
`
ucryptography.hazmat.backends.openssl.backend
T abackend
backend
ed25519_supported
aUnsupportedAlgorithm
ued25519 is not supported by this version of OpenSSL.
a_Reasons
aUNSUPPORTED_PUBLIC_KEY_ALGORITHM
rust_openssl
ed25519
from_public_bytes
generate_key
from_private_bytes
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
ucryptography.exceptions
T aUnsupportedAlgorithm
a_Reasons
ucryptography.hazmat.bindings._rust
T aopenssl
openssl
ucryptography.hazmat.primitives
T a_serialization
a_serialization
metaclass
aABCMeta
a__prepare__
T aEd25519PublicKey
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
