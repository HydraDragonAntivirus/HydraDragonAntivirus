# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.dsa

aDSAParameters
a__qualname__
abstractmethod
D areturn
aDSAPrivateKey

Generates and returns a DSAPrivateKey.
uDSAParameters.generate_private_key
D areturn
aDSAParameterNumbers

Returns a DSAParameterNumbers.
parameter_numbers
uDSAParameters.parameter_numbers
aDSAParametersWithNumbers
register
T aDSAPrivateKey
T
aDSAPrivateKey
property
D areturn
int

The bit length of the prime modulus.
key_size
uDSAPrivateKey.key_size
D areturn
aDSAPublicKey

The DSAPublicKey associated with this private key.
public_key
uDSAPrivateKey.public_key
D areturn
aDSAParameters

The DSAParameters object associated with this private key.
parameters
uDSAPrivateKey.parameters
D adata
algorithm
return
bytes
uasym_utils.Prehashed | hashes.HashAlgorithm
bytes

Signs the data
sign
uDSAPrivateKey.sign
D areturn
aDSAPrivateNumbers

Returns a DSAPrivateNumbers.
private_numbers
uDSAPrivateKey.private_numbers
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
uDSAPrivateKey.private_bytes
aDSAPrivateKeyWithSerialization
T aDSAPublicKey
T
aDSAPublicKey
uDSAPublicKey.key_size

The DSAParameters object associated with this public key.
uDSAPublicKey.parameters
D areturn
aDSAPublicNumbers

Returns a DSAPublicNumbers.
public_numbers
uDSAPublicKey.public_numbers
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes
public_bytes
uDSAPublicKey.public_bytes
D asignature
data
algorithm
return
bytes
puasym_utils.Prehashed | hashes.HashAlgorithm
aNone

Verifies the signature of the data.
verify
uDSAPublicKey.verify
D aother
return
object
bool

Checks equality.
a__eq__
uDSAPublicKey.__eq__
aDSAPublicKeyWithSerialization
aDSAPrivateNumbers
aDSAPublicNumbers
aDSAParameterNumbers
T nD akey_size
backend
return
int
utyping.Any
aDSAParameters
D akey_size
backend
return
int
utyping.Any
aDSAPrivateKey
ucryptography\hazmat\primitives\asymmetric\dsa.py
u<module cryptography.hazmat.primitives.asymmetric.dsa>
T a__class__
T aself
other
T akey_size
backend
T aself
T akey_size
backend
parameters
T aself
encoding
format
encryption_algorithm
T aself
encoding
format
T aself
data
algorithm
T aself
signature
data
algorithm

a__spec__
.cryptography.hazmat.primitives.asymmetric.ec
utils
a_check_bytes
data
udata must not be an empty byte string
T l l l uUnsupported elliptic curve point type
rust_openssl
ec
from_public_bytes
ucryptography.hazmat.backends.openssl.backend
T abackend
backend
ecdsa_deterministic_supported
aUnsupportedAlgorithm
uECDSA with deterministic signature (RFC 6979) is not supported by this version of OpenSSL.
a_Reasons
aUNSUPPORTED_PUBLIC_KEY_ALGORITHM
a_algorithm
a_deterministic_signing
uprivate_value must be an integer type.
uprivate_value must be a positive integer.
derive_private_key
a_OID_TO_CURVE
uThe provided object identifier has no matching elliptic curve class
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
abc
typing
cryptography
T autils
ucryptography.exceptions
T aUnsupportedAlgorithm
a_Reasons
ucryptography.hazmat._oid
T aObjectIdentifier
aObjectIdentifier
ucryptography.hazmat.bindings._rust
T aopenssl
openssl
ucryptography.hazmat.primitives
T a_serialization
hashes
a_serialization
hashes
ucryptography.hazmat.primitives.asymmetric
asym_utils
