# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.dh

aDHParameters
a__qualname__
abstractmethod
D areturn
aDHPrivateKey

Generates and returns a DHPrivateKey.
generate_private_key
uDHParameters.generate_private_key
D aencoding
format
return
u_serialization.Encoding
u_serialization.ParameterFormat
bytes

Returns the parameters serialized as bytes.
parameter_bytes
uDHParameters.parameter_bytes
D areturn
aDHParameterNumbers

Returns a DHParameterNumbers.
parameter_numbers
uDHParameters.parameter_numbers
aDHParametersWithSerialization
register
T aDHPublicKey
T
aDHPublicKey
property
D areturn
int

The bit length of the prime modulus.
key_size
uDHPublicKey.key_size
D areturn
aDHParameters

The DHParameters object associated with this public key.
parameters
uDHPublicKey.parameters
D areturn
aDHPublicNumbers

Returns a DHPublicNumbers.
public_numbers
uDHPublicKey.public_numbers
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes

Returns the key serialized as bytes.
public_bytes
uDHPublicKey.public_bytes
D aother
return
object
bool

Checks equality.
a__eq__
uDHPublicKey.__eq__
aDHPublicKeyWithSerialization
T aDHPrivateKey
T
aDHPrivateKey
uDHPrivateKey.key_size
D areturn
aDHPublicKey

The DHPublicKey associated with this private key.
public_key
uDHPrivateKey.public_key

The DHParameters object associated with this private key.
uDHPrivateKey.parameters
D apeer_public_key
return
aDHPublicKey
bytes

Given peer's DHPublicKey, carry out the key exchange and
return shared key as bytes.
exchange
uDHPrivateKey.exchange
D areturn
aDHPrivateNumbers

Returns a DHPrivateNumbers.
private_numbers
uDHPrivateKey.private_numbers
D aencoding
format
encryption_algorithm
return
u_serialization.Encoding
u_serialization.PrivateFormat
u_serialization.KeySerializationEncryption
bytes
private_bytes
uDHPrivateKey.private_bytes
aDHPrivateKeyWithSerialization
ucryptography\hazmat\primitives\asymmetric\dh.py
u<module cryptography.hazmat.primitives.asymmetric.dh>
T a__class__
T aself
other
T aself
peer_public_key
T aself
T aself
encoding
format
T aself
encoding
format
encryption_algorithm

a__spec__
.cryptography.hazmat.primitives.asymmetric.dsa
^
s
T l  l  l  l  uKey size must be 1024, 2048, 3072, or 4096 bits.
rust_openssl
dsa
generate_parameters
generate_private_key
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
typing
ucryptography.hazmat.bindings._rust
T aopenssl
openssl
ucryptography.hazmat.primitives
T a_serialization
hashes
a_serialization
hashes
ucryptography.hazmat.primitives.asymmetric
T autils
utils
asym_utils
metaclass
aABCMeta
a__prepare__
T aDSAParameters
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
