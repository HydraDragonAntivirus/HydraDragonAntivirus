# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.x25519

aX25519PublicKey
a__qualname__
classmethod
D adata
return
bytes
aX25519PublicKey
uX25519PublicKey.from_public_bytes
abstractmethod
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes

The serialized bytes of the public key.
public_bytes
uX25519PublicKey.public_bytes
D areturn
bytes

The raw bytes of the public key.
Equivalent to public_bytes(Raw, Raw).
public_bytes_raw
uX25519PublicKey.public_bytes_raw
D aother
return
object
bool

Checks equality.
a__eq__
uX25519PublicKey.__eq__
register
T aX25519PrivateKey
T
aX25519PrivateKey
D areturn
aX25519PrivateKey
generate
uX25519PrivateKey.generate
D adata
return
bytes
aX25519PrivateKey
uX25519PrivateKey.from_private_bytes
D areturn
aX25519PublicKey

Returns the public key associated with this private key
public_key
uX25519PrivateKey.public_key
D aencoding
format
encryption_algorithm
return
u_serialization.Encoding
u_serialization.PrivateFormat
u_serialization.KeySerializationEncryption
bytes

The serialized bytes of the private key.
private_bytes
uX25519PrivateKey.private_bytes

The raw bytes of the private key.
Equivalent to private_bytes(Raw, Raw, NoEncryption()).
private_bytes_raw
uX25519PrivateKey.private_bytes_raw
D apeer_public_key
return
aX25519PublicKey
bytes

Performs a key exchange operation using the provided peer's public key.
exchange
uX25519PrivateKey.exchange
ucryptography\hazmat\primitives\asymmetric\x25519.py
u<module cryptography.hazmat.primitives.asymmetric.x25519>
T a__class__
T aself
other
T aself
peer_public_key
T acls
data
backend
T acls
backend
T aself
encoding
format
encryption_algorithm
T aself
T aself
encoding
format

a__spec__
.cryptography.hazmat.primitives.asymmetric.x448
[
ucryptography.hazmat.backends.openssl.backend
T abackend
backend
x448_supported
aUnsupportedAlgorithm
uX448 is not supported by this version of OpenSSL.
a_Reasons
aUNSUPPORTED_EXCHANGE_ALGORITHM
rust_openssl
x448
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
T aX448PublicKey
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
