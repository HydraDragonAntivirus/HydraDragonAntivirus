# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.ed25519

aEd25519PublicKey
a__qualname__
classmethod
D adata
return
bytes
aEd25519PublicKey
uEd25519PublicKey.from_public_bytes
abstractmethod
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes

The serialized bytes of the public key.
public_bytes
uEd25519PublicKey.public_bytes
D areturn
bytes

The raw bytes of the public key.
Equivalent to public_bytes(Raw, Raw).
public_bytes_raw
uEd25519PublicKey.public_bytes_raw
D asignature
data
return
bytes
paNone

Verify the signature.
verify
uEd25519PublicKey.verify
D aother
return
object
bool

Checks equality.
a__eq__
uEd25519PublicKey.__eq__
register
T aEd25519PrivateKey
T
aEd25519PrivateKey
D areturn
aEd25519PrivateKey
generate
uEd25519PrivateKey.generate
D adata
return
bytes
aEd25519PrivateKey
uEd25519PrivateKey.from_private_bytes
D areturn
aEd25519PublicKey

The Ed25519PublicKey derived from the private key.
public_key
uEd25519PrivateKey.public_key
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
uEd25519PrivateKey.private_bytes

The raw bytes of the private key.
Equivalent to private_bytes(Raw, Raw, NoEncryption()).
private_bytes_raw
uEd25519PrivateKey.private_bytes_raw
D adata
return
bytes
pu
Signs the data.
sign
uEd25519PrivateKey.sign
ucryptography\hazmat\primitives\asymmetric\ed25519.py
u<module cryptography.hazmat.primitives.asymmetric.ed25519>
T a__class__
T aself
other
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
T aself
data
T aself
signature
data

a__spec__
.cryptography.hazmat.primitives.asymmetric.ed448
a
def ucryptography.hazmat.backends.openssl.backend
T abackend
backend
ed448_supported
aUnsupportedAlgorithm
ued448 is not supported by this version of OpenSSL.
a_Reasons
aUNSUPPORTED_PUBLIC_KEY_ALGORITHM
rust_openssl
ed448
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
T aEd448PublicKey
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
