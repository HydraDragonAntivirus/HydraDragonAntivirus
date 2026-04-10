# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.ed448

aEd448PublicKey
a__qualname__
classmethod
D adata
return
bytes
aEd448PublicKey
uEd448PublicKey.from_public_bytes
abstractmethod
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes

The serialized bytes of the public key.
public_bytes
uEd448PublicKey.public_bytes
D areturn
bytes

The raw bytes of the public key.
Equivalent to public_bytes(Raw, Raw).
public_bytes_raw
uEd448PublicKey.public_bytes_raw
D asignature
data
return
bytes
paNone

Verify the signature.
verify
uEd448PublicKey.verify
D aother
return
object
bool

Checks equality.
a__eq__
uEd448PublicKey.__eq__
register
T aEd448PrivateKey
T
aEd448PrivateKey
D areturn
aEd448PrivateKey
generate
uEd448PrivateKey.generate
D adata
return
bytes
aEd448PrivateKey
uEd448PrivateKey.from_private_bytes
D areturn
aEd448PublicKey

The Ed448PublicKey derived from the private key.
public_key
uEd448PrivateKey.public_key
D adata
return
bytes
pu
Signs the data.
sign
uEd448PrivateKey.sign
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
uEd448PrivateKey.private_bytes

The raw bytes of the private key.
Equivalent to private_bytes(Raw, Raw, NoEncryption()).
private_bytes_raw
uEd448PrivateKey.private_bytes_raw
x448
ucryptography\hazmat\primitives\asymmetric\ed448.py
u<module cryptography.hazmat.primitives.asymmetric.ed448>
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
.cryptography.hazmat.primitives.asymmetric.padding
6
\
a_mgf
a_MaxLength
a_Auto
a_DigestLength
usalt_length must be an integer, MAX_LENGTH, DIGEST_LENGTH, or AUTO
usalt_length must be zero or greater.
a_salt_length
hashes
aHashAlgorithm
uExpected instance of hashes.HashAlgorithm.
a_algorithm
a_label
rsa
aRSAPrivateKey
aRSAPublicKey
ukey must be an RSA public or private key
key_size
l l adigest_size
l a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
ucryptography.hazmat.primitives
T ahashes
ucryptography.hazmat.primitives._asymmetric
T aAsymmetricPadding
aAsymmetricPadding
ucryptography.hazmat.primitives.asymmetric
T arsa
a__prepare__
aPKCS1v15
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
