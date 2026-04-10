# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.rsa

aRSAPrivateKey
a__qualname__
abstractmethod
D aciphertext
padding
return
bytes
aAsymmetricPadding
bytes

Decrypts the provided ciphertext.
decrypt
uRSAPrivateKey.decrypt
property
D areturn
int

The bit length of the public modulus.
key_size
uRSAPrivateKey.key_size
D areturn
aRSAPublicKey

The RSAPublicKey associated with this private key.
public_key
uRSAPrivateKey.public_key
D adata
padding
algorithm
return
bytes
aAsymmetricPadding
uasym_utils.Prehashed | hashes.HashAlgorithm
bytes

Signs the data.
sign
uRSAPrivateKey.sign
D areturn
aRSAPrivateNumbers

Returns an RSAPrivateNumbers.
private_numbers
uRSAPrivateKey.private_numbers
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
uRSAPrivateKey.private_bytes
aRSAPrivateKeyWithSerialization
register
T aRSAPublicKey
T
aRSAPublicKey
D aplaintext
padding
return
bytes
aAsymmetricPadding
bytes

Encrypts the given plaintext.
encrypt
uRSAPublicKey.encrypt
uRSAPublicKey.key_size
D areturn
aRSAPublicNumbers

Returns an RSAPublicNumbers
public_numbers
uRSAPublicKey.public_numbers
D aencoding
format
return
u_serialization.Encoding
u_serialization.PublicFormat
bytes
public_bytes
uRSAPublicKey.public_bytes
D asignature
data
padding
algorithm
return
bytes
paAsymmetricPadding
uasym_utils.Prehashed | hashes.HashAlgorithm
aNone

Verifies the signature of the data.
verify
uRSAPublicKey.verify
D asignature
padding
algorithm
return
bytes
aAsymmetricPadding
uhashes.HashAlgorithm | None
bytes

Recovers the original data from the signature.
recover_data_from_signature
uRSAPublicKey.recover_data_from_signature
D aother
return
object
bool

Checks equality.
a__eq__
uRSAPublicKey.__eq__
aRSAPublicKeyWithSerialization
aRSAPrivateNumbers
aRSAPublicNumbers
T nD apublic_exponent
key_size
backend
return
int
putyping.Any
aRSAPrivateKey
D apublic_exponent
key_size
return
int
paNone
D wewmareturn
int
ppD wpwqareturn
int
pparsa_crt_iqmp
D aprivate_exponent
wpareturn
int
pparsa_crt_dmp1
D aprivate_exponent
wqareturn
int
pparsa_crt_dmq1
D wewpwqareturn
int
ppparsa_recover_private_exponent
l  D wnwewdareturn
int
pputuple[int, int]
rsa_recover_prime_factors
ucryptography\hazmat\primitives\asymmetric\rsa.py
u<module cryptography.hazmat.primitives.asymmetric.rsa>
T a__class__
T aself
other
T	wewmax1
x2
wawbwqwraxn
T apublic_exponent
key_size
T aself
ciphertext
padding
T aself
plaintext
padding
T apublic_exponent
key_size
backend
T aself
T aself
encoding
format
encryption_algorithm
T aself
encoding
format
T aself
signature
padding
algorithm
T aprivate_exponent
wpT aprivate_exponent
wqT wpwqTwnwewdaktot
wtaspotted
tries
wawkacand
wpwqwrT wewpwqalambda_n
T aself
data
padding
algorithm
T aself
signature
data
padding
algorithm

a__spec__
.cryptography.hazmat.primitives.asymmetric.types
D
@
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
cryptography
T autils
utils
ucryptography.hazmat.primitives.asymmetric
T adh
dsa
ec
ed448
ed25519
rsa
x448
x25519
dh
dsa
ec
ed448
ed25519
rsa
x448
x25519
aUnion
aDHPublicKey
aDSAPublicKey
aRSAPublicKey
aEllipticCurvePublicKey
aEd25519PublicKey
aEd448PublicKey
aX25519PublicKey
aX448PublicKey
aPublicKeyTypes
aPUBLIC_KEY_TYPES
deprecated
ucryptography.hazmat.primitives.asymmetric.types
uUse PublicKeyTypes instead
aDeprecatedIn40
D aname
aPUBLIC_KEY_TYPES
aDHPrivateKey
aEd25519PrivateKey
aEd448PrivateKey
aRSAPrivateKey
aDSAPrivateKey
aEllipticCurvePrivateKey
aX25519PrivateKey
aX448PrivateKey
aPrivateKeyTypes
aPRIVATE_KEY_TYPES
uUse PrivateKeyTypes instead
D aname
aPRIVATE_KEY_TYPES
aCertificateIssuerPrivateKeyTypes
aCERTIFICATE_PRIVATE_KEY_TYPES
uUse CertificateIssuerPrivateKeyTypes instead
D aname
aCERTIFICATE_PRIVATE_KEY_TYPES
aCertificateIssuerPublicKeyTypes
aCERTIFICATE_ISSUER_PUBLIC_KEY_TYPES
uUse CertificateIssuerPublicKeyTypes instead
D aname
aCERTIFICATE_ISSUER_PUBLIC_KEY_TYPES
aCertificatePublicKeyTypes
aCERTIFICATE_PUBLIC_KEY_TYPES
uUse CertificatePublicKeyTypes instead
D aname
aCERTIFICATE_PUBLIC_KEY_TYPES
ucryptography\hazmat\primitives\asymmetric\types.py
u<module cryptography.hazmat.primitives.asymmetric.types>

a__spec__
.cryptography.hazmat.primitives.asymmetric.utils
#
hashes
aHashAlgorithm
uExpected instance of HashAlgorithm.
a_algorithm
digest_size
a_digest_size
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucryptography.hazmat.bindings._rust
T aasn1
asn1
ucryptography.hazmat.primitives
T ahashes
decode_dss_signature
encode_dss_signature
