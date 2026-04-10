# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.asymmetric.padding

a__qualname__
uEMSA-PKCS1-v1_5
name
a__orig_bases__
uSentinel value for `MAX_LENGTH`.
uSentinel value for `AUTO`.
uSentinel value for `DIGEST_LENGTH`.
aPSS
a__annotations__
aMAX_LENGTH
aAUTO
aDIGEST_LENGTH
uEMSA-PSS
uint | _MaxLength | _Auto | _DigestLength
D amgf
salt_length
return
aMGF
uint | _MaxLength | _Auto | _DigestLength
aNone
a__init__
uPSS.__init__
property
D areturn
aMGF
mgf
uPSS.mgf
aOAEP
uEME-OAEP
D amgf
algorithm
label
aMGF
uhashes.HashAlgorithm
ubytes | None
uOAEP.__init__
D areturn
uhashes.HashAlgorithm
algorithm
uOAEP.algorithm
uOAEP.mgf
metaclass
aABCMeta
T aMGF
T
aMGF
uhashes.HashAlgorithm
aMGF1
D aalgorithm
uhashes.HashAlgorithm
uMGF1.__init__
D akey
hash_algorithm
return
ursa.RSAPrivateKey | rsa.RSAPublicKey
uhashes.HashAlgorithm
int
calculate_max_pss_salt_length
ucryptography\hazmat\primitives\asymmetric\padding.py
u<module cryptography.hazmat.primitives.asymmetric.padding>
T a__class__
T aself
algorithm
T aself
mgf
algorithm
label
T aself
mgf
salt_length
T aself
T akey
hash_algorithm
emlen
salt_length

a__spec__
.cryptography.hazmat.primitives.asymmetric.rsa
a_verify_rsa_parameters
rust_openssl
rsa
generate_private_key
T l l   upublic_exponent must be either 3 (for legacy compatibility) or 65537. Almost everyone should choose 65537 here!
l  ukey_size must be at least 1024-bits.
T l l
wbwaax1
x2

Modular Multiplicative Inverse. Returns x such that: (x*e) mod m == 1
a_modinv

Compute the CRT (q ** -1) % p value from RSA primes p and q.

Compute the CRT private_exponent % (p - 1) value from the RSA
private_exponent (d) and p.

Compute the CRT private_exponent % (q - 1) value from the RSA
private_exponent (d) and q.
gcd

Compute the RSA private_exponent (d) given the public exponent (e)
nd the RSA primes p and q.
This uses the Carmichael totient function to generate the
smallest possible working value of the private exponent.
l apow
un, d, e don't match
wtl aspotted
tries
a_MAX_RECOVERY_ATTEMPTS
random
randint
wnwkuUnable to compute factors p and q from exponent d.
wpasorted
D areverse
tu
Compute factors p and q from the private exponent d. We assume that n has
no more than two factors. This function is adapted from code in PyCrypto.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
typing
math
T agcd
ucryptography.hazmat.bindings._rust
T aopenssl
openssl
ucryptography.hazmat.primitives
T a_serialization
hashes
a_serialization
hashes
ucryptography.hazmat.primitives._asymmetric
T aAsymmetricPadding
aAsymmetricPadding
ucryptography.hazmat.primitives.asymmetric
T autils
utils
asym_utils
metaclass
aABCMeta
a__prepare__
T aRSAPrivateKey
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
