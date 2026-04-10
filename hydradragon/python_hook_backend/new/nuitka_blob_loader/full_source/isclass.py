# Reconstructed from integrated Nuitka blob
# Module: isclass

P abuiltins
a__builtin__
a__name__
u%s.%s

Returns a user-readable name for the type of an object
:param value:
A value to get the type name of
:return:
A unicode string of the object's type name
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
sys
str_cls
byte_cls
int_types
bytes_to_list
chr_cls
type_name
uasn1crypto\_types.py
u<module asn1crypto._types>
T anum
T avalue
cls

a__spec__
.asn1crypto.algos
>
( a_oid_pair
T aalgorithm
parameters
algorithm
native
a_oid_specs
dotted
a_null_algos
aNull
a_ForceNullParameters
a__setitem__
parameters
aVoid
D amd2_rsa
md5_rsa
sha1_rsa
sha224_rsa
sha256_rsa
sha384_rsa
sha512_rsa
rsassa_pkcs1v15
rsassa_pss
sha1_dsa
sha224_dsa
sha256_dsa
dsa
sha1_ecdsa
sha224_ecdsa
sha256_ecdsa
sha384_ecdsa
sha512_ecdsa
sha3_224_ecdsa
sha3_256_ecdsa
sha3_384_ecdsa
sha3_512_ecdsa
ecdsa
ed25519
ed448
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pkcs1v15
rsassa_pss
dsa
dsa
dsa
dsa
ecdsa
ecdsa
ecdsa
ecdsa
ecdsa
ecdsa
ecdsa
ecdsa
ecdsa
ecdsa
ed25519
ed448
unwrap

Signature algorithm not known for %s

:return:
A unicode string of "rsassa_pkcs1v15", "rsassa_pss", "dsa",
"ecdsa", "ed25519" or "ed448"
D amd2_rsa
md5_rsa
sha1_rsa
sha224_rsa
sha256_rsa
sha384_rsa
sha512_rsa
sha1_dsa
sha224_dsa
sha256_dsa
sha1_ecdsa
sha224_ecdsa
sha256_ecdsa
sha384_ecdsa
sha512_ecdsa
ed25519
ed448
md2
md5
sha1
sha224
sha256
sha384
sha512
sha1
sha224
sha256
sha1
sha224
sha256
sha384
sha512
sha512
shake256
rsassa_pss
hash_algorithm

Hash algorithm not known for %s

:return:
A unicode string of "md2", "md5", "sha1", "sha224", "sha256",
"sha384", "sha512", "sha512_224", "sha512_256" or "shake256"
int_from_bytes
l wrwsu
Reads a signature from a byte string encoding accordint to IEEE P1363,
which is used by Microsoft's BCryptSignHash() function.
:param data:
A byte string from BCryptSignHash()
:return:
A DSASignature object
int_to_bytes
max
fill_width

Dumps a signature to a byte string compatible with Microsoft's
BCryptVerifySignature() function.
:return:
A byte string compatible with BCryptVerifySignature()
pbes2
key_derivation_func
find
T w.T w_asplit
T w_l apbes1
pbkdf1
pkcs12
pkcs12_kdf

Encryption algorithm "%s" does not have a registered key
derivation function
encryption_algo

Unrecognized encryption algorithm "%s", can not determine key
derivation function

Returns the name of the key derivation function to use.
:return:
A unicode from of one of the following: "pbkdf1", "pbkdf2",
"pkcs12_kdf"
prf
T w_l u
Unrecognized encryption algorithm "%s", can not determine key
derivation hmac algorithm

Returns the HMAC algorithm to use with the KDF.
:return:
A unicode string of one of the following: "md2", "md5", "sha1",
"sha224", "sha256", "sha384", "sha512"
salt
name
other_source
T u
Can not determine key derivation salt - the
reserved-for-future-use other source salt choice was
specified in the PBKDF2 params structure

Unrecognized encryption algorithm "%s", can not determine key
derivation salt

Returns the byte string to use as the salt for the KDF.
:return:
A byte string
iteration_count
iterations

Unrecognized encryption algorithm "%s", can not determine key
derivation iterations

Returns the number of iterations that should be run via the KDF.
:return:
An integer
:l
l naaes
D aaes128_
aes192_
aes256_
l l l :l
l nD ades
tripledes_3key
l l arc2
rc2_parameter_version
D l  lxl:l l l l  l T u
Invalid RC2 parameter version found in EncryptionAlgorithm
parameters
key_length
encryption_scheme
D apbes1_md2_des
pbes1_md5_des
pbes1_md2_rc2
pbes1_md5_rc2
pbes1_sha1_des
pbes1_sha1_rc2
pkcs12_sha1_rc4_128
pkcs12_sha1_rc4_40
pkcs12_sha1_tripledes_3key
pkcs12_sha1_tripledes_2key
pkcs12_sha1_rc2_128
pkcs12_sha1_rc2_40
l pppppl l l l pl u
Unrecognized encryption algorithm "%s"

Returns the key length to pass to the cipher/kdf. The PKCS#5 spec does
not specify a way to store the RC5 key length, however this tends not
to be a problem since OpenSSL does not support RC5 in PKCS#8 and OS X
does not provide an RC5 cipher for use in the Security Transforms
library.
:raises:
ValueError - when the key length can not be determined
:return:
An integer representing the length in bytes
P aaes192_
aes128_
aes256_
:l nn:l
l napbes1_
cbc
pkcs12_
P atripledes_3key
des
rc2
rc5
encryption_mode

Returns the name of the encryption mode to use.
:return:
A unicode string from one of the following: "cbc", "ecb", "ofb",
"cfb", "wrap", "gcm", "ccm", "wrap_pad"
P ades
rc2
rc5
tripledes_3key
tripledes
encryption_cipher
D apbes1_md2_des
pbes1_md5_des
pbes1_md2_rc2
pbes1_md5_rc2
pbes1_sha1_des
pbes1_sha1_rc2
pkcs12_sha1_rc4_128
pkcs12_sha1_rc4_40
pkcs12_sha1_tripledes_3key
pkcs12_sha1_tripledes_2key
pkcs12_sha1_rc2_128
pkcs12_sha1_rc2_40
des
des
rc2
rc2
des
rc2
rc4
rc4
tripledes
tripledes
rc2
rc2

Returns the name of the symmetric encryption cipher to use. The key
length can be retrieved via the .key_length property to disabiguate
between different variations of TripleDES, AES, and the RC* ciphers.
:return:
A unicode string from one of the following: "rc2", "rc5", "des",
"tripledes", "aes"
l D ades
tripledes_3key
rc2
l pparc5
block_size_in_bits
l aencryption_block_size
D apbes1_md2_des
pbes1_md5_des
pbes1_md2_rc2
pbes1_md5_rc2
pbes1_sha1_des
pbes1_sha1_rc2
pkcs12_sha1_rc4_128
pkcs12_sha1_rc4_40
pkcs12_sha1_tripledes_3key
pkcs12_sha1_tripledes_2key
pkcs12_sha1_rc2_128
pkcs12_sha1_rc2_40
l pppppl
pl pppu
Returns the block size of the encryption cipher, in bytes.
:return:
An integer that is the block size in bytes
P arc2
rc5
iv
S aaes192_ofb
tripledes_3key
aes192_cbc
aes128_cbc
aes256_cbc
des
aes256_ofb
aes128_ofb
encryption_iv

Returns the byte string of the initialization vector for the encryption
scheme. Only the PBES2 stores the IV in the params. For PBES1, the IV
is derived from the KDF and this property will return None.
:return:
A byte string or None
a_map
aEncryptionAlgorithmId
aSignedDigestAlgorithmId
aDigestAlgorithmId
items
aSequence
a_setup
aEncryptionAlgorithm
aSignedDigestAlgorithm
specs

ASN.1 type classes for various algorithms using in various aspects of public
key cryptography. Exports the following items:
- AlgorithmIdentifier()
- AnyAlgorithmIdentifier()
- DigestAlgorithm()
- DigestInfo()
- DSASignature()
- EncryptionAlgorithm()
- HmacAlgorithm()
- KdfAlgorithm()
- Pkcs5MacAlgorithm()
- SignedDigestAlgorithm()
Other type classes are defined that help compose the types listed above.
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
a_errors
T aunwrap
a_int
T afill_width
util
T aint_from_bytes
int_to_bytes
core
T aAny
aChoice
aInteger
aNull
aObjectIdentifier
aOctetString
aSequence
aVoid
aAny
aChoice
aInteger
aObjectIdentifier
aOctetString
a__prepare__
aAlgorithmIdentifier
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
