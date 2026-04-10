# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Math._IntegerNative

uA class to model a natural integer (including zero)
a__qualname__
a__init__
uIntegerNative.__init__
a__int__
uIntegerNative.__int__
a__str__
uIntegerNative.__str__
a__repr__
uIntegerNative.__repr__
a__hex__
uIntegerNative.__hex__
a__index__
uIntegerNative.__index__
T l
big
to_bytes
uIntegerNative.to_bytes
classmethod
T abig
from_bytes
uIntegerNative.from_bytes
uIntegerNative.__eq__
a__ne__
uIntegerNative.__ne__
uIntegerNative.__lt__
uIntegerNative.__le__
a__gt__
uIntegerNative.__gt__
a__ge__
uIntegerNative.__ge__
a__nonzero__
uIntegerNative.__nonzero__
a__bool__
is_negative
uIntegerNative.is_negative
a__add__
uIntegerNative.__add__
a__sub__
uIntegerNative.__sub__
a__mul__
uIntegerNative.__mul__
a__floordiv__
uIntegerNative.__floordiv__
a__mod__
uIntegerNative.__mod__
T nuIntegerNative.inplace_pow
a__pow__
uIntegerNative.__pow__
a__abs__
uIntegerNative.__abs__
sqrt
uIntegerNative.sqrt
a__iadd__
uIntegerNative.__iadd__
a__isub__
uIntegerNative.__isub__
a__imul__
uIntegerNative.__imul__
a__imod__
uIntegerNative.__imod__
a__and__
uIntegerNative.__and__
a__or__
uIntegerNative.__or__
a__rshift__
uIntegerNative.__rshift__
a__irshift__
uIntegerNative.__irshift__
a__lshift__
uIntegerNative.__lshift__
a__ilshift__
uIntegerNative.__ilshift__
get_bit
uIntegerNative.get_bit
is_odd
uIntegerNative.is_odd
is_even
uIntegerNative.is_even
uIntegerNative.size_in_bits
size_in_bytes
uIntegerNative.size_in_bytes
is_perfect_square
uIntegerNative.is_perfect_square
fail_if_divisible_by
uIntegerNative.fail_if_divisible_by
multiply_accumulate
uIntegerNative.multiply_accumulate
set
uIntegerNative.set
uIntegerNative.inplace_inverse
uIntegerNative.inverse
uIntegerNative.gcd
lcm
uIntegerNative.lcm
staticmethod
uIntegerNative.jacobi_symbol
a_mult_modulo_bytes
uIntegerNative._mult_modulo_bytes
a__orig_bases__
uCrypto\Math\_IntegerNative.py
u<module Crypto.Math._IntegerNative>
T a__class__
T aself
T aself
term
T aself
divisor
T aself
pos
T aself
term
modulus
T aself
value
T aself
divisor
divisor_value
T aself
factor
T aself
exponent
modulus
result
T aterm1
term2
modulus
number_len
T aself
small_prime
T acls
byte_string
byteorder
T aself
wnaresult
T aself
modulus
T aself
exponent
modulus
exp_value
mod_value
T aself
modulus
result
T aself
wxasquare_x
T wawnweaa1
wsan1
T aself
wawbT aself
source
T aself
modulus
value
wxwyaresult
T aself
block_size
byteorder
result

a__spec__
.Crypto.Math
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aMath
T aNUITKA_PACKAGE_Crypto_Math
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uCrypto\Math\__init__.py
u<module Crypto.Math>

a__spec__
.Crypto.Protocol.DH
c
@
pointQ
wdais_point_at_infinity
uInvalid ECDH point
curve
aCurve25519
wxato_bytes
T l alittle
T abyteorder
aCurve448
T l8alittle
long_to_bytes
size_in_bytes
a_import_curve25519_public_key
construct
T acurve
point_x
uCreate a new X25519 public key object,
starting from the key encoded as raw ``bytes``,
in the format described in RFC7748.
Args:
encoded (bytes):
The x25519 public key to import.
It must be 32 bytes.
Returns:
:class:`Crypto.PublicKey.EccKey` : a new ECC key object.
Raises:
ValueError: when the given key cannot be parsed.
T aseed
curve
uCreate a new X25519 private key object,
starting from the key encoded as raw ``bytes``,
in the format described in RFC7748.
Args:
encoded (bytes):
The X25519 private key to import.
It must be 32 bytes.
Returns:
:class:`Crypto.PublicKey.EccKey` : a new ECC key object.
Raises:
ValueError: when the given key cannot be parsed.
a_import_curve448_public_key
uCreate a new X448 public key object,
starting from the key encoded as raw ``bytes``,
in the format described in RFC7748.
Args:
encoded (bytes):
The x448 public key to import.
It must be 56 bytes.
Returns:
:class:`Crypto.PublicKey.EccKey` : a new ECC key object.
Raises:
ValueError: when the given key cannot be parsed.
uCreate a new X448 private key object,
starting from the key encoded as raw ``bytes``,
in the format described in RFC7748.
Args:
encoded (bytes):
The X448 private key to import.
It must be 56 bytes.
Returns:
:class:`Crypto.PublicKey.EccKey` : a new ECC key object.
Raises:
ValueError: when the given key cannot be parsed.
static_priv
static_pub
eph_priv
eph_pub
kdf
u'kdf' is mandatory
check_curve
ukey_agreement.<locals>.check_curve
uToo few keys for the ECDH key agreement
c
a_compute_ecdh
uDH mode C(2e, 1s) is not supported
uPerform a Diffie-Hellman key agreement.
Keywords:
kdf (callable):
A key derivation function that accepts ``bytes`` as input and returns
``bytes``.
static_priv (EccKey):
The local static private key. Optional.
static_pub (EccKey):
The static public key that belongs to the peer. Optional.
eph_priv (EccKey):
The local ephemeral private key, generated for this session. Optional.
eph_pub (EccKey):
The ephemeral public key, received from the peer for this session. Optional.
At least two keys must be passed, of which one is a private key and one
a public key.
Returns (bytes):
The derived secret key material.
aEccKey
u'%s' must be an ECC key
has_private
u'%s' must be a private ECC key
u'%s' is defined on an incompatible curve
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.number
T along_to_bytes
uCrypto.PublicKey.ECC
T aEccKey
construct
a_import_curve25519_public_key
a_import_curve448_public_key
import_x25519_public_key
import_x25519_private_key
import_x448_public_key
import_x448_private_key
key_agreement
uCrypto\Protocol\DH.py
u<module Crypto.Protocol.DH>
T akey_priv
key_pub
pointP
wzT acurve
key
name
private
T aencoded
T aencoded
wxTakwargs
static_priv
static_pub
eph_priv
eph_pub
kdf
count_priv
count_pub
curve
check_curve
aZs
aZe
wZu
a__spec__
.Crypto.Protocol.KDF
7
aSHA1
tobytes
new
digest_size
uSelected hash algorithm has a too short digest (%d bytes).
uSalt is not 8 bytes long (%d bytes instead).
iter_range
pHash
digest
uDerive one key from a password (or passphrase).
This function performs key derivation according to an old version of
the PKCS#5 standard (v1.5) or `RFC2898
<https://www.ietf.org/rfc/rfc2898.txt>`_.
Args:
password (string):
The secret password to generate the key from.
salt (byte string):
An 8 byte string to use for better protection from dictionary attacks.
This value does not need to be kept secret, but it should be randomly
chosen for each derivation.
dkLen (integer):
The length of the desired key. The default is 16 bytes, suitable for
instance for :mod:`Crypto.Cipher.AES`.
count (integer):
The number of iterations to carry out. The recommendation is 1000 or
more.
hashAlgo (module):
The hash algorithm to use, as a module or an object from the :mod:`Crypto.Hash` package.
The digest length must be no shorter than ``dkLen``.
The default algorithm is :mod:`Crypto.Hash.SHA1`.
Return:
A byte string of length ``dkLen`` that can be used as key.
u'prf' and 'hmac_hash_module' are mutually exlusive
hmac_hash_module
a_pbkdf2_hmac_assist
u<lambda>
uPBKDF2.<locals>.<lambda>
link
uPBKDF2.<locals>.link
c
key
prf
password
salt
struct
pack
u>I
wil areduce
strxor
aHMAC
copy
update
count
uDerive one or more keys from a password (or passphrase).
This function performs key derivation according to the PKCS#5 standard (v2.0).
Args:
password (string or byte string):
The secret password to generate the key from.
Strings will be encoded as ISO 8859-1 (also known as Latin-1),
which does not allow any characters with codepoints > 255.
salt (string or byte string):
A (byte) string to use for better protection from dictionary attacks.
This value does not need to be kept secret, but it should be randomly
chosen for each derivation. It is recommended to use at least 16 bytes.
Strings will be encoded as ISO 8859-1 (also known as Latin-1),
which does not allow any characters with codepoints > 255.
dkLen (integer):
The cumulative length of the keys to produce.
Due to a flaw in the PBKDF2 design, you should not request more bytes
than the ``prf`` can output. For instance, ``dkLen`` should not exceed
20 bytes in combination with ``HMAC-SHA1``.
count (integer):
The number of iterations to carry out. The higher the value, the slower
nd the more secure the function becomes.
You should find the maximum number of iterations that keeps the
key derivation still acceptable on the slowest hardware you must support.
Although the default value is 1000, **it is recommended to use at least
1000000 (1 million) iterations**.
prf (callable):
A pseudorandom function. It must be a function that returns a
pseudorandom byte string from two parameters: a secret and a salt.
The slower the algorithm, the more secure the derivation function.
If not specified, **HMAC-SHA1** is used.
hmac_hash_module (module):
A module from ``Crypto.Hash`` implementing a Merkle-Damgard cryptographic
hash, which PBKDF2 must use in combination with HMAC.
This parameter is mutually exclusive with ``prf``.
Return:
A byte string of length ``dkLen`` that can be used as key material.
If you want multiple keys, just break up this string into segments of the desired length.
wsu<genexpr>
uPBKDF2.<locals>.<genexpr>
a_copy_bytes
a_key
a_ciphermod
d
block_size
a_last_string
a_cache
l a_n_updates
a_cipher_params
uInitialize the S2V PRF.
:Parameters:
key : byte string
A secret that can be used as key for CMACs
based on ciphers from ``ciphermod``.
ciphermod : module
A block cipher module from `Crypto.Cipher`.
cipher_params : dictionary
A set of extra parameters to use to create a cipher instance.
a_S2V
uCreate a new S2V PRF.
:Parameters:
key : byte string
A secret that can be used as key for CMACs
based on ciphers from ``ciphermod``.
ciphermod : module
A block cipher module from `Crypto.Cipher`.
bytes_to_long
bord
l  l  along_to_bytes
uToo many components passed to S2V
aCMAC
T amsg
ciphermod
cipher_params
a_double
uPass the next component of the vector.
The maximum number of components you can pass is equal to the block
length of the cipher (in bits) minus 1.
:Parameters:
item : byte string
The next component of the vector.
:Raise TypeError: when the limit on the number of components has been reached.
:nq n:q nnd b
:nl nu"Derive a secret from the vector of components.
:Return: a byte string, as long as the block length of the cipher.
l  uToo much secret data to derive
T adigestmod
tlen
prk
wtacontext
wBwnahashmod
key_len
uDerive one or more keys from a master secret using
the HMAC-based KDF defined in RFC5869_.
Args:
master (byte string):
The unguessable value used by the KDF to generate the other keys.
It must be a high-entropy secret, though not necessarily uniform.
It must not be a password.
key_len (integer):
The length in bytes of every derived key.
salt (byte string):
A non-secret, reusable value that strengthens the randomness
extraction step.
Ideally, it is as long as the digest size of the chosen hash.
If empty, a string of zeroes in used.
hashmod (module):
A cryptographic hash algorithm from :mod:`Crypto.Hash`.
:mod:`Crypto.Hash.SHA512` is a good choice.
num_keys (integer):
The number of keys to derive. Every key is :data:`key_len` bytes long.
The maximum cumulative length of all keys is
255 times the digest size.
context (byte string):
Optional identifier describing what the keys are used for.
Return:
A byte string or a tuple of byte strings.
.. _RFC5869: http://tools.ietf.org/html/rfc5869
bit_size
uN must be a power of 2
g
uN is too big
g ?     up or r are too big
uscrypt.<locals>.<lambda>
aPBKDF2
T aprf
a_raw_scrypt_lib
scryptROMix
a_raw_salsa20_lib
aSalsa20_8_core
wracreate_string_buffer
c_size_t
wNacore
uError %X while running scrypt
data_out
get_raw_buffer
uDerive one or more keys from a passphrase.
Args:
password (string):
The secret pass phrase to generate the keys from.
salt (string):
A string to use for better protection from dictionary attacks.
This value does not need to be kept secret,
but it should be randomly chosen for each derivation.
It is recommended to be at least 16 bytes long.
key_len (integer):
The length in bytes of each derived key.
N (integer):
CPU/Memory cost parameter. It must be a power of 2 and less
than :math:`2^{32}`.
r (integer):
Block size parameter.
p (integer):
Parallelization parameter.
It must be no greater than :math:`(2^{32}-1)/(4r)`.
num_keys (integer):
The number of keys to derive. Every key is :data:`key_len` bytes long.
By default, only 1 key is generated.
The maximum cumulative length of all keys is :math:`(2^{32}-1)*32`
(that is, 128TB).
A good choice of parameters *(N, r , p)* was suggested
by Colin Percival in his `presentation in 2009`__:
- *( 2     , 8, 1 )* for interactive logins (   100ms)
- *( 2     , 8, 1 )* for file encryption (   5s)
Return:
A byte string or a tuple of byte strings.
.. __: http://www.tarsnap.com/scrypt/scrypt-slides.pdf
aSHA256
:l nnazfill
T l abits
bstr
l :nq naresult
u./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789

tostr
T l l uIncorrect length
:nq n:nq nabchr
uCrypto.Cipher
T a_EKSBlowfish
a_EKSBlowfish
uThe password is too long. It must be 72 bytes at most.
l ubcrypt cost factor must be in the range 4..31
aMODE_ECB
;l
l@l acipher
encrypt
ctext
uutf-8
find
T l
uThe password contains the zero byte
get_random_bytes
T l ubcrypt salt must be 16 bytes long
a_bcrypt_hash
cOrpheanBeholderScryDoubt
d$T l a_bcrypt_encode
c$2a
uHash a password into a key, using the OpenBSD bcrypt protocol.
Args:
password (byte string or string):
The secret password or pass phrase.
It must be at most 72 bytes long.
It must not contain the zero byte.
Unicode strings will be encoded as UTF-8.
cost (integer):
The exponential factor that makes it slower to compute the hash.
It must be in the range 4 to 31.
A value of at least 12 is recommended.
salt (byte string):
Optional. Random byte string to thwarts dictionary and rainbow table
ttacks. It must be 16 bytes long.
If not passed, a random value is generated.
Return (byte string):
The bcrypt hash
Raises:
ValueError: if password is longer than 72 bytes or if it contains the zero byte
uIncorrect length of the bcrypt hash: %d bytes instead of 60
:nl nc$2a$
uUnsupported prefix
re
compile
T c\$2a\$([0-9][0-9])\$([A-Za-z0-9./]{22,22})([A-Za-z0-9./]{31,31})
match
uIncorrect bcrypt hash format
group
T l uIncorrect cost
a_bcrypt_decode
bcrypt
aBLAKE2s
l  T adigest_bits
key
data
uIncorrect bcrypt hash
uVerify if the provided password matches the given bcrypt hash.
Args:
password (byte string or string):
The secret password or pass phrase to test.
It must be at most 72 bytes long.
It must not contain the zero byte.
Unicode strings will be encoded as UTF-8.
bcrypt_hash (byte string, bytearray):
The reference bcrypt hash the password needs to be checked against.
Raises:
ValueError: if the password does not match
T d
uNull byte found in context
dk
label
key_len_enc
master
g       uOverflow in SP800 108 counter
uDerive one or more keys from a master secret using
a pseudorandom function in Counter Mode, as specified in
`NIST SP 800-108r1 <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf>`_.
Args:
master (byte string):
The secret value used by the KDF to derive the other keys.
It must not be a password.
The length on the secret must be consistent with the input expected by
the :data:`prf` function.
key_len (integer):
The length in bytes of each derived key.
prf (function):
A pseudorandom function that takes two byte strings as parameters:
the secret and an input. It returns another byte string.
num_keys (integer):
The number of keys to derive. Every key is :data:`key_len` bytes long.
By default, only 1 key is derived.
label (byte string):
Optional description of the purpose of the derived keys.
It must not contain zero bytes.
context (byte string):
Optional information pertaining to
the protocol that uses the keys, such as the identity of the
participants, nonces, session IDs, etc.
It must not contain zero bytes.
Return:
- a byte string (if ``num_keys`` is not specified), or
- a tuple of byte strings (if ``num_key`` is specified).
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T atobytes
bord
a_copy_bytes
iter_range
tostr
bchr
bstr
uCrypto.Hash
T aSHA1
aSHA256
aHMAC
aCMAC
aBLAKE2s
uCrypto.Util.strxor
T astrxor
uCrypto.Random
T aget_random_bytes
uCrypto.Util.number
T asize
long_to_bytes
bytes_to_long
size
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
create_string_buffer
get_raw_buffer
c_size_t
load_pycryptodome_raw_lib
T uCrypto.Cipher._Salsa20

int Salsa20_8_core(const uint8_t *x, const uint8_t *y,
uint8_t *out);
T uCrypto.Protocol._scrypt

typedef int (core_t)(const uint8_t [64], const uint8_t [64], uint8_t [64]);
int scryptROMix(const uint8_t *data_in, uint8_t *data_out,
size_t data_len, unsigned N, core_t *core);
T l  naPBKDF1
T l l  nnT Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
