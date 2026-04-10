# Reconstructed from integrated Nuitka blob
# Module: uecdsa.errors

uRaised in case the encoding of private or public key is malformed.
a__qualname__
a__orig_bases__
uecdsa\errors.py
u<module ecdsa.errors>

a__spec__
.ecdsa.keys
` abaselen
aBadDigestError
uthis curve ({0}) is too short for the length of your digest ({1})
name
l astring_to_number
digest
bit_length
curve
order
max
uTruncates and converts digest to an integer.
uPlease use VerifyingKey.generate() to construct me
default_hashfunc
pubkey
uUnsupported, please use one of the classmethods to initialise.
to_string
T acompressed
aNone
uVerifyingKey.from_string({0!r}, {1!r}, {2})
aVerifyingKey
uReturn True if the points are identical, False otherwise.
uReturn False if the points are identical, True otherwise.
T tT a_error__please_use_generate
aCurveEdTw
uMethod incompatible with Edwards curves
ellipticcurve
aPointJacobi
from_affine
ecdsa
aPublic_key
generator
aInvalidPointError
aMalformedPointError
T uPoint does not lay on the curve

Initialise the object from a Point object.
This is a low-level method, generally you will not want to use it.
:param point: The point to wrap around, the actual public key
:type point: ~ecdsa.ellipticcurve.AbstractPoint
:param curve: The curve on which the point needs to reside, defaults
to NIST192p
:type curve: ~ecdsa.curves.Curve
:param hashfunc: The default hash function that will be used for
verification, needs to implement the same interface
s :py:class:`hashlib.sha1`
:type hashfunc: callable
:type bool validate_point: whether to check if the point lays on curve
should always be used if the public point is not a result
of our own calculation
:raises MalformedPointError: if the public point does not lay on the
curve
:return: Initialised VerifyingKey object
:rtype: VerifyingKey
point
aPointEdwards
wxwyD agenerator
tl u
Precompute multiplication tables for faster signature verification.
Calling this method will cause the library to precompute the
scalar multiplication tables, used in signature verification.
While it's an expensive operation (comparable to performing
s many signatures as the bit size of the curve, i.e. 256 for NIST256p)
it speeds up verification 2 times. You should call this method
if you expect to verify hundreds of signatures (or more) using the same
VerifyingKey object.
Note: You should call this method only once, this method generates a
new precomputation table every time it's called.
:param bool lazy: whether to calculate the precomputation table now
(if set to False) or if it should be delayed to the time of first
use (when set to True)
eddsa
aPublicKey
T uMalformed point for the curve
from_bytes
T avalidate_encoding
valid_encodings
from_public_point

Initialise the object from byte encoding of public key.
The method does accept and automatically detect the type of point
encoding used. It supports the :term:`raw encoding`,
:term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.
It also works with the native encoding of Ed25519 and Ed448 public
keys (technically those are compressed, but encoded differently than
in other signature systems).
Note, while the method is named "from_string" it's a misnomer from
Python 2 days when there were no binary strings. In Python 3 the
input needs to be a bytes-like object.
:param string: single point encoding of the public key
:type string: :term:`bytes-like object`
:param curve: the curve on which the public key is expected to lay
:type curve: ~ecdsa.curves.Curve
:param hashfunc: The default hash function that will be used for
verification, needs to implement the same interface as
hashlib.sha1. Ignored for EdDSA.
:type hashfunc: callable
:param validate_point: whether to verify that the point lays on the
provided curve or not, defaults to True. Ignored for EdDSA.
:type validate_point: bool
:param valid_encodings: list of acceptable point encoding formats,
supported ones are: :term:`uncompressed`, :term:`compressed`,
:term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
name). All formats by default (specified with ``None``).
Ignored for EdDSA.
:type valid_encodings: :term:`set-like object`
:raises MalformedPointError: if the public point does not lay on the
curve or the encoding is invalid
:return: Initialised VerifyingKey object
:rtype: VerifyingKey
from_der
der
unpem
T ahashfunc
valid_encodings
valid_curve_encodings

Initialise from public key stored in :term:`PEM` format.
The PEM header of the key should be ``BEGIN PUBLIC KEY``.
See the :func:`~VerifyingKey.from_der()` method for details of the
format supported.
Note: only a single PEM object decoding is supported in provided
string.
:param string: text with PEM-encoded public ECDSA key
:type string: str
:param valid_encodings: list of allowed point encodings.
By default :term:`uncompressed`, :term:`compressed`, and
:term:`hybrid`. To read malformed files, include
:term:`raw encoding` with ``raw`` in the list.
:type valid_encodings: :term:`set-like object`
:param valid_curve_encodings: list of allowed encoding formats
for curve parameters. By default (``None``) all are supported:
``named_curve`` and ``explicit``.
:type valid_curve_encodings: :term:`set-like object`
:return: Initialised VerifyingKey object
:rtype: VerifyingKey
S ahybrid
uncompressed
compressed
normalise_bytes
remove_sequence
c
aUnexpectedDER
utrailing junk after DER pubkey: %s
binascii
hexlify
remove_object
aEd25519
oid
aEd448
remove_bitstring
T utrailing junk after public key
from_string
oid_ecPublicKey
uUnexpected object identifier in DER encoding: {0!r}
aCurve
utrailing junk after pubkey pointstring: %s
verifying_key_length
T uMalformed encoding of public point
T ahashfunc
valid_encodings

Initialise the key stored in :term:`DER` format.
The expected format of the key is the SubjectPublicKeyInfo structure
from RFC5912 (for RSA keys, it's known as the PKCS#1 format)::
SubjectPublicKeyInfo {PUBLIC-KEY: IOSet} ::= SEQUENCE {
lgorithm        AlgorithmIdentifier {PUBLIC-KEY, {IOSet}},
subjectPublicKey BIT STRING
}
Note: only public EC keys are supported by this method. The
SubjectPublicKeyInfo.algorithm.algorithm field must specify
id-ecPublicKey (see RFC3279).
Only the named curve encoding is supported, thus the
SubjectPublicKeyInfo.algorithm.parameters field needs to be an
object identifier. A sequence in that field indicates an explicit
parameter curve encoding, this format is not supported. A NULL object
in that field indicates an "implicitlyCA" encoding, where the curve
parameters come from CA certificate, those, again, are not supported.
:param string: binary string with the DER encoding of public ECDSA key
:type string: bytes-like object
:param valid_encodings: list of allowed point encodings.
By default :term:`uncompressed`, :term:`compressed`, and
:term:`hybrid`. To read malformed files, include
:term:`raw encoding` with ``raw`` in the list.
:type valid_encodings: :term:`set-like object`
:param valid_curve_encodings: list of allowed encoding formats
for curve parameters. By default (``None``) all are supported:
``named_curve`` and ``explicit``.
:type valid_curve_encodings: :term:`set-like object`
:return: Initialised VerifyingKey object
:rtype: VerifyingKey
uMethod unsupported for Edwards curves
from_public_key_recovery_with_digest
T ahashfunc
sigdecode
allow_truncate

Return keys that can be used as verifiers of the provided signature.
Tries to recover the public key that can be used to verify the
signature, usually returns two keys like that.
:param signature: the byte string with the encoded signature
:type signature: bytes-like object
:param data: the data to be hashed for signature verification
:type data: bytes-like object
:param curve: the curve over which the signature was performed
:type curve: ~ecdsa.curves.Curve
:param hashfunc: The default hash function that will be used for
verification, needs to implement the same interface as hashlib.sha1
:type hashfunc: callable
:param sigdecode: Callable to define the way the signature needs to
be decoded to an object, needs to handle `signature` as the
first parameter, the curve order (an int) as the second and return
a tuple with two integers, "r" as the first one and "s" as the
second one. See :func:`ecdsa.util.sigdecode_string` and
:func:`ecdsa.util.sigdecode_der` for examples.
:param bool allow_truncate: if True, the provided hashfunc can generate
values larger than the bit size of the order of the curve, the
extra bits (at the end of the digest) will be truncated.
:type sigdecode: callable
:return: Initialised VerifyingKey objects
:rtype: list of VerifyingKey
aSignature
a_truncate_and_convert_digest
recover_public_keys
cls
hashfunc

Return keys that can be used as verifiers of the provided signature.
Tries to recover the public key that can be used to verify the
signature, usually returns two keys like that.
:param signature: the byte string with the encoded signature
:type signature: bytes-like object
:param digest: the hash value of the message signed by the signature
:type digest: bytes-like object
:param curve: the curve over which the signature was performed
:type curve: ~ecdsa.curves.Curve
:param hashfunc: The default hash function that will be used for
verification, needs to implement the same interface as hashlib.sha1
:type hashfunc: callable
:param sigdecode: Callable to define the way the signature needs to
be decoded to an object, needs to handle `signature` as the
first parameter, the curve order (an int) as the second and return
a tuple with two integers, "r" as the first one and "s" as the
second one. See :func:`ecdsa.util.sigdecode_string` and
:func:`ecdsa.util.sigdecode_der` for examples.
:type sigdecode: callable
:param bool allow_truncate: if True, the provided hashfunc can generate
values larger than the bit size of the order of the curve (and
the length of provided `digest`), the extra bits (at the end of the
digest) will be truncated.
:return: Initialised VerifyingKey object
:rtype: VerifyingKey
T araw
uncompressed
compressed
hybrid
to_bytes

Convert the public key to a byte string.
The method by default uses the :term:`raw encoding` (specified
by `encoding="raw"`. It can also output keys in :term:`uncompressed`,
:term:`compressed` and :term:`hybrid` formats.
Remember that the curve identification is not part of the encoding
so to decode the point using :func:`~VerifyingKey.from_string`, curve
needs to be specified.
Note: while the method is called "to_string", it's a misnomer from
Python 2 days when character strings and byte strings shared type.
On Python 3 the returned type will be `bytes`.
:return: :term:`raw encoding` of the public key (public point) on the
curve
:rtype: bytes
topem
to_der
uPUBLIC KEY

Convert the public key to the :term:`PEM` format.
The PEM header of the key will be ``BEGIN PUBLIC KEY``.
The format of the key is described in the
:func:`~VerifyingKey.from_der()` method.
This method supports only "named curve" encoding of keys.
:param str point_encoding: specification of the encoding format
of public keys. "uncompressed" is most portable, "compressed" is
smallest. "hybrid" is uncommon and unsupported by most
implementations, it is as big as "uncompressed".
:param str curve_parameters_encoding: the encoding for curve parameters
to use, by default tries to use ``named_curve`` encoding,
if that is not possible, falls back to ``explicit`` encoding.
:return: portable encoding of the public key
:rtype: bytes
.. warning:: The PEM is encoded to US-ASCII, it needs to be
re-encoded if the system is incompatible (e.g. uses UTF-16)
raw
uraw point_encoding not allowed in DER
encode_sequence
encode_oid
encode_bitstring
encoded_oid_ecPublicKey

Convert the public key to the :term:`DER` format.
The format of the key is described in the
:func:`~VerifyingKey.from_der()` method.
This method supports only "named curve" encoding of keys.
:param str point_encoding: specification of the encoding format
of public keys. "uncompressed" is most portable, "compressed" is
smallest. "hybrid" is uncommon and unsupported by most
implementations, it is as big as "uncompressed".
:param str curve_parameters_encoding: the encoding for curve parameters
to use, by default tries to use ``named_curve`` encoding,
if that is not possible, falls back to ``explicit`` encoding.
:return: DER encoding of the public key
:rtype: bytes
ssh
serialize_public

Convert the public key to the SSH format.
:return: SSH encoding of the public key
:rtype: bytes
verify
aBadSignatureError
uSignature verification failed
verify_digest

Verify a signature made over provided data.
Will hash `data` to verify the signature.
By default expects signature in :term:`raw encoding`. Can also be used
to verify signatures in ASN.1 DER encoding by using
:func:`ecdsa.util.sigdecode_der`
s the `sigdecode` parameter.
:param signature: encoding of the signature
:type signature: sigdecode method dependent
:param data: data signed by the `signature`, will be hashed using
`hashfunc`, if specified, or default hash function
:type data: :term:`bytes-like object`
:param hashfunc: The default hash function that will be used for
verification, needs to implement the same interface as hashlib.sha1
:type hashfunc: callable
:param sigdecode: Callable to define the way the signature needs to
be decoded to an object, needs to handle `signature` as the
first parameter, the curve order (an int) as the second and return
a tuple with two integers, "r" as the first one and "s" as the
second one. See :func:`ecdsa.util.sigdecode_string` and
:func:`ecdsa.util.sigdecode_der` for examples.
:type sigdecode: callable
:param bool allow_truncate: if True, the provided digest can have
bigger bit-size than the order of the curve, the extra bits (at
the end of the digest) will be truncated. Use it when verifying
SHA-384 output using NIST256p or in similar situations. Defaults to
True.
:raises BadSignatureError: if the signature is invalid or malformed
:return: True if the verification was successful
:rtype: bool
aMalformedSignature
uMalformed formatting of signature
verifies
T uSignature verification failed

Verify a signature made over provided hash value.
By default expects signature in :term:`raw encoding`. Can also be used
to verify signatures in ASN.1 DER encoding by using
:func:`ecdsa.util.sigdecode_der`
s the `sigdecode` parameter.
:param signature: encoding of the signature
:type signature: sigdecode method dependent
:param digest: raw hash value that the signature authenticates.
:type digest: :term:`bytes-like object`
:param sigdecode: Callable to define the way the signature needs to
be decoded to an object, needs to handle `signature` as the
first parameter, the curve order (an int) as the second and return
a tuple with two integers, "r" as the first one and "s" as the
second one. See :func:`ecdsa.util.sigdecode_string` and
:func:`ecdsa.util.sigdecode_der` for examples.
:type sigdecode: callable
:param bool allow_truncate: if True, the provided digest can have
bigger bit-size than the order of the curve, the extra bits (at
the end of the digest) will be truncated. Use it when verifying
SHA-384 output using NIST256p or in similar situations.
:raises BadSignatureError: if the signature is invalid or malformed
:raises BadDigestError: if the provided digest is too big for the curve
ssociated with this VerifyingKey and allow_truncate was not set
:return: True if the verification was successful
:rtype: bool
uPlease use SigningKey.generate() to construct me
verifying_key
privkey
aSigningKey
urandom
aPrivateKey
public_key
uGenerate a private key on a Twisted Edwards curve.
randrange
from_secret_exponent
uGenerate a private key on a Weierstrass curve.
a_twisted_edwards_keygen
a_weierstrass_keygen

Generate a random private key.
:param curve: The curve on which the point needs to reside, defaults
to NIST192p
:type curve: ~ecdsa.curves.Curve
:param entropy: Source of randomness for generating the private keys,
should provide cryptographically secure random numbers if the keys
need to be secure. Uses os.urandom() by default.
:type entropy: callable
:param hashfunc: The default hash function that will be used for
signing, needs to implement the same interface
s hashlib.sha1
:type hashfunc: callable
:return: Initialised SigningKey object
:rtype: SigningKey
uEdwards keys don't support setting the secret scalar (exponent) directly
uInvalid value for secexp, expected integer between 1 and {0}
scale
aPrivate_key

Create a private key from a random integer.
Note: it's a low level method, it's recommended to use the
:func:`~SigningKey.generate` method to create private keys.
:param int secexp: secret multiplier (the actual private key in ECDSA).
Needs to be an integer between 1 and the curve order.
:param curve: The curve on which the point needs to reside
:type curve: ~ecdsa.curves.Curve
:param hashfunc: The default hash function that will be used for
signing, needs to implement the same interface
s hashlib.sha1
:type hashfunc: callable
:raises MalformedPointError: when the provided secexp is too large
or too small for the curve selected
:raises RuntimeError: if the generation of public key from private
key failed
:return: Initialised SigningKey object
:rtype: SigningKey
uInvalid length of private key, received {0}, expected {1}

Decode the private key from :term:`raw encoding`.
Note: the name of this method is a misnomer coming from days of
Python 2, when binary strings and character strings shared a type.
In Python 3, the expected type is `bytes`.
:param string: the raw encoding of the private key
:type string: :term:`bytes-like object`
:param curve: The curve on which the point needs to reside
:type curve: ~ecdsa.curves.Curve
:param hashfunc: The default hash function that will be used for
signing, needs to implement the same interface
s hashlib.sha1
:type hashfunc: callable
:raises MalformedPointError: if the length of encoding doesn't match
the provided curve or the encoded values is too large
:raises RuntimeError: if the generation of public key from private
key failed
:return: Initialised SigningKey object
:rtype: SigningKey
aPY2
encode
find
T c-----BEGIN EC PRIVATE KEY-----
index
T c-----BEGIN PRIVATE KEY-----

Initialise from key stored in :term:`PEM` format.
The PEM formats supported are the un-encrypted RFC5915
(the ssleay format) supported by OpenSSL, and the more common
un-encrypted RFC5958 (the PKCS #8 format).
The legacy format files have the header with the string
``BEGIN EC PRIVATE KEY``.
PKCS#8 files have the header ``BEGIN PRIVATE KEY``.
Encrypted files (ones that include the string
``Proc-Type: 4,ENCRYPTED``
right after the PEM header) are not supported.
See :func:`~SigningKey.from_der` for ASN.1 syntax of the objects in
this files.
:param string: text with PEM-encoded private ECDSA key
:type string: str
:param valid_curve_encodings: list of allowed encoding formats
for curve parameters. By default (``None``) all are supported:
``named_curve`` and ``explicit``.
:type valid_curve_encodings: :term:`set-like object`
:raises MalformedPointError: if the length of encoding doesn't match
the provided curve or the encoded values is too large
:raises RuntimeError: if the generation of public key from private
key failed
:raises UnexpectedDER: if the encoding of the PEM file is incorrect
:return: Initialised SigningKey object
:rtype: SigningKey
utrailing junk after DER privkey: %s
remove_integer
is_sequence
T l
l uexpected version '0' or '1' at start of privkey, got %d
T uNon NULL parameters for a EdDSA key
remove_octet_string
T utrailing junk after the encoded private key
oid_ecDH
oid_ecMQV
uunexpected algorithm identifier '%s'
uexpected version '1' at start of DER privkey, got %d
wsaremove_constructed
uexpected tag 0 in DER privkey, got %d
d
privkey_str

Initialise from key stored in :term:`DER` format.
The DER formats supported are the un-encrypted RFC5915
(the ssleay format) supported by OpenSSL, and the more common
un-encrypted RFC5958 (the PKCS #8 format).
Both formats contain an ASN.1 object following the syntax specified
in RFC5915::
ECPrivateKey ::= SEQUENCE {
version        INTEGER { ecPrivkeyVer1(1) }} (ecPrivkeyVer1),
privateKey     OCTET STRING,
parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
publicKey  [1] BIT STRING OPTIONAL
}
`publicKey` field is ignored completely (errors, if any, in it will
be undetected).
Two formats are supported for the `parameters` field: the named
curve and the explicit encoding of curve parameters.
In the legacy ssleay format, this implementation requires the optional
`parameters` field to get the curve name. In PKCS #8 format, the curve
is part of the PrivateKeyAlgorithmIdentifier.
The PKCS #8 format includes an ECPrivateKey object as the `privateKey`
field within a larger structure::
OneAsymmetricKey ::= SEQUENCE {
version                   Version,
privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
privateKey                PrivateKey,
ttributes            [0] Attributes OPTIONAL,
...,
[[2: publicKey        [1] PublicKey OPTIONAL ]],
...
}
The `attributes` and `publicKey` fields are completely ignored; errors
in them will not be detected.
:param string: binary string with DER-encoded private ECDSA key
:type string: :term:`bytes-like object`
:param valid_curve_encodings: list of allowed encoding formats
for curve parameters. By default (``None``) all are supported:
``named_curve`` and ``explicit``.
Ignored for EdDSA.
:type valid_curve_encodings: :term:`set-like object`
:raises MalformedPointError: if the length of encoding doesn't match
the provided curve or the encoded values is too large
:raises RuntimeError: if the generation of public key from private
key failed
:raises UnexpectedDER: if the encoding of the DER file is incorrect
:return: Initialised SigningKey object
:rtype: SigningKey
private_key
secret_multiplier
number_to_string

Convert the private key to :term:`raw encoding`.
Note: while the method is named "to_string", its name comes from
Python 2 days, when binary and character strings used the same type.
The type used in Python 3 is `bytes`.
:return: raw encoding of private key
:rtype: bytes
T assleay
pkcs8
ssleay
uEC PRIVATE KEY
uPRIVATE KEY

Convert the private key to the :term:`PEM` format.
See :func:`~SigningKey.from_pem` method for format description.
Only the named curve format is supported.
The public key will be included in generated string.
The PEM header will specify ``BEGIN EC PRIVATE KEY`` or
``BEGIN PRIVATE KEY``, depending on the desired format.
:param str point_encoding: format to use for encoding public point
:param str format: either ``ssleay`` (default) or ``pkcs8``
:param str curve_parameters_encoding: format of encoded curve
parameters, default depends on the curve, if the curve has
n associated OID, ``named_curve`` format will be used,
if no OID is associated with the curve, the fallback of
``explicit`` parameters will be used.
:return: PEM encoded private key
:rtype: bytes
.. warning:: The PEM is encoded to US-ASCII, it needs to be
re-encoded if the system is incompatible (e.g. uses UTF-16)
encode_octet_string
encode_integer
T l
uCreate a PKCS#8 encoding of EdDSA keys.
uraw encoding not allowed in DER
pkcs8
uOnly PKCS#8 format supported for EdDSA keys
a_encode_eddsa
get_verifying_key
T l aencode_constructed

Convert the private key to the :term:`DER` format.
See :func:`~SigningKey.from_der` method for format specification.
Only the named curve format is supported.
The public key will be included in the generated string.
:param str point_encoding: format to use for encoding public point
Ignored for EdDSA
:param str format: either ``ssleay`` (default) or ``pkcs8``.
EdDSA keys require ``pkcs8``.
:param str curve_parameters_encoding: format of encoded curve
parameters, default depends on the curve, if the curve has
n associated OID, ``named_curve`` format will be used,
if no OID is associated with the curve, the fallback of
``explicit`` parameters will be used.
Ignored for EdDSA.
:return: DER encoded private key
:rtype: bytes
serialize_private

Convert the private key to the SSH format.
:return: SSH encoded private key
:rtype: bytes

Return the VerifyingKey associated with this private key.
Equivalent to reading the `verifying_key` field of an instance.
:return: a public key that can be used to verify the signatures made
with this SigningKey
:rtype: VerifyingKey
sign
sign_digest_deterministic
T ahashfunc
sigencode
extra_entropy
allow_truncate

Create signature over data.
For Weierstrass curves it uses the deterministic RFC6979 algorithm.
For Edwards curves it uses the standard EdDSA algorithm.
For ECDSA the data will be hashed using the `hashfunc` function before
signing.
For EdDSA the data will be hashed with the hash associated with the
curve (SHA-512 for Ed25519 and SHAKE-256 for Ed448).
This is the recommended method for performing signatures when hashing
of data is necessary.
:param data: data to be hashed and computed signature over
:type data: :term:`bytes-like object`
:param hashfunc: hash function to use for computing the signature,
if unspecified, the default hash function selected during
object initialisation will be used (see
`VerifyingKey.default_hashfunc`). The object needs to implement
the same interface as hashlib.sha1.
Ignored with EdDSA.
:type hashfunc: callable
:param sigencode: function used to encode the signature.
The function needs to accept three parameters: the two integers
that are the signature and the order of the curve over which the
signature was computed. It needs to return an encoded signature.
See `ecdsa.util.sigencode_string` and `ecdsa.util.sigencode_der`
s examples of such functions.
Ignored with EdDSA.
:type sigencode: callable
:param extra_entropy: additional data that will be fed into the random
number generator used in the RFC6979 process. Entirely optional.
Ignored with EdDSA.
:type extra_entropy: :term:`bytes-like object`
:return: encoded signature over `data`
:rtype: bytes or sigencode function dependent type
simple_r_s
uSigningKey.sign_digest_deterministic.<locals>.simple_r_s
rfc6979
generate_k
self
secexp
retry_gen
extra_entropy
T aretry_gen
extra_entropy
sign_digest
allow_truncate
T asigencode
wkaallow_truncate
aRSZeroError

Create signature for digest using the deterministic RFC6979 algorithm.
`digest` should be the output of cryptographically secure hash function
like SHA256 or SHA-3-256.
This is the recommended method for performing signatures when no
hashing of data is necessary.
:param digest: hash of data that will be signed
:type digest: :term:`bytes-like object`
:param hashfunc: hash function to use for computing the random "k"
value from RFC6979 process,
if unspecified, the default hash function selected during
object initialisation will be used (see
:attr:`.VerifyingKey.default_hashfunc`). The object needs to
implement
the same interface as :func:`~hashlib.sha1` from :py:mod:`hashlib`.
:type hashfunc: callable
:param sigencode: function used to encode the signature.
The function needs to accept three parameters: the two integers
that are the signature and the order of the curve over which the
signature was computed. It needs to return an encoded signature.
See :func:`~ecdsa.util.sigencode_string` and
:func:`~ecdsa.util.sigencode_der`
s examples of such functions.
:type sigencode: callable
:param extra_entropy: additional data that will be fed into the random
number generator used in the RFC6979 process. Entirely optional.
:type extra_entropy: :term:`bytes-like object`
:param bool allow_truncate: if True, the provided digest can have
bigger bit-size than the order of the curve, the extra bits (at
the end of the digest) will be truncated. Use it when signing
SHA-384 output using NIST256p or in similar situations.
:return: encoded signature for the `digest` hash
:rtype: bytes or sigencode function dependent type
sign_deterministic

Create signature over data.
Uses the probabilistic ECDSA algorithm for Weierstrass curves
(NIST256p, etc.) and the deterministic EdDSA algorithm for the
Edwards curves (Ed25519, Ed448).
This method uses the standard ECDSA algorithm that requires a
cryptographically secure random number generator.
It's recommended to use the :func:`~SigningKey.sign_deterministic`
method instead of this one.
:param data: data that will be hashed for signing
:type data: :term:`bytes-like object`
:param callable entropy: randomness source, :func:`os.urandom` by
default. Ignored with EdDSA.
:param hashfunc: hash function to use for hashing the provided
``data``.
If unspecified the default hash function selected during
object initialisation will be used (see
:attr:`.VerifyingKey.default_hashfunc`).
Should behave like :func:`~hashlib.sha1` from :py:mod:`hashlib`.
The output length of the
hash (in bytes) must not be longer than the length of the curve
order (rounded up to the nearest byte), so using SHA256 with
NIST256p is ok, but SHA256 with NIST192p is not. (In the 2**-96ish
unlikely event of a hash output larger than the curve order, the
hash will effectively be wrapped mod n).
If you want to explicitly allow use of large hashes with small
curves set the ``allow_truncate`` to ``True``.
Use ``hashfunc=hashlib.sha1`` to match openssl's
``-ecdsa-with-SHA1`` mode,
or ``hashfunc=hashlib.sha256`` for openssl-1.0.0's
``-ecdsa-with-SHA256``.
Ignored for EdDSA
:type hashfunc: callable
:param sigencode: function used to encode the signature.
The function needs to accept three parameters: the two integers
that are the signature and the order of the curve over which the
signature was computed. It needs to return an encoded signature.
See :func:`~ecdsa.util.sigencode_string` and
:func:`~ecdsa.util.sigencode_der`
s examples of such functions.
Ignored for EdDSA
:type sigencode: callable
:param int k: a pre-selected nonce for calculating the signature.
In typical use cases, it should be set to None (the default) to
llow its generation from an entropy source.
Ignored for EdDSA.
:param bool allow_truncate: if ``True``, the provided digest can have
bigger bit-size than the order of the curve, the extra bits (at
the end of the digest) will be truncated. Use it when signing
SHA-384 output using NIST256p or in similar situations. True by
default.
Ignored for EdDSA.
:raises RSZeroError: in the unlikely event when *r* parameter or
*s* parameter of the created signature is equal 0, as that would
leak the key. Caller should try a better entropy source, retry with
different ``k``, or use the
:func:`~SigningKey.sign_deterministic` in such case.
:return: encoded signature of the hash of `data`
:rtype: bytes or sigencode function dependent type
sign_number

Create signature over digest using the probabilistic ECDSA algorithm.
This method uses the standard ECDSA algorithm that requires a
cryptographically secure random number generator.
This method does not hash the input.
It's recommended to use the
:func:`~SigningKey.sign_digest_deterministic` method
instead of this one.
:param digest: hash value that will be signed
:type digest: :term:`bytes-like object`
:param callable entropy: randomness source, os.urandom by default
:param sigencode: function used to encode the signature.
The function needs to accept three parameters: the two integers
that are the signature and the order of the curve over which the
signature was computed. It needs to return an encoded signature.
See `ecdsa.util.sigencode_string` and `ecdsa.util.sigencode_der`
s examples of such functions.
:type sigencode: callable
:param int k: a pre-selected nonce for calculating the signature.
In typical use cases, it should be set to None (the default) to
llow its generation from an entropy source.
:param bool allow_truncate: if True, the provided digest can have
bigger bit-size than the order of the curve, the extra bits (at
the end of the digest) will be truncated. Use it when signing
SHA-384 output using NIST256p or in similar situations.
:raises RSZeroError: in the unlikely event when "r" parameter or
"s" parameter of the created signature is equal 0, as that would
leak the key. Caller should try a better entropy source, retry with
different 'k', or use the
:func:`~SigningKey.sign_digest_deterministic` in such case.
:return: encoded signature for the `digest` hash
:rtype: bytes or sigencode function dependent type
wru
Sign an integer directly.
Note, this is a low level method, usually you will want to use
:func:`~SigningKey.sign_deterministic` or
:func:`~SigningKey.sign_digest_deterministic`.
:param int number: number to sign using the probabilistic ECDSA
lgorithm.
:param callable entropy: entropy source, os.urandom by default
:param int k: pre-selected nonce for signature operation. If unset
it will be selected at random using the entropy source.
:raises RSZeroError: in the unlikely event when "r" parameter or
"s" parameter of the created signature is equal 0, as that would
leak the key. Caller should try a better entropy source, retry with
different 'k', or use the
:func:`~SigningKey.sign_digest_deterministic` in such case.
:return: the "r" and "s" parameters of the signature
:rtype: tuple of ints

Primary classes for performing signing and verification operations.
a__doc__
a__file__
origin
has_location
a__cached__
hashlib
T asha1
sha1
os
six
T aPY2

T aecdsa
eddsa
T ader
ssh
T arfc6979
T aellipticcurve
curves
T aNIST192p
aCurve
aEd25519
aEd448
aNIST192p
T aRSZeroError
util
T astring_to_number
number_to_string
randrange
T asigencode_string
sigdecode_string
bit_length
sigencode_string
sigdecode_string
T aoid_ecPublicKey
encoded_oid_ecPublicKey
oid_ecDH
oid_ecMQV
aMalformedSignature
a_compat
T anormalise_bytes
errors
T aMalformedPointError
T aPointJacobi
aCurveEdTw
L aBadSignatureError
aBadDigestError
aVerifyingKey
aSigningKey
aMalformedPointError
a__all__
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
