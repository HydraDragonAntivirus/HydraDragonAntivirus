# Reconstructed from integrated Nuitka blob
# Module: uecdsa.ssh

a__qualname__
a__init__
u_Serializer.__init__
u_Serializer.put_raw
u_Serializer.put_u32
u_Serializer.put_str
T l u_Serializer.put_pad
u_Serializer.encode
u_Serializer.tobytes
u_Serializer.topem
serialize_public
serialize_private
uecdsa\ssh.py
u<module ecdsa.ssh>
T aself
T aname
T aself
blklen
padlen
T aself
val
Taname
pub
priv
spub
ktype
spriv
checksum
comment
main
ciphername
kdfname
nokdf
nkeys
T aname
pub
serial
ktype
a__spec__
.ecdsa.util
s'
from_bytes
big
:l nnazfill
l uConvert a bytestring to string of 0's and 1's
bit_length
u%x
l aurandom
entropy
upper_256
entropy_to_bits
uReturn a random integer k such that 1 <= k < order, uniformly
distributed across that range. Worst case should be a mean of 2 loops at
(2**k)+2.
Note that this function is not declared to be forwards-compatible: we may
change the behavior in future releases. The entropy= argument (which
should get a callable that behaves like os.urandom) can be used to
chieve stability within a given release (for repeatable unit tests), but
should not be used as a long-term-compatible key generation algorithm.
block_generator
generator
anext
self
aPY2

sha256
uprng-%d-%s
counter
seed
digest
uPRNG.block_generator
aPRNG
orderlen
binascii
hexlify
l amath
log
bits_and_bytes
w
l aint2byte
lsb_of_ones
:l nnc
extrabits
generate
T l astring_to_number
bytes
u%0
wxaunhexlify
encode
number_to_string

Encode the signature to a pair of strings in a tuple
Encodes signature into raw encoding (:term:`raw encoding`) with the
``r`` and ``s`` parts of the signature encoded separately.
It's expected that this function will be used as a ``sigencode=`` parameter
in :func:`ecdsa.keys.SigningKey.sign` method.
:param int r: first parameter of the signature
:param int s: second parameter of the signature
:param int order: the order of the curve over which the signature was
computed
:return: raw encoding of ECDSA signature
:rtype: tuple(bytes, bytes)
sigencode_strings

Encode the signature to raw format (:term:`raw encoding`)
It's expected that this function will be used as a ``sigencode=`` parameter
in :func:`ecdsa.keys.SigningKey.sign` method.
:param int r: first parameter of the signature
:param int s: second parameter of the signature
:param int order: the order of the curve over which the signature was
computed
:return: raw encoding of ECDSA signature
:rtype: bytes
der
encode_sequence
encode_integer

Encode the signature into the ECDSA-Sig-Value structure using :term:`DER`.
Encodes the signature to the following :term:`ASN.1` structure::
Ecdsa-Sig-Value ::= SEQUENCE {
r       INTEGER,
s       INTEGER
}
It's expected that this function will be used as a ``sigencode=`` parameter
in :func:`ecdsa.keys.SigningKey.sign` method.
:param int r: first parameter of the signature
:param int s: second parameter of the signature
:param int order: the order of the curve over which the signature was
computed
:return: DER encoding of ECDSA signature
:rtype: bytes

Encode the signature to a pair of strings in a tuple
Encodes signature into raw encoding (:term:`raw encoding`) with the
``r`` and ``s`` parts of the signature encoded separately.
Makes sure that the signature is encoded in the canonical format, where
the ``s`` parameter is always smaller than ``order / 2``.
Most commonly used in bitcoin.
It's expected that this function will be used as a ``sigencode=`` parameter
in :func:`ecdsa.keys.SigningKey.sign` method.
:param int r: first parameter of the signature
:param int s: second parameter of the signature
:param int order: the order of the curve over which the signature was
computed
:return: raw encoding of ECDSA signature
:rtype: tuple(bytes, bytes)
sigencode_string

Encode the signature to raw format (:term:`raw encoding`)
Makes sure that the signature is encoded in the canonical format, where
the ``s`` parameter is always smaller than ``order / 2``.
Most commonly used in bitcoin.
It's expected that this function will be used as a ``sigencode=`` parameter
in :func:`ecdsa.keys.SigningKey.sign` method.
:param int r: first parameter of the signature
:param int s: second parameter of the signature
:param int order: the order of the curve over which the signature was
computed
:return: raw encoding of ECDSA signature
:rtype: bytes
sigencode_der

Encode the signature into the ECDSA-Sig-Value structure using :term:`DER`.
Makes sure that the signature is encoded in the canonical format, where
the ``s`` parameter is always smaller than ``order / 2``.
Most commonly used in bitcoin.
Encodes the signature to the following :term:`ASN.1` structure::
Ecdsa-Sig-Value ::= SEQUENCE {
r       INTEGER,
s       INTEGER
}
It's expected that this function will be used as a ``sigencode=`` parameter
in :func:`ecdsa.keys.SigningKey.sign` method.
:param int r: first parameter of the signature
:param int s: second parameter of the signature
:param int order: the order of the curve over which the signature was
computed
:return: DER encoding of ECDSA signature
:rtype: bytes
normalise_bytes
aMalformedSignature
uInvalid length of signature, expected {0} bytes long, provided string is {1} bytes long
string_to_number_fixedlen

Decoder for :term:`raw encoding`  of ECDSA signatures.
raw encoding is a simple concatenation of the two integers that comprise
the signature, with each encoded using the same amount of bytes depending
on curve size/order.
It's expected that this function will be used as the ``sigdecode=``
parameter to the :func:`ecdsa.keys.VerifyingKey.verify` method.
:param signature: encoded signature
:type signature: bytes like object
:param order: order of the curve over which the signature was computed
:type order: int
:raises MalformedSignature: when the encoding of the signature is invalid
:return: tuple with decoded ``r`` and ``s`` values of signature
:rtype: tuple of ints
uInvalid number of strings provided: {0}, expected 2
uInvalid length of first string ('r' parameter), expected {0} bytes long, provided string is {1} bytes long
uInvalid length of second string ('s' parameter), expected {0} bytes long, provided string is {1} bytes long

Decode the signature from two strings.
First string needs to be a big endian encoding of ``r``, second needs to
be a big endian encoding of the ``s`` parameter of an ECDSA signature.
It's expected that this function will be used as the ``sigdecode=``
parameter to the :func:`ecdsa.keys.VerifyingKey.verify` method.
:param list rs_strings: list of two bytes-like objects, each encoding one
parameter of signature
:param int order: order of the curve over which the signature was computed
:raises MalformedSignature: when the encoding of the signature is invalid
:return: tuple with decoded ``r`` and ``s`` values of signature
:rtype: tuple of ints
remove_sequence
aUnexpectedDER
utrailing junk after DER sig: %s
remove_integer
utrailing junk after DER numbers: %s

Decoder for DER format of ECDSA signatures.
DER format of signature is one that uses the :term:`ASN.1` :term:`DER`
rules to encode it as a sequence of two integers::
Ecdsa-Sig-Value ::= SEQUENCE {
r       INTEGER,
s       INTEGER
}
It's expected that this function will be used as as the ``sigdecode=``
parameter to the :func:`ecdsa.keys.VerifyingKey.verify` method.
:param sig_der: encoded signature
:type sig_der: bytes like object
:param order: order of the curve over which the signature was computed
:type order: int
:raises UnexpectedDER: when the encoding of signature is invalid
:return: tuple with decoded ``r`` and ``s`` values of signature
:rtype: tuple of ints

This module includes some utility functions.
The methods most typically used are the sigencode and sigdecode functions
to be used with :func:`~ecdsa.keys.SigningKey.sign` and
:func:`~ecdsa.keys.VerifyingKey.verify`
respectively. See the :func:`sigencode_strings`, :func:`sigdecode_string`,
:func:`sigencode_der`, :func:`sigencode_strings_canonize`,
:func:`sigencode_string_canonize`, :func:`sigencode_der_canonize`,
:func:`sigdecode_strings`, :func:`sigdecode_string`, and
:func:`sigdecode_der` functions.
a__doc__
a__file__
origin
has_location
a__cached__
division
os
sys
hashlib
T asha256
six
T aPY2
int2byte
anext
T ader
a_compat
T anormalise_bytes
T l l l  l Nl l aoid_ecPublicKey
encode_oid
encoded_oid_ecPublicKey
T l l l  l l aoid_ecDH
T l l l  l laoid_ecMQV
T narandrange
