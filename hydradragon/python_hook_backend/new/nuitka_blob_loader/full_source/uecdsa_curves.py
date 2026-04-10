# Reconstructed from integrated Nuitka blob
# Module: uecdsa.curves

a__qualname__
a__orig_bases__
T na__init__
uCurve.__init__
a__eq__
uCurve.__eq__
a__ne__
uCurve.__ne__
a__repr__
uCurve.__repr__
T nauncompressed
uCurve.to_der
to_pem
uCurve.to_pem
uCurve.from_der
from_pem
uCurve.from_pem
aSECP112r1
curve_112r1
generator_112r1
T l l l  l
l asecp112r1
aSECP112r2
curve_112r2
generator_112r2
T l l l  l
l asecp112r2
aSECP128r1
curve_128r1
generator_128r1
T l l l  l
l asecp128r1
aSECP160r1
curve_160r1
generator_160r1
T l l l  l
l asecp160r1
aNIST192p
curve_192
generator_192
T l l l  l Nl l paprime192v1
aNIST224p
curve_224
generator_224
T l l l  l
l!asecp224r1
aNIST256p
curve_256
generator_256
T l l l  l Nl l l aprime256v1
aNIST384p
curve_384
generator_384
T l l l  l
l"asecp384r1
aNIST521p
curve_521
generator_521
T l l l  l
l#asecp521r1
aSECP256k1
curve_secp256k1
generator_secp256k1
T l l l  l
l
secp256k1
aBRAINPOOLP160r1
curve_brainpoolp160r1
generator_brainpoolp160r1
T
l l l$l pl l l ppabrainpoolP160r1
aBRAINPOOLP160t1
curve_brainpoolp160t1
generator_brainpoolp160t1
T
l l l$l pl l l pl abrainpoolP160t1
aBRAINPOOLP192r1
curve_brainpoolp192r1
generator_brainpoolp192r1
T
l l l$l pl l l pl abrainpoolP192r1
aBRAINPOOLP192t1
curve_brainpoolp192t1
generator_brainpoolp192t1
T
l l l$l pl l l pl abrainpoolP192t1
aBRAINPOOLP224r1
curve_brainpoolp224r1
generator_brainpoolp224r1
T
l l l$l pl l l pl abrainpoolP224r1
aBRAINPOOLP224t1
curve_brainpoolp224t1
generator_brainpoolp224t1
T
l l l$l pl l l pl abrainpoolP224t1
aBRAINPOOLP256r1
curve_brainpoolp256r1
generator_brainpoolp256r1
T
l l l$l pl l l pl abrainpoolP256r1
aBRAINPOOLP256t1
curve_brainpoolp256t1
generator_brainpoolp256t1
T
l l l$l pl l l pl abrainpoolP256t1
aBRAINPOOLP320r1
curve_brainpoolp320r1
generator_brainpoolp320r1
T
l l l$l pl l l pl	abrainpoolP320r1
aBRAINPOOLP320t1
curve_brainpoolp320t1
generator_brainpoolp320t1
T
l l l$l pl l l pl
brainpoolP320t1
aBRAINPOOLP384r1
curve_brainpoolp384r1
generator_brainpoolp384r1
T
l l l$l pl l l pl abrainpoolP384r1
aBRAINPOOLP384t1
curve_brainpoolp384t1
generator_brainpoolp384t1
T
l l l$l pl l l pl abrainpoolP384t1
aBRAINPOOLP512r1
curve_brainpoolp512r1
generator_brainpoolp512r1
T
l l l$l pl l l plabrainpoolP512r1
aBRAINPOOLP512t1
curve_brainpoolp512t1
generator_brainpoolp512t1
T
l l l$l pl l l pl abrainpoolP512t1
aEd25519
curve_ed25519
generator_ed25519
T l l lelpaEd448
curve_ed448
generator_ed448
T l l lelqacurve_by_name
uecdsa\curves.py
T a.0
wiu<module ecdsa.curves>
T aself
other
T aself
name
curve
generator
oid
openssl_name
T aself
T aname
wcT aoid_curve
wcT adata
valid_encodings
oid
empty
seq
version
rest
field_id
curve
base_bytes
order
cofactor
w_afield_type
prime
curve_a_bytes
curve_b_bytes
curve_a
curve_b
curve_fp
base
tmp_curve
wiT acls
string
valid_encodings
ec_param_index
T aself
encoding
point_encoding
curve_p
version
field_id
curve
base
order
seq_elements
cofactor
T aself
encoding
point_encoding
a__spec__
.ecdsa.der
int2byte
l  aencode_length
u%x
encode
l d0abinascii
unhexlify
whastr_idx_as_int
l d d
c
a_sentry
warnings
warn
uLegacy call convention used, unused= needs to be specified
aDeprecationWarning
l uunused must be integer between 0 and 7
uunused is non-zero but s is empty
uunused bits must be zeros in DER
d u
Encode a binary string as a BIT STRING using :term:`DER` encoding.
Note, because there is no native Python object that can encode an actual
bit string, this function only accepts byte strings as the `s` argument.
The byte string is the actual bit string that will be encoded, padded
on the right (least significant bits, looking from big endian perspective)
to the first full byte. If the bit string has a bit length that is multiple
of 8, then the padding should not be included. For correct DER encoding
the padding bits MUST be set to 0.
Number of bits of padding need to be provided as the `unused` parameter.
In case they are specified as None, it means the number of unused bits
is already encoded in the string as the first byte.
The deprecated call convention specifies just the `s` parameters and
encodes the number of unused bits as first parameter (same convention
s with None).
Empty string must be encoded with `unused` specified as 0.
Future version of python-ecdsa will make specifying the `unused` argument
mandatory.
:param s: bytes to encode
:type s: bytes like object
:param unused: number of bits at the end of `s` that are unused, must be
between 0 and 7 (inclusive)
:type unused: int or None
:raises ValueError: when `unused` is too large or too small
:return: `s` encoded using DER
:rtype: bytes
d l'achain
encode_number
l(d u<genexpr>
uencode_oid.<locals>.<genexpr>
wnab128_digits
l  :nl nl  aUnexpectedDER
uwanted type 'constructed tag' (0xa0-0xbf), got 0x%02x
l aread_length
:l nnT uEmpty string does not encode a sequence
uwanted type 'sequence' (0x30), got 0x%02x
T uLength longer than the provided buffer
uwanted type 'octetstring' (0x04), got 0x%02x
T uEmpty string does not encode an object identifier
uwanted type 'object' (0x06), got 0x%02x
T uEmpty object identifier
T uLength of object identifier longer than the provided buffer
body
read_number
numbers
lPainsert
T uEmpty string is an invalid encoding of an integer
uwanted type 'integer' (0x02), got 0x%02x
T uLength longer than provided buffer
T u0-byte long encoding of integer
T uNegative integers are not supported
T uInvalid encoding of integer, unnecessary zero padding bytes
hexlify
l T uNon minimal encoding of OID subidentifier
llen
string
T uran out of length bytes
number
wsT uEmpty string can't encode valid length value
T uInvalid length encoding, length of length is 0
T uLength of length longer than provided buffer
T uNot minimal encoding of length
T uEmpty string does not encode a bitstring
uLegacy call convention used, expect_unused= needs to be specified
uwanted bitstring (0x03), got 0x%02x
T uInvalid length of bit string, can't be 0
T uInvalid encoding of unused bits
T uUnexpected number of unused bits
T uInvalid encoding of empty bit string
T uNon zero padding bits in bit string

Remove a BIT STRING object from `string` following :term:`DER`.
The `expect_unused` can be used to specify if the bit string should
have the amount of unused bits decoded or not. If it's an integer, any
read BIT STRING that has number of unused bits different from specified
value will cause UnexpectedDER exception to be raised (this is especially
useful when decoding BIT STRINGS that have DER encoded object in them;
DER encoding is byte oriented, so the unused bits will always equal 0).
If the `expect_unused` is specified as None, the first element returned
will be a tuple, with the first value being the extracted bit string
while the second value will be the decoded number of unused bits.
If the `expect_unused` is unspecified, the decoding of byte with
number of unused bits will not be attempted and the bit string will be
returned as-is, the callee will be required to decode it and verify its
correctness.
Future version of python will require the `expected_unused` parameter
to be specified.
:param string: string of bytes to extract the BIT STRING from
:type string: bytes like object
:param expect_unused: number of bits that should be unused in the BIT
STRING, or None, to return it to caller
:type expect_unused: int or None
:raises UnexpectedDER: when the encoding does not follow DER.
:return: a tuple with first element being the extracted bit string and
the second being the remaining bytes in the string (if any); if the
`expect_unused` is specified as None, the first element of the returned
tuple will be a tuple itself, with first element being the bit string
s bytes and the second element being the number of unused bits at the
end of the byte array as an integer
:rtype: tuple
text_type
split
T d
startswith
T c-----
strip
base64
b64decode
b64encode
compat26_str
u-----BEGIN %s-----
lLd
u-----END %s-----
a__doc__
a__file__
origin
has_location
a__cached__
division
itertools
T achain
six
T aint2byte
text_type
a_compat
T acompat26_str
str_idx_as_int
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
