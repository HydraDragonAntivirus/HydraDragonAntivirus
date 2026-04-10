# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Util.asn1

uThis class differs from BytesIO in that a ValueError exception is
raised whenever EOF is reached.
a__qualname__
uBytesIO_EOF.__init__
uBytesIO_EOF.set_bookmark
uBytesIO_EOF.data_since_bookmark
uBytesIO_EOF.remaining_data
uBytesIO_EOF.read
uBytesIO_EOF.read_byte
a__orig_bases__
uBase class for defining a single DER object.
This class should never be directly instantiated.
T nc
nFnuDerObject.__init__
uDerObject._convertTag
staticmethod
uDerObject._definite_form
uDerObject.encode
uDerObject._decodeLen
uDerObject.decode
uDerObject._decodeFromStream
uClass to model a DER INTEGER.
An example of encoding is::
>>> from Crypto.Util.asn1 import DerInteger
>>> from binascii import hexlify, unhexlify
>>> int_der = DerInteger(9)
>>> print hexlify(int_der.encode())
which will show ``020109``, the DER encoding of 9.
And for decoding::
>>> s = unhexlify(b'020109')
>>> try:
>>>   int_der = DerInteger()
>>>   int_der.decode(s)
>>>   print int_der.value
>>> except ValueError:
>>>   print "Not a valid DER INTEGER"
the output will be ``9``.
:ivar value: The integer value
:vartype value: integer
T l
nnuDerInteger.__init__
uDerInteger.encode
uDerInteger.decode
uDerInteger._decodeFromStream
aDerBoolean
uClass to model a DER-encoded BOOLEAN.
An example of encoding is::
>>> from Crypto.Util.asn1 import DerBoolean
>>> bool_der = DerBoolean(True)
>>> print(bool_der.encode().hex())
which will show ``0101ff``, the DER encoding of True.
And for decoding::
>>> s = bytes.fromhex('0101ff')
>>> try:
>>>   bool_der = DerBoolean()
>>>   bool_der.decode(s)
>>>   print(bool_der.value)
>>> except ValueError:
>>>   print "Not a valid DER BOOLEAN"
the output will be ``True``.
:ivar value: The boolean value
:vartype value: boolean
T FnnuDerBoolean.__init__
uDerBoolean.encode
uDerBoolean.decode
uDerBoolean._decodeFromStream
aDerSequence
uClass to model a DER SEQUENCE.
This object behaves like a dynamic Python sequence.
Sub-elements that are INTEGERs behave like Python integers.
Any other sub-element is a binary string encoded as a complete DER
sub-element (TLV).
An example of encoding is:
>>> from Crypto.Util.asn1 import DerSequence, DerInteger
>>> from binascii import hexlify, unhexlify
>>> obj_der = unhexlify('070102')
>>> seq_der = DerSequence([4])
>>> seq_der.append(9)
>>> seq_der.append(obj_der.encode())
>>> print hexlify(seq_der.encode())
which will show ``3009020104020109070102``, the DER encoding of the
sequence containing ``4``, ``9``, and the object with payload ``02``.
For decoding:
>>> s = unhexlify(b'3009020104020109070102')
>>> try:
>>>   seq_der = DerSequence()
>>>   seq_der.decode(s)
>>>   print len(seq_der)
>>>   print seq_der[0]
>>>   print seq_der[:]
>>> except ValueError:
>>>   print "Not a valid DER SEQUENCE"
the output will be::
3
4
[4, 9, b'   ']
T nnnuDerSequence.__init__
a__delitem__
uDerSequence.__delitem__
uDerSequence.__getitem__
a__setitem__
uDerSequence.__setitem__
a__setslice__
uDerSequence.__setslice__
a__delslice__
uDerSequence.__delslice__
a__getslice__
uDerSequence.__getslice__
a__len__
uDerSequence.__len__
a__iadd__
uDerSequence.__iadd__
uDerSequence.append
uDerSequence.insert
T tuDerSequence.hasInts
uDerSequence.hasOnlyInts
uDerSequence.encode
T FnFuDerSequence.decode
uDerSequence._decodeFromStream
aDerOctetString
uClass to model a DER OCTET STRING.
An example of encoding is:
>>> from Crypto.Util.asn1 import DerOctetString
>>> from binascii import hexlify, unhexlify
>>> os_der = DerOctetString(b'\xaa')
>>> os_der.payload += b'\xbb'
>>> print hexlify(os_der.encode())
which will show ``0402aabb``, the DER encoding for the byte string
``b'\xAA\xBB'``.
For decoding:
>>> s = unhexlify(b'0402aabb')
>>> try:
>>>   os_der = DerOctetString()
>>>   os_der.decode(s)
>>>   print hexlify(os_der.payload)
>>> except ValueError:
>>>   print "Not a valid DER OCTET STRING"
the output will be ``aabb``.
:ivar payload: The content of the string
:vartype payload: byte string
T c
nuDerOctetString.__init__
aDerNull
uClass to model a DER NULL element.
uDerNull.__init__
aDerObjectId
uClass to model a DER OBJECT ID.
An example of encoding is:
>>> from Crypto.Util.asn1 import DerObjectId
>>> from binascii import hexlify, unhexlify
>>> oid_der = DerObjectId("1.2")
>>> oid_der.value += ".840.113549.1.1.1"
>>> print hexlify(oid_der.encode())
which will show ``06092a864886f70d010101``, the DER encoding for the
RSA Object Identifier ``1.2.840.113549.1.1.1``.
For decoding:
>>> s = unhexlify(b'06092a864886f70d010101')
>>> try:
>>>   oid_der = DerObjectId()
>>>   oid_der.decode(s)
>>>   print oid_der.value
>>> except ValueError:
>>>   print "Not a valid DER OBJECT ID"
the output will be ``1.2.840.113549.1.1.1``.
:ivar value: The Object ID (OID), a dot separated list of integers
:vartype value: string
T u
nnuDerObjectId.__init__
uDerObjectId.encode
uDerObjectId.decode
uDerObjectId._decodeFromStream
aDerBitString
uClass to model a DER BIT STRING.
An example of encoding is:
>>> from Crypto.Util.asn1 import DerBitString
>>> bs_der = DerBitString(b'\xAA')
>>> bs_der.value += b'\xBB'
>>> print(bs_der.encode().hex())
which will show ``030300aabb``, the DER encoding for the bit string
``b'\xAA\xBB'``.
For decoding:
>>> s = bytes.fromhex('030300aabb')
>>> try:
>>>   bs_der = DerBitString()
>>>   bs_der.decode(s)
>>>   print(bs_der.value.hex())
>>> except ValueError:
>>>   print "Not a valid DER BIT STRING"
the output will be ``aabb``.
:ivar value: The content of the string
:vartype value: byte string
T c
nnuDerBitString.__init__
uDerBitString.encode
uDerBitString.decode
uDerBitString._decodeFromStream
aDerSetOf
uClass to model a DER SET OF.
An example of encoding is:
>>> from Crypto.Util.asn1 import DerBitString
>>> from binascii import hexlify, unhexlify
>>> so_der = DerSetOf([4,5])
>>> so_der.add(6)
>>> print hexlify(so_der.encode())
which will show ``3109020104020105020106``, the DER encoding
of a SET OF with items 4,5, and 6.
For decoding:
>>> s = unhexlify(b'3109020104020105020106')
>>> try:
>>>   so_der = DerSetOf()
>>>   so_der.decode(s)
>>>   print [x for x in so_der]
>>> except ValueError:
>>>   print "Not a valid DER SET OF"
the output will be ``[4, 5, 6]``.
T nnuDerSetOf.__init__
uDerSetOf.__getitem__
a__iter__
uDerSetOf.__iter__
uDerSetOf.__len__
uDerSetOf.add
uDerSetOf.decode
uDerSetOf._decodeFromStream
uDerSetOf.encode
uCrypto\Util\asn1.py
u<module Crypto.Util.asn1>
T a__class__
T aself
wnT aself
wiwjT aself
item
T aself
initial_bytes
T aself
value
implicit
explicit
T aself
T aself
asn1Id
payload
implicit
constructed
explicit
constructed_bit
T aself
value
implicit
T aself
startSeq
implicit
explicit
T aself
startSet
implicit
weT aself
key
value
T aself
wiwjasequence
T aself
tag
T aself
wsastrict
T aself
wsastrict
bits
wiT aself
wsastrict
idOctet
length
wpainner_octet
T aself
wsastrict
wpasubcomps
wvwcT aself
wsastrict
wpader
derInt
data
ok
T aself
wsastrict
wpasetIdOctet
der
derInt
T aself
wsalength
encoded_length
T alength
encoding
T wxaonly_non_negative
test
T aself
elem
eo
T aself
der_encoded
strict
T aself
der_encoded
strict
wsT aself
der_encoded
strict
nr_elements
only_ints_expected
result
T aself
number
T aself
output_payload
T aself
comps
subcomps
encoding
wvT aself
ordered
item
bys
T aself
only_non_negative
items
T aself
only_non_negative
T aself
index
item
T aself
length
new_index
result

a__spec__
.Crypto.Util
uMiscellaneous modules
Contains useful modules that don't belong into any of the
other Crypto.* subpackages.
========================    =============================================
Module                      Description
========================    =============================================
`Crypto.Util.number`        Number-theoretic functions (primality testing, etc.)
`Crypto.Util.Counter`       Fast counter functions for CTR cipher modes.
`Crypto.Util.RFC1751`       Converts between 128-bit keys and human-readable
strings of words.
`Crypto.Util.asn1`          Minimal support for ASN.1 DER encoding
`Crypto.Util.Padding`       Set of functions for adding and removing padding.
========================    =============================================
:undocumented: _galois, _number_new, cpuid, py3compat, _raw_api
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aUtil
T aNUITKA_PACKAGE_Crypto_Util
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
L aRFC1751
number
strxor
asn1
aCounter
aPadding
a__all__
uCrypto\Util\__init__.py
u<module Crypto.Util>

a__spec__
.Crypto.Util.number
uNon positive values
uReturn ceil(n/d), that is, the smallest integer r such that r*d >= n
uSize in bits only available for non-negative numbers
bit_length
uReturns the size of the number N in bits.
aRandom
get_random_bytes
l l T l astruct
pack
wBabytes_to_long
uReturn a random number at most N bits long.
If :data:`randfunc` is omitted, then :meth:`Random.get_random_bytes` is used.
.. deprecated:: 3.0
This function is for internal use only and may be renamed or removed in
the future. Use :func:`Crypto.Random.random.getrandbits` instead.
size
getRandomInteger
value
bits
randfunc
uReturn a random number *n* so that *a <= n < b*.
If :data:`randfunc` is omitted, then :meth:`Random.get_random_bytes` is used.
.. deprecated:: 3.0
This function is for internal use only and may be renamed or removed in
the future. Use :func:`Crypto.Random.random.randrange` instead.
l uReturn a random number with exactly N-bits,
i.e. a random number between 2**(N-1) and (2**N)-1.
If :data:`randfunc` is omitted, then :meth:`Random.get_random_bytes` is used.
.. deprecated:: 3.0
This function is for internal use only and may be renamed or removed in
the future.
uModulus cannot be zero
uModulus cannot be negative
pow
uThe inverse of :data:`u` *mod* :data:`v`.
uN must be larger than 1
getRandomNBitInteger
wNaisPrime
T arandfunc
uReturn a random N-bit prime number.
N must be an integer larger than 1.
If randfunc is omitted, then :meth:`Random.get_random_bytes` is used.
wmwbaiter_range
min
getRandomRange
wnwaatested
wzu_rabinMillerTest(n:long, rounds:int, randfunc:callable):int
Tests if n is prime.
Returns 0 when n is definitely composite.
Returns 1 when n is probably prime.
Returns 2 when n is definitely prime.
If randfunc is omitted, then Random.new().read is used.
This function is for internal use only and may be renamed or removed in
the future.
a_fastmath
getStrongPrime
long
l  l  ubits must be multiple of 128 and > 512
math
ceil
log
T l l g     D     l  g          OT l
l leasieve_base
wyafield
a_rabinMillerTest
rabin_miller_rounds
wparesult
uCouln't find prime in field. Developer: Increase field_size
inverse
wXweaGCD
increment

Return a random strong *N*-bit prime number.
In this context, *p* is a strong prime if *p-1* and *p+1* have at
least one large prime factor.
Args:
N (integer): the exact length of the strong prime.
It must be a multiple of 128 and > 512.
e (integer): if provided, the returned prime (minus 1)
will be coprime to *e* and thus suitable for RSA where
*e* is the public exponent.
false_positive_prob (float):
The statistical probability for the result not to be actually a
prime. It defaults to 10\ :sup:`-6`.
Note that the real probability of a false-positive is far less. This is
just the mathematically provable limit.
randfunc (callable):
A function that takes a parameter *N* and that returns
a random byte string of such length.
If omitted, :func:`Crypto.Random.get_random_bytes` is used.
Return:
The new strong prime.
.. deprecated:: 3.0
This function is for internal use only and may be renamed or removed in
the future.
uTest if a number *N* is a prime.
Args:
false_positive_prob (float):
The statistical probability for the result not to be actually a
prime. It defaults to 10\ :sup:`-6`.
Note that the real probability of a false-positive is far less.
This is just the mathematically provable limit.
randfunc (callable):
A function that takes a parameter *N* and that returns
a random byte string of such length.
If omitted, :func:`Crypto.Random.get_random_bytes` is used.
Return:
`True` if the input is indeed prime.
uValues must be non-negative
bsr
u>Q
g            l@l u>I
g       l u>B
l  d
c
lstrip
T d
uConvert a positive integer to a byte string using big endian encoding.
If :data:`blocksize` is absent or zero, the byte string will
be of minimal length.
Otherwise, the length of the byte string is guaranteed to be a multiple
of :data:`blocksize`. If necessary, zeroes (``\x00``) are added at the left.
.. note::
In Python 3, if you are sure that :data:`n` can fit into
:data:`blocksize` bytes, you can simply use the native method instead::
>>> n.to_bytes(blocksize, 'big')
For instance::
>>> n = 80
>>> n.to_bytes(2, 'big')
b'\x00P'
However, and unlike this ``long_to_bytes()`` function,
n ``OverflowError`` exception is raised if :data:`n` does not fit.
unpack
acc
wsv  Convert a byte string to a long integer (big endian).
In Python 3.2+, use the native method instead::
>>> int.from_bytes(s, 'big')
For instance::
>>> int.from_bytes(b'
P', 'big')
80
This is (essentially) the inverse of :func:`long_to_bytes`.
warnings
warn
T ulong2str() has been replaced by long_to_bytes()
long_to_bytes
T ustr2long() has been replaced by bytes_to_long()
a__doc__
a__file__
origin
has_location
a__cached__
sys
aCrypto
T aRandom
uCrypto.Util.py3compat
T aiter_range
ceil_div
T nagcd
getPrime
T l
f       >nT f       >nT l
long2str
str2long
T Nl l l l l ll l l l l l%l)l+l/l5l;l=lClGlIlOlSlYlalelglklmlql l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l
l
l
l
l
l
l
l
l
l
l
l
l
l
l
l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l l l l l l l l l l l l l l l l l l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l !l !l !l !l !l !l !l !l !l !l !l !l !l !l !l !l "l "l "l "l "l "l "l "l "l "l "l "l "l #l #l #l #l #l #l #l #l #l #l #l #l #l #l #l #l $l $l $l $l $l $l $l $l $l $l $l $l $l $l $l $l %l %l %l %l %l %l %l %l %l %l %l %l &l &l &l &l &l &l &l &l &l &l &l &l &l &l &l &l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l 'l (l (l (l (l (l (l (l (l (l (l (l (l )l )l )l )l )l )l )l )l )l )l )l *l *l *l *l *l *l *l *l *l *l *l *l *l *l *l *l *l *l *l +l +l +l +l +l +l +l +l +l +l +l +l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l ,l -l -l -l -l -l -l -l -l -l -l -l -l -l -l -l -l -l -l .l .l .l .l .l .l .l .l .l .l /l /l /l /l /l /l /l /l /l /l /l /l /l /l /l /l 0l 0l 0l 0l 0l 0l 0l 0l 0l 0l 0l 0l 0l 0l 0l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 1l 2l 2l 2l 2l 2l 2l 2l 2l 2l 3l 3l 3l 3l 3l 3l 3l 3l 3l 3l 3l 3l 3l 3l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 4l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 5l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 6l 7l 7l 7l 7l 7l 7l 7l 7l 7l 7l 7l 8l 8l 8l 8l 8l 8l 8l 8l 8l 8l 8l 8l 8l 9l 9l 9l 9l 9l 9l 9l 9l 9l 9l 9l 9l :l :l :l :l :l :l :l :l :l :l :l :l :l :l :l :l :l ;l ;l ;l ;l ;l ;l ;l ;l ;l ;l ;l ;l ;l ;l ;l <l <l <l <l <l <l <l <l <l <l <l <l <l <l =l =l =l =l =l =l =l =l =l =l =l =l =l =l =l >l >l >l >l >l >l >l >l >l >l >l ?l ?l ?l ?l ?l ?l ?l ?l ?l ?l ?l ?l ?l ?l ?l @l @l @l @l @l @l @l @l @l @l @l @l @l @l @l @l Al Al Al Al Al Al Al Al Al Al Al Al Al Bl Bl Bl Bl Bl Bl Bl Bl Bl Bl Bl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Cl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl Dl El El El El El El El El El El El El El Fl Fl Fl Fl Fl Fl Fl Fl Fl Fl Fl Fl Fl Fl Gl Gl Gl Gl Gl Gl Gl Gl Gl Gl Gl Gl Gl Gl Gl Hl Hl Hl Hl Hl Hl Hl Hl Hl Hl Hl Hl Hl Hl Hl Il Il Il Il Il Il Il Il Il Il Il Il Il Il Il Il Jl Jl Jl Jl Jl Jl Jl Jl Jl Jl Jl Kl Kl Kl Kl Kl Kl Kl Kl Kl Kl Kl Kl Kl Kl Kl Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ll Ml Ml Ml Ml Ml Ml Ml Ml Ml Ml Ml Ml Ml Ml Nl Nl Nl Nl Nl Nl Nl Nl Nl Nl Nl Nl Nl Ol Ol Ol Ol Ol Ol Ol Ol Ol Ol Ol Ol Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Pl Ql Ql Ql Ql Ql Ql Ql Ql Ql Ql Ql Ql Rl Rl Rl Rl Rl Rl Rl Rl Rl Rl Rl Rl Sl Sl Sl Sl Sl Sl Sl Sl Sl Sl Sl Sl Sl Sl Sl Tl Tl Tl Tl Tl Tl Tl Tl Tl Tl Tl Tl Ul Ul Ul Ul Ul Ul Ul Ul Ul Ul Ul Ul Ul Ul Vl Vl Vl Vl Vl Vl Vl Vl Vl Vl Vl Vl Vl Wl Wl Wl Wl Wl Wl Wl Wl Wl Wl Wl Wl Wl Xl Xl Xl Xl Xl Xl Xl Xl Xl Xl Xl Xl Yl Yl Yl Yl Yl Yl Yl Yl Yl Yl Yl Yl Yl Yl Yl Zl Zl Zl Zl Zl Zl Zl Zl Zl Zl [l [l [l [l [l [l [l [l [l [l \l \l \l \l \l \l \l \l \l \l \l \l \l \l \l \l \l ]l ]l ]l ]l ]l ]l ]l ]l ]l ]l ]l ]l ]l ]l ^l ^l ^l ^l ^l ^l ^l ^l ^l ^l ^l ^l ^l ^l ^l _l _l _l _l _l _l _l _l _l _l _l _l _l _l `l `l `l `l `l `l `l `l `l `l `l `l `l al al al al al al al al al al al al al al al al bl bl bl bl bl bl bl bl bl bl bl bl bl bl bl bl cl cl cl cl cl cl cl cl cl cl cl cl dl dl dl dl dl dl dl dl dl dl dl dl dl dl el el el el el el el el el el el el el el el fl fl fl fl fl fl fl fl fl fl fl fl fl fl gl gl gl gl gl gl gl gl gl gl gl hl hl hl hl hl hl hl hl hl hl hl hl il il il il il il il il il il il il il jl jl jl jl jl jl jl jl jl jl jl jl jl jl kl kl kl kl kl kl kl kl kl kl kl kl kl kl ll ll ll ll ll ll ll ll ll ll ll ll ll ll ll ml ml ml ml ml ml ml ml ml ml ml nl nl nl nl nl nl nl nl nl nl nl nl ol ol ol ol ol ol ol ol ol ol pl pl pl pl pl pl pl pl pl pl pl pl pl pl pl ql ql ql ql ql ql ql ql ql ql ql ql ql rl rl rl rl rl rl rl rl rl rl rl rl rl sl sl sl sl sl sl sl sl sl sl sl sl sl sl sl sl sl tl tl tl tl tl tl tl tl tl tl tl tl tl tl ul ul ul ul ul ul ul ul ul ul ul vl vl vl vl vl vl vl vl vl vl vl vl vl wl wl wl wl wl wl wl wl wl wl wl wl wl wl wl wl wl xl xl xl xl xl xl xl xl xl xl xl xl xl xl yl yl yl yl yl yl yl yl yl yl yl yl zl zl zl zl zl zl zl zl zl zl zl zl zl zl zl zl {l {l {l {l {l {l {l {l {l {l {l {l |l |l |l |l |l |l |l |l |l |l |l |l |l |l }l }l }l }l }l }l }l }l }l }l }l }l }l }l }l ~l ~l ~l ~l ~l ~l ~l ~l ~l ~l ~l ~l  l  l  l  l  l  l  l  l  l  l  l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   l   uCrypto\Util\number.py
u<module Crypto.Util.number>
T wnarounds
randfunc
n_1
wbwmatested
wiwawzacomposite
wrT wsaacc
unpack
length
extra
wiT wnwdwrwqT wNarandfunc
number
T wNarandfunc
wSaodd_bits
rand_bits
value
T wNarandfunc
value
T wawbarandfunc
range_
bits
value
T wNweafalse_positive_prob
randfunc
rabin_miller_rounds
wxalower_bound
upper_bound
wXwpwiwyafield
prime
offset
wjaresult
composite
tmp
tmp1
tmp2
wRaincrement
is_possible_prime
T wuwvT wNafalse_positive_prob
randfunc
wparounds
T wnablocksize
T wnablocksize
result
pack
bsr
bresult
target_len
T wNT wsu
a__spec__
.Crypto.Util.py3compat
+
encode
T ulatin-1
ulatin-1
tobytes
decode
uReturn an immutable copy of a sequence (byte string, byte array, memoryview)
in a certain interval [start:seq]
uCompatibility code for handling string/bytes changes from Python 2.x to Py3k
In Python 2.x, strings (of type ''str'') contain binary data, including encoded
Unicode text (e.g. UTF-8).  The separate type ''unicode'' holds Unicode text.
Unicode literals are specified via the u'...' prefix.  Indexing or slicing
either type always produces a string of the same type as the original.
Data read from a file is always of '''str'' type.
In Python 3.x, strings (type ''str'') may only contain Unicode text. The u'...'
prefix and the ''unicode'' type are now redundant.  A new type (called
''bytes'') has to be used for binary data (including any particular
''encoding'' of a string).  The b'...' prefix allows one to specify a binary
literal.  Indexing or slicing a string produces another string.  Slicing a byte
string produces another byte string, but the indexing operation produces an
integer.  Data read from a file is of '''str'' type if the file was opened in
text mode, or of ''bytes'' type otherwise.
Since PyCrypto aims at supporting both Python 2.x and 3.x, the following helper
functions are used to keep the rest of the library as independent as possible
from the actual Python version.
In general, the code should always deal with binary strings, and use integers
instead of 1-byte character strings.
b(s)
Take a text string literal (with no prefix or with u'...' prefix) and
make a byte string.
bchr(c)
Take an integer and make a 1-character byte string.
bord(c)
Take the result of indexing on a byte string and make an integer.
tobytes(s)
Take a text string, a byte string, or a sequence of character taken from
a byte string and make a byte string.
a__doc__
a__file__
origin
has_location
a__cached__
sys
abc
wbabchr
bstr
bord
tostr
byte_string
concat_buffers
aBytesIO
aStringIO
g            amaxint
iter_range
is_native_int
is_string
is_bytes
T aABC
aABC
aFileNotFoundError
a_copy_bytes
uCrypto\Util\py3compat.py
u<module Crypto.Util.py3compat>
T astart
end
seq
T wsT wawbT wxT wsaencoding
T abs

a__spec__
.Crypto.Util.strxor
#
uOnly byte strings of equal length can be xored
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
a_raw_strxor
strxor
c_uint8_ptr
c_size_t
get_raw_buffer
uFrom two byte strings of equal length,
create a third one which is the byte-by-byte XOR of the two.
Args:
term1 (bytes/bytearray/memoryview):
The first byte string to XOR.
term2 (bytes/bytearray/memoryview):
The second byte string to XOR.
output (bytearray/memoryview):
The location where the result will be written to.
It must have the same length as ``term1`` and ``term2``.
If ``None``, the result is returned.
:Return:
If ``output`` is ``None``, a new byte string with the result.
Otherwise ``None``.
.. note::
``term1`` and ``term2`` must have the same length.
l  uc must be in range(256)
strxor_c
term
uFrom a byte string, create a second one of equal length
where each byte is XOR-red with the same value.
Args:
term(bytes/bytearray/memoryview):
The byte string to XOR.
c (int):
Every byte in the string will be XOR-ed with this value.
It must be between 0 and 255 (included).
output (None or bytearray/memoryview):
The location where the result will be written to.
It must have the same length as ``term``.
If ``None``, the result is returned.
Return:
If ``output`` is ``None``, a new ``bytes`` string with the result.
Otherwise ``None``.
uVery fast XOR - check conditions!
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
c_size_t
create_string_buffer
get_raw_buffer
c_uint8_ptr
is_writeable_buffer
load_pycryptodome_raw_lib
T uCrypto.Util._strxor

void strxor(const uint8_t *in1,
const uint8_t *in2,
uint8_t *out, size_t len);
void strxor_c(const uint8_t *in,
uint8_t c,
uint8_t *out,
size_t len);
T na_strxor_direct
uCrypto\Util\strxor.py
u<module Crypto.Util.strxor>
T aterm1
term2
result
T aterm1
term2
output
result
T aterm
wcaoutput
result

a__spec__
.Crypto
B
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
L aCipher
aHash
aProtocol
aPublicKey
aUtil
aSignature
aIO
aMath
a__all__
T l l w0aversion_info
w.a__version__
uCrypto\__init__.py
u<module Crypto>

a__spec__
.__main__
Q
M
a__mro_entries__
bases
a__iter__
a__getitem__
u%s argument after * must be an iterable, not %s
a__name__
keys
u%s argument after ** must be a mapping, not %s
u%s got multiple values for keyword argument '%s'
called
star_arg_dict
kw
args
star_arg_list
ukeywords must be strings
u'%s' object is not a mapping
ur+
a__enter__
a__exit__
read
T nnnajson
loads
print
aFore
aCYAN

u[
aRED
uJSON CONFIG INVALID
u]
aLIGHTWHITE_EX
uConfiguration file have errors, please check config.json syntax and relaunch program
aLIGHTBLACK_EX
uPRESS ANY KEY TO CONTINUE
aRESET
l   a__doc__
a__file__
a__cached__
a__annotations__
wallet_searcher
a__program__
u1.1.1
a__version__
colorama
T aFore
init
init
colorama_init
T tT aautoreset
sys
uvendor.setup
T aSetup
aSetup
run
T u./input/config.json
parseConfig
uvendor.vxauth
T aVXNET_AUTHENTICATION_SYSTEM
getLatestProgramVersion
aVXNET_AUTHENTICATION_SYSTEM
getLatestProgramVersion
auth_api
config
authenticate
u./input/config.json
license
json_auth_data
a__latest__
modules
T aUI
aUI
ui
main
umain.py
u<module>
T aconfig_file
data
wfaconfig
.__parents_main__
I
O
ur+
a__enter__
a__exit__
read
T nnnajson
loads
print
aFore
aCYAN

u[
aRED
uJSON CONFIG INVALID
u]
aLIGHTWHITE_EX
uConfiguration file have errors, please check config.json syntax and relaunch program
aLIGHTBLACK_EX
uPRESS ANY KEY TO CONTINUE
aRESET
l   umultiprocessing.spawn
u<lambda>
u__nuitka_freeze_support.<locals>.<lambda>
spawn
a_fixup_main_from_path
argv
:l nnasplit
T w=apipe_handle
aNone
kwds
modules
a__parents_main__
a__main__
spawn_main
a__doc__
a__file__
origin
has_location
a__cached__
wallet_searcher
a__program__
u1.1.1
a__version__
colorama
T aFore
init
init
colorama_init
T tT aautoreset
sys
uvendor.setup
T aSetup
aSetup
run
T u./input/config.json
parseConfig
uvendor.vxauth
T aVXNET_AUTHENTICATION_SYSTEM
getLatestProgramVersion
aVXNET_AUTHENTICATION_SYSTEM
getLatestProgramVersion
auth_api
config
authenticate
u./input/config.json
license
json_auth_data
a__latest__
T aUI
aUI
a__nuitka_freeze_support
umain.py
T amod_name
u<module __parents_main__>
T asys
multiprocessing
kwds
args
arg
name
value
T aconfig_file
data
wfaconfig
a__spec__
.aiohappyeyeballs._staggered
O
done
set_result
T nuSet the result of a future if it is not already done.
uWait for the first future to complete.
loop
create_future
D afut
return
uasyncio.Future[Any]
na_on_completion
u_wait_one.<locals>._on_completion
futures
add_done_callback
remove_done_callback
a_wait_one
wait_next

Run coroutines with staggered start times and take the first to finish.
This method takes an iterable of coroutine functions. The first one is
started immediately. From then on, whenever the immediately preceding one
fails (raises an exception), or when *delay* seconds has passed, the next
coroutine is started. This continues until one of the coroutines complete
successfully, in which case all others are cancelled, or until all
coroutines fail.
The coroutines provided should be well-behaved in the following way:
* They should only ``return`` if completed successfully.
* They should always raise an exception if they did not complete
successfully. In particular, if they handle cancellation, they should
probably reraise, like this::
try:
# do work
except asyncio.CancelledError:
# undo partially completed work
raise
Args:
----
coro_fns: an iterable of coroutine functions, i.e. callables that
return a coroutine object when called. Use ``functools.partial`` or
lambdas to pass arguments.
delay: amount of time, in seconds, between starting coroutines. If
``None``, the coroutines will run sequentially.
loop: the event loop to use. If ``None``, the running loop is used.
Returns:
-------
tuple *(winner_result, winner_index, exceptions)* where
- *winner_result*: the result of the winning coroutine, or ``None``
if no coroutines won.
- *winner_index*: the index of the winning coroutine in
``coro_fns``, or ``None`` if no coroutines won. If the winning
coroutine may return None on success, *winner_index* can be used
to definitively determine whether any coroutine won.
- *exceptions*: list of exceptions returned by the coroutines.
``len(exceptions)`` is equal to the number of coroutines actually
started, and the order is the same as in ``coro_fns``. The winning
coroutine's entry is ``None``.
asyncio
get_running_loop
coro_fn
aCallable
aAwaitable
a_T
this_index
start_next
uasyncio.Future[None]
return
aOptional
aTuple

Run a single coroutine.
If the coroutine fails, set the exception in the exceptions list and
start the next coroutine by setting the result of the start_next.
If the coroutine succeeds, return the result and the index of the
coroutine in the coro_fns list.
If SystemExit or KeyboardInterrupt is raised, re-raise it.
run_one_coro
ustaggered_race.<locals>.run_one_coro
coro_fns
exceptions
append
create_task
tasks
add
delay
call_later
a_set_result
start_next_timer
cancel
remove
result
contextlib
suppress
aCancelledError
a__enter__
a__exit__
T nnnastaggered_race
T ESystemExit
EKeyboardInterrupt
a__doc__
a__file__
origin
has_location
a__cached__
aTYPE_CHECKING
aAny
aIterable
aList
aSet
aTypeVar
aUnion
T a_T
D await_next
return
uasyncio.Future[None]
nuIterable[asyncio.Future[Any]]
aAbstractEventLoop
D aloop
nuaiohappyeyeballs\_staggered.py
u<module aiohappyeyeballs._staggered>
T afut
wait_next
T await_next
T afutures
loop
wait_next
a_on_completion
wfT acoro_fn
this_index
start_next
result
weaexceptions
T aexceptions
T acoro_fns
delay
loop
exceptions
tasks
start_next_timer
start_next
task
done
run_one_coro
coro_iter
this_index
coro_fn
winner

a__spec__
.aiohappyeyeballs
Q
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_aiohappyeyeballs
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
u2.4.6
a__version__
impl
T astart_connection
start_connection
types
T aAddrInfoType
aAddrInfoType
utils
T aaddr_to_addr_infos
pop_addr_infos_interleave
remove_addr_infos
addr_to_addr_infos
pop_addr_infos_interleave
remove_addr_infos
T aAddrInfoType
addr_to_addr_infos
pop_addr_infos_interleave
remove_addr_infos
start_connection
a__all__
uaiohappyeyeballs\__init__.py
u<module aiohappyeyeballs>

a__spec__
.aiohappyeyeballs.impl
(
W

Connect to a TCP server.
Create a socket connection to a specified destination.  The
destination is specified as a list of AddrInfoType tuples as
returned from getaddrinfo().
The arguments are, in order:
* ``family``: the address family, e.g. ``socket.AF_INET`` or
``socket.AF_INET6``.
* ``type``: the socket type, e.g. ``socket.SOCK_STREAM`` or
``socket.SOCK_DGRAM``.
* ``proto``: the protocol, e.g. ``socket.IPPROTO_TCP`` or
``socket.IPPROTO_UDP``.
* ``canonname``: the canonical name of the address, e.g.
``"www.python.org"``.
* ``sockaddr``: the socket address
This method is a coroutine which will try to establish the connection
in the background. When successful, the coroutine returns a
socket.
The expected use case is to use this method in conjunction with
loop.create_connection() to establish a connection to a server::
socket = await start_connection(addr_infos)
transport, protocol = await loop.create_connection(
MyProtocol, sock=socket, ...)
loop
asyncio
get_running_loop
addr_infos
happy_eyeballs_delay
interleave
a_interleave_addrinfos
a_connect_sock
current_loop
exceptions
local_addr_infos
T ERuntimeError
EOSError
a_staggered
staggered_race
uMultiple exceptions: {}
u,
errno
start_connection
partial
u<genexpr>
ustart_connection.<locals>.<genexpr>
model
first_errno
uCreate, bind and connect one socket.
append
addr_info
socket
T afamily
type
proto
setblocking
T Fasock
bind
uerror while attempting to bind on address

u:
strerror
lower
my_exceptions
uno matching local address with family=
u found
sock_connect
close
collections
aOrderedDict
addrinfos_by_family
values
itertools
chain
from_iterable
zip_longest
uInterleave list of addrinfo tuples by family.
u_interleave_addrinfos.<locals>.<genexpr>
uBase implementation.
a__doc__
a__file__
origin
has_location
a__cached__
functools
aList
aOptional
aSequence
aUnion
T a_staggered
types
T aAddrInfoType
aAddrInfoType
D alocal_addr_infos
happy_eyeballs_delay
interleave
loop
nnnnaAbstractEventLoop
return
T nT EOSError
ERuntimeError
T l aaddrinfos
first_address_family_count
uaiohappyeyeballs\impl.py
T a.0
waT a.0
addrinfo
current_loop
exceptions
local_addr_infos
T a.0
exc
T a.0
exc
first_errno
T a.0
exc
model
u<module aiohappyeyeballs.impl>
T aloop
exceptions
addr_info
local_addr_infos
my_exceptions
family
type_
proto
w_aaddress
sock
lfamily
laddr
exc
msg
weT aaddrinfos
first_address_family_count
addrinfos_by_family
reordered
addr
family
addrinfos_lists
T aaddr_infos
local_addr_infos
happy_eyeballs_delay
interleave
loop
sock
exceptions
current_loop
single_addr_info
addrinfo
w_aall_exceptions
first_exception
model
msg
first_errno
a__spec__
.aiohappyeyeballs.types
uTypes for aiohappyeyeballs.
a__doc__
a__file__
origin
has_location
a__cached__
socket
aTuple
aUnion
aAddressFamily
aSocketKind
aAddrInfoType
uaiohappyeyeballs\types.py
u<module aiohappyeyeballs.types>

a__spec__
.aiohappyeyeballs.utils
9
w:l l asocket
aAF_INET6
aAF_INET
aSOCK_STREAM
aIPPROTO_TCP

uConvert an address tuple to a list of addr_info tuples.
seen
to_remove
addr_infos
remove

Pop addr_info from the list of addr_infos by family up to interleave times.
The interleave parameter is used to know how many addr_infos for
each family should be popped of the top of the list.
ipaddress
ip_address
:l nnuConvert an address tuple to an IPv4Address.
bad_addrs_infos
a_addr_tuple_to_ip_address
uAddress
u not found in addr_infos

Remove an address from the list of addr_infos.
The addr value is typically the return value of
sock.getpeername().
uUtility functions for aiohappyeyeballs.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aList
aOptional
aTuple
aUnion
types
T aAddrInfoType
aAddrInfoType
addr
T Ostr
Oint
ppT Ostr
Oint
pT Ostr
Oint
return
addr_to_addr_infos
T nainterleave
pop_addr_infos_interleave
aIPv4Address
aIPv6Address
remove_addr_infos
uaiohappyeyeballs\utils.py
u<module aiohappyeyeballs.utils>
T aaddr
T aaddr
host
port
is_ipv6
flowinfo
scopeid
addr_len
family
T aaddr_infos
interleave
seen
to_remove
addr_info
family
T aaddr_infos
addr
bad_addrs_infos
addr_info
bad_addr_info
match_addr
a__spec__
.aiohttp._websocket
Z
uWebSocket protocol versions 13 and 8.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_aiohttp
u\not_existing
a_websocket
T aNUITKA_PACKAGE_aiohttp__websocket
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uaiohttp\_websocket\__init__.py
u<module aiohttp._websocket>

a__spec__
.aiohttp._websocket.helpers
P
m
;l
l  l wbu<genexpr>
u_xor_table.<locals>.<genexpr>
a_xor_table
:nnl atranslate
:l nl :l nl :l nl uWebsocket masking function.
`mask` is a `bytes` object of length 4; `data` is a `bytearray`
object of any length. The contents of `data` are masked with `mask`,
s specified in section 5.3 of RFC 6455.
Note that this function mutates the `data` argument.
This pure-python implementation may be replaced by an optimized
version when available.
a_XOR_TABLE
u_websocket_mask_python.<locals>.<genexpr>
T l
Fa_WS_EXT_RE_SPLIT
finditer
group
T l l a_WS_EXT_RE
match
T l l	T l aWSHandshakeError
T uInvalid window size
T l uExtension for deflate not supported
compress
uCompress wbits must between 9 and 15, zlib does not support wbits=8
upermessage-deflate
client_max_window_bits
userver_max_window_bits=
server_no_context_takeover
u;
uHelpers for WebSocket protocol versions 13 and 8.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
functools
re
struct
T aStruct
aStruct
aTYPE_CHECKING
aFinal
aList
aOptional
aPattern
aTuple
helpers
T aNO_EXTENSIONS
l aNO_EXTENSIONS
models
T aWSHandshakeError
T u!Q
unpack_from
aUNPACK_LEN3
T u!H
unpack
aUNPACK_CLOSE_CODE
T u!BB
pack
aPACK_LEN1
T u!BBH
aPACK_LEN2
T u!BBQ
aPACK_LEN3
aPACK_CLOSE_CODE
T u!L
aPACK_RANDBITS
l   aMSG_SIZE
l aMASK_LEN
c258EAFA5-E914-47DA-95CA-C5AB0DC85B11
aWS_KEY
lru_cache
return
D amask
data
return
Obytes
Obytearray
na_websocket_mask_python
websocket_mask
mask
T a_websocket_mask_cython
a_websocket_mask_cython
compile
T u^(?:;\s*(?:(server_no_context_takeover)|(client_no_context_takeover)|(server_max_window_bits(?:=(\d+))?)|(client_max_window_bits(?:=(\d+))?)))*$
T upermessage-deflate([^,]+)?
T Faextstr
isserver
T Oint
Obool
ws_ext_parse
T l FpD acompress
isserver
server_notakeover
return
Oint
Obool
pOstr
ws_ext_gen
uaiohttp\_websocket\helpers.py
T a.0
wna_XOR_TABLE
T a.0
wawbu<module aiohttp._websocket.helpers>
T amask
data
a_XOR_TABLE
wawbwcwdT acompress
isserver
server_notakeover
enabledext
T aextstr
isserver
compress
notakeover
ext
defext
match

a__spec__
.aiohttp._websocket.models
O
r
data
uReturn parsed JSON data.
.. versionadded:: 0.22
code
a__class__
a__init__
cast
args
uModels for WebSocket protocol versions 13 and 8.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
json
enum
T aIntEnum
aIntEnum
aAny
aCallable
aFinal
aNamedTuple
aOptional
b
aWS_DEFLATE_TRAILING
a__prepare__
aWSCloseCode
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
