# Reconstructed from integrated Nuitka blob
# Module: uecdsa.eddsa

uPublic key for the Edwards Digital Signature Algorithm.
a__qualname__
T na__init__
uPublicKey.__init__
a__eq__
uPublicKey.__eq__
a__ne__
uPublicKey.__ne__
property
point
uPublicKey.point
setter
public_point
uPublicKey.public_point
uPublicKey.public_key
verify
uPublicKey.verify
a__orig_bases__
uPrivate key for the Edwards Digital Signature Algorithm.
uPrivateKey.__init__
private_key
uPrivateKey.private_key
uPrivateKey.__eq__
uPrivateKey.__ne__
uPrivateKey._key_prune
uPrivateKey.public_key
sign
uPrivateKey.sign
uecdsa\eddsa.py
u<module ecdsa.eddsa>
T a__class__
T aself
other
T aself
generator
private_key
waascalar
T aself
generator
public_key
public_point
T aself
key
whah_log
wlT adata
T aself
T aself
public_point
T	aself
data
wAaprefix
dom
wrwRwkwST aself
data
signature
wRwSadom
wka__spec__
.ecdsa.ellipticcurve
M
mpz
a_CurveFp__p
a_CurveFp__a
a_CurveFp__b
a_CurveFp__h

The curve of points satisfying y^2 = x^3 + a*x + b (mod p).
h is an integer that is the cofactor of the elliptic curve domain
parameters; it is the number of points satisfying the elliptic
curve equation divided by the order of the base point. It is used
for selection of efficient algorithm for public point verification.
aCurveFp
uReturn True if other is an identical curve, False otherwise.
Note: the value of the cofactor of the curve is not taken into account
when comparing curves, as it's derived from the base point and
intrinsic curve characteristic (but it's complex to compute),
only the prime and curve parameters are considered.
uReturn False if other is an identical curve, True otherwise.
uIs the point (x,y) on this curve?
uCurveFp(p={0}, a={1}, b={2}, h={3})
uCurveFp(p={0}, a={1}, b={2})
a_CurveEdTw__p
a_CurveEdTw__a
a_CurveEdTw__d
a_CurveEdTw__h
a_CurveEdTw__hash_func

The curve of points satisfying a*x^2 + y^2 = 1 + d*x^2*y^2 (mod p).
h is the cofactor of the curve.
hash_func is the hash function associated with the curve
(like SHA-512 for Ed25519)
aCurveEdTw
uReturns True if other is an identical curve.
uReturn False if the other is an identical curve, True otherwise.
uIs the point (x, y) on this curve?
uCurveEdTw(p={0}, a={1}, d={2}, h={3})
uCurveEdTw(p={0}, a={1}, d={2})
l astring_to_number

Decode public point from :term:`raw encoding`.
:term:`raw encoding` is the same as the :term:`uncompressed` encoding,
but without the 0x04 byte at the beginning.
:nl nT d d aMalformedPointError
T uMalformed compressed point encoding
d :l nnwpapow
l wawbanumbertheory
square_root_mod_prime
aError
uEncoding does not correspond to a point on curve
uDecode public point from compressed encoding.
T d d a_from_raw_encoding
d d T uInconsistent hybrid point encoding
uDecode public point from hybrid encoding.
bit_length
l l T uPoint length doesn't match the curve.
l  l abytes_to_int
little
aGMPY
inverse_mod
wdwxuDecode a point on an Edwards curve.
S araw
hybrid
uncompressed
compressed
uOnly uncompressed, compressed, hybrid or raw encoding supported.
normalise_bytes
a_from_edwards
orderlen
raw
hybrid
uncompressed
a_from_hybrid
d T uInvalid X9.62 encoding of the public point
compressed
a_from_compressed
uLength of string does not match lengths of any of the enabled ({0}) encodings of the curve.
u,

Initialise the object from byte encoding of a point.
The method does accept and automatically detect the type of point
encoding used. It supports the :term:`raw encoding`,
:term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.
Note: generally you will want to call the ``from_bytes()`` method of
either a child class, PointJacobi or Point.
:param data: single point encoding of the public key
:type data: :term:`bytes-like object`
:param curve: the curve on which the public key is expected to lay
:type curve: ~ecdsa.ellipticcurve.CurveFp
:param validate_encoding: whether to verify that the encoding of the
point is self-consistent, defaults to True, has effect only
on ``hybrid`` encoding
:type validate_encoding: bool
:param valid_encodings: list of acceptable point encoding formats,
supported ones are: :term:`uncompressed`, :term:`compressed`,
:term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
name). All formats by default (specified with ``None``).
:type valid_encodings: :term:`set-like object`
:raises `~ecdsa.errors.MalformedPointError`: if the public point does
not lay on the curve or the encoding is invalid
:return: x and y coordinates of the encoded point
:rtype: tuple(int, int)
P araw
hybrid
uncompressed
compressed
u<genexpr>
uAbstractPoint.from_bytes.<locals>.<genexpr>
curve
number_to_string
wyuConvert the point to the :term:`raw encoding`.
d uEncode the point into the compressed form.
a_raw_encode
uEncode the point into the hybrid form.
scale
int_to_bytes
uEncode the point according to RFC8032 encoding.
T araw
uncompressed
compressed
hybrid
a_edwards_encode
a_hybrid_encode
a_compressed_encode

Convert the point to a byte string.
The method by default uses the :term:`raw encoding` (specified
by `encoding="raw"`. It can also output points in :term:`uncompressed`,
:term:`compressed`, and :term:`hybrid` formats.
For points on Edwards curves `encoding` is ignored and only the
encoding defined in RFC 8032 is supported.
:return: :term:`raw encoding` of a public on the curve
:rtype: bytes
mult
l aret
uCalculate non-adjacent form of number.
aPointJacobi
a__init__
a_PointJacobi__curve
a_PointJacobi__coords
a_PointJacobi__order
a_PointJacobi__generator
a_PointJacobi__precompute

Initialise a point that uses Jacobi representation internally.
:param CurveFp curve: curve on which the point resides
:param int x: the X parameter of Jacobi representation (equal to x when
converting from affine coordinates
:param int y: the Y parameter of Jacobi representation (equal to y when
converting from affine coordinates
:param int z: the Z parameter of Jacobi representation (equal to 1 when
converting from affine coordinates
:param int order: the point order, must be non zero when using
generator=True
:param bool generator: the point provided is a curve generator, as
such, it will be commonly used with scalar multiplication. This will
cause to precompute multiplication table generation for it
from_bytes

Initialise the object from byte encoding of a point.
The method does accept and automatically detect the type of point
encoding used. It supports the :term:`raw encoding`,
:term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.
:param data: single point encoding of the public key
:type data: :term:`bytes-like object`
:param curve: the curve on which the public key is expected to lay
:type curve: ~ecdsa.ellipticcurve.CurveFp
:param validate_encoding: whether to verify that the encoding of the
point is self-consistent, defaults to True, has effect only
on ``hybrid`` encoding
:type validate_encoding: bool
:param valid_encodings: list of acceptable point encoding formats,
supported ones are: :term:`uncompressed`, :term:`compressed`,
:term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
name). All formats by default (specified with ``None``).
:type valid_encodings: :term:`set-like object`
:param int order: the point order, must be non zero when using
generator=True
:param bool generator: the point provided is a curve generator, as
such, it will be commonly used with scalar multiplication. This
will cause to precompute multiplication table generation for it
:raises `~ecdsa.errors.MalformedPointError`: if the public point does
not lay on the curve or the encoding is invalid
:return: Point on curve
:rtype: PointJacobi
wiadoubler
double
precompute
copy
update
aINFINITY
aPoint
other
uCompare for equality two points with each-other.
Note: only points that lay on the same curve can be equal.
uCompare for inequality two points with each-other.
uReturn the order of the point.
None if it is undefined.
uReturn curve over which the point is defined.

Return affine x coordinate.
This method should be used only when the 'y' coordinate is not needed.
It's computationally more efficient to use `to_affine()` and then
call x() and y() on the returned instance. Or call `scale()`
nd then x() and y() on the returned instance.

Return affine y coordinate.
This method should be used only when the 'x' coordinate is not needed.
It's computationally more efficient to use `to_affine()` and then
call x() and y() on the returned instance. Or call `scale()`
nd then x() and y() on the returned instance.

Return point scaled so that z == 1.
Modifies point in place, returns self.
uReturn point in affine form.
order
uCreate from an affine point.
:param bool generator: set to True to make the point to precalculate
multiplication table - useful for public point when verifying many
signatures (around 100 or so) or for generator points of a curve.
T l
pl uAdd a point to itself with z == 1.
a_double_with_z_1
uAdd a point to itself, arbitrary z.
a_double
uAdd a point to itself.
uadd points when both Z1 and Z2 equal 1
uadd points when Z1 == Z2
uadd points when Z2 == 1
uadd points with arbitrary z
uAdd other to self.
a_add_with_z_1
a_add_with_z_eq
a_add_with_z2_1
a_add_with_z_ne
uadd two points, select fastest method.
from_affine
uThe other point is on different curve
a_add
uAdd two points on elliptic curve.
uMultiply point by an integer.
aX3
aY3
aZ3
uMultiply point by integer with precomputation table.
a_maybe_precompute
a_mul_precompute
a_naf
aX2
aY2
self_naf
other_naf
aZ2
aX1
aY1
aZ1
mAmB_X
mAmB_Y
mAmB_Z
mApB_X
mApB_Y
mApB_Z
pAmB_X
pAmB_Y
pAmB_Z
pApB_X
pApB_Y
pApB_Z

Do two multiplications at the same time, add results.
calculates self*self_mul + other*other_mul
uReturn negated point.
a_Point__curve
a_Point__x
a_Point__y
a_Point__order
contains_point
cofactor
ucurve, x, y, order; order (optional) is the order of this point.

Initialise the object from byte encoding of a point.
The method does accept and automatically detect the type of point
encoding used. It supports the :term:`raw encoding`,
:term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.
:param data: single point encoding of the public key
:type data: :term:`bytes-like object`
:param curve: the curve on which the public key is expected to lay
:type curve: ~ecdsa.ellipticcurve.CurveFp
:param validate_encoding: whether to verify that the encoding of the
point is self-consistent, defaults to True, has effect only
on ``hybrid`` encoding
:type validate_encoding: bool
:param valid_encodings: list of acceptable point encoding formats,
supported ones are: :term:`uncompressed`, :term:`compressed`,
:term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
name). All formats by default (specified with ``None``).
:type valid_encodings: :term:`set-like object`
:param int order: the point order, must be non zero when using
generator=True
:raises `~ecdsa.errors.MalformedPointError`: if the public point does
not lay on the curve or the encoding is invalid
:return: Point on curve
:rtype: Point
uReturn True if the points are identical, False otherwise.
Note: only points that lay on the same curve can be equal.
uReturns False if points are identical, True otherwise.
uAdd one point to another point.
leftmost_bit
uPoint.__mul__.<locals>.leftmost_bit
result
e3
weaself
negative_self
uMultiply a point by an integer.
infinity
u(%d,%d)
uReturn a new point that is twice the old.
aPointEdwards
a_PointEdwards__curve
a_PointEdwards__coords
a_PointEdwards__order
a_PointEdwards__generator
a_PointEdwards__precompute

Initialise a point that uses the extended coordinates internally.

Initialise the object from byte encoding of a point.
`validate_encoding` and `valid_encodings` are provided for
compatibility with Weierstrass curves, they are ignored for Edwards
points.
:param data: single point encoding of the public key
:type data: :term:`bytes-like object`
:param curve: the curve on which the public key is expected to lay
:type curve: ecdsa.ellipticcurve.CurveEdTw
:param None validate_encoding: Ignored, encoding is always validated
:param None valid_encodings: Ignored, there is just one encoding
supported
:param int order: the point order, must be non zero when using
generator=True
:param bool generator: Flag to mark the point as a curve generator,
this will cause the library to pre-compute some values to
make repeated usages of the point much faster
:raises `~ecdsa.errors.MalformedPointError`: if the public point does
not lay on the curve or the encoding is invalid
:return: Initialised point on an Edwards curve
:rtype: PointEdwards
prime
uReturn affine x coordinate.
uReturn affine y coordinate.
uReturn the curve of the point.
uCompare for equality two points with each-other.
Note: only points on the same curve can be equal.
uadd two points, assume sane parameters.
uThe other point is on a different curve.
uAdd point to another.
uDouble the point, assume sane parameters.
uReturn point added to itself.
aT3
T l
l pl
aT2
a__doc__
a__file__
origin
has_location
a__cached__
division
gmpy2
T ampz
gmpy
six
T apython_2_unicode_compatible
python_2_unicode_compatible

T anumbertheory
a_compat
T anormalise_bytes
int_to_bytes
bit_length
bytes_to_int
errors
T aMalformedPointError
util
T aorderlen
string_to_number
number_to_string
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
