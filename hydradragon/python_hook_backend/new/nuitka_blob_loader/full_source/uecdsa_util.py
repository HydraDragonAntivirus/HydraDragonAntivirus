# Reconstructed from integrated Nuitka blob
# Module: uecdsa.util

a__qualname__
a__init__
uPRNG.__init__
a__call__
uPRNG.__call__
randrange_from_seed__overshoot_modulo
randrange_from_seed__truncate_bytes
randrange_from_seed__truncate_bits
randrange_from_seed__trytryagain
number_to_string_crop
sigencode_strings_canonize
sigencode_string_canonize
sigencode_der_canonize
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Raised by decoding functions when the signature is malformed.
Malformed in this context means that the relevant strings or integers
do not match what a signature over provided curve would create. Either
because the byte strings have incorrect lengths or because the encoded
values are too large.
a__orig_bases__
sigdecode_string
sigdecode_strings
sigdecode_der
uecdsa\util.py
u<module ecdsa.util>
T aself
numbytes
waT aself
seed
T wxT aorder
bits
bytes
extrabits
T aself
seed
counter
byte
T aent_256
T anumbits
T anum
order
wlafmt_str
string
T aorder
T aorder
entropy
upper_2
upper_256
ent_256
ent_2
rand_num
T aseed
order
base
number
T aseed
order
hashmod
bits
maxbytes
base
topbits
number
T aseed
order
hashmod
bits
a_bytes
extrabits
base
number
T aseed
order
bits
bytes
extrabits
generate
extrabyte
guess
T asig_der
order
rs_strings
empty
wrarest
wsT asignature
order
wlwrwsT ars_strings
order
r_str
s_str
wlwrwsT wrwsaorder
T wrwsaorder
r_str
s_str
T astring
T astring
order
wla__spec__
.ecpy
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_ecpy
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uecpy\__init__.py
u<module ecpy>

a__spec__
.ecpy.curve_defs
a__doc__
a__file__
origin
has_location
a__cached__
weierstrass
aWEIERSTRASS
twistededward
aTWISTEDEDWARD
montgomery
aMONTGOMERY
name
stark256
type
size
l  afield
g
generator
T g	                                         g                                         aorder
g
cofactor
wawbg	                        &               afrp256v1
g	                                         T g	                                          g	a                                 1     g	                                        g	                                         g	          Q                              asecp521r1
l  g                                                                                     T g                                                                                    g                                                                         N          g                                                                                     g                                                                                     g                                                d                                   asecp384r1
l  g
T g                         t                                   g                                                              g                                                              g
g     K                  v             	                    asecp256k1
g	                                          T g	y                                        g	H                                        g	                                          l asecp256r1
g	       @
T g	k   _                                   g	O        4                              g	       ?                              g	       @
g	Z        u                              asecp224k1
l  g                                     T g P             ~                    g ?                                 g
;               l asecp224r1
g
T g [                                   g ^                            M   (g                                    g                                     g Z
secp192k1
l  g ?                              T g 6        +                   g &                             g ?                              l asecp192r1
g ?                              T g                   t         g                                g ?                              g ?                              g     !                         asecp160k1
l  g                           T g                           g          c               g
secp160r1
g                           T g 	                         g          Z        B     g
g                           g                          asecp160r2
T g
g                          g
g                           g                    F     uBrainpool-p512t1
l  g                           #                                                       T g                                                                        M          g                                                                                 g                           #                                                       g                           #                                                       g                                                                                    uBrainpool-p512r1
T g                                                                                  g                                                                 r               g            w                                      J                              g  {   X        c                                                              [uBrainpool-p384t1
g                                                       t     T g                                   v                         g                                                              g                                                              g                                                       t     g     g                                                      uBrainpool-p384r1
T g                                                              g                                                       (     g                    -                                 J     gJ                                                            uBrainpool-p320t1
l  g                                                    T g                                                   g                               X                    g                                             i     g                                                    g                                    *               uBrainpool-p320r1
T g                                                     g S                                                  g                                                     g                                                   }uBrainpool-p256r1
g	                                          T g	               K             w          g	T                                        g	                                          g	}        X                              g	&                                        uBrainpool-p256t1
T g	                                          g	-        s                              g	                                          g	f                                        uBrainpool-p224r1
g k                                   T g          ~                         g ,                                   g k                                   g 4                  T               g                                     uBrainpool-p224t1
g k                                   g %                                 ST g 5                                   g          >             9          uBrainpool-p192r1
g 0                              T g 0                              g                    )          g 0                              g                                g                                uBrainpool-p192t1
T g                                g
g 0                              g                                uBrainpool-p160r1
g                          T g               R          g                           g                          g               W          g                           uBrainpool-p160t1
T g                           g                           g                          g                           uNIST-P256
uNIST-P224
uNIST-P192
aEd448
l  g                                                                         T g  '                            x                                        g  4                                                                      g                                              N        [               l wdg                                                                         aEd25519
g	                                         T g	!                                      yg	f                                        g
^          l g	R                         (          aCurve448
T l g  >                                                                     l  	aCurve25519
T l	g	_                  [                  	l   acurves
uecpy\curve_defs.py
u<module ecpy.curve_defs>

a__spec__
.ecpy.curves
!@
o aCurve
a_curves_cache
curve_defs
curves
name
type
aWEIERSTRASS
aWeierstrassCurve
aTWISTEDEDWARD
aTwistedEdwardCurve
aMONTGOMERY
aMontgomeryCurve
uReturn a Curve object  according to its name
Args:
name (str) : curve name to retrieve
Returns:
Curve:          Curve object, or None if curve is unknown
u Returns all known curve names
Returns:
tuple:  list of names as str
uAbstract method __init__
self
a_domain
generator
aPoint
a_infinity_point
a_at_infinity
replace
T w,w
uAbstract method is_on_curve
uCheck if P is on this curve
This function ignores the default curve attach to P
Args:
P (Point): Point to check
Returns:
bool: True if P is on curve, False else
u Returns the sum of P and Q
Args:
P (Point): first  point to add
Q (Point): second point to add
Returns:
Point: A new Point R = P+Q
Raises:
ECPyException : with "Point not on curve", if Point R is not on              curve,  thus meaning either P or Q was not on.
u Returns the difference of P and Q
Args:
P (Point): first  point to subtract with
Q (Point): second point to subtract to
Returns:
Point: A new Point R = P-Q
Raises:
ECPyException : with "Point not on curve", if Point R is not on              curve,  thus meaning either P or Q was not on.
u Returns the scalar multiplication  P with k.
This function ignores the default curve attach to P and Q,
nd assumes P and Q are on this curve.
Args:
P (Point): point to mul_point
k (int)  : scalar to multiply
Returns:
Point: A new Point R = k*Q
Raises:
ECPyException : with "Point not on curve", if Point R is not
on curve, thus meaning P was not on.
u Returns R, R = -P.
Args:
P (Point): point to mul_point
Returns:
Point: A new Point R = -Q
Raises:
ECPyException : with "Point not on curve", if Point R is not
on curve, thus meaning P was not on.
uAbstract method add_point
uAbstract method mul_point
uAbstract method neg_point
uAbstract method y_recover
u Recover the y coordinate according to x
This method is currently only  supported for Weierstrass and Montgomery curve
Args:
x the coordinate
sign the sign of y
Returns:
y coordinate
uAbstract method x_recover
u Recover the x coordinate according to y
This method is currently only supported for TwiestedEdward curve
Args:
y the coordinate
sign the sign of x
Returns:
x coordinate
uAbstract method encode_point
u encode/compress a point according to its curve
uAbstract method _point decode_point
u decode/decompress a point according to its curve
pow
l wqwsl wzwpwtwmwcwiwru Generic Tonelli   Shanks algorithm
a_set
T	aname
type
size
wawbafield
generator
order
cofactor
u Built an new short Weierstrass curve with the provided parameters.
field
wxwywawbu See :func:`Curve.is_on_curve`
a_sqrt
w asize
l l ato_bytes
big
extend
u Encodes a point P according to *P1363-2000*.
Args:
P: point to encode
Returns:
bytes : encoded point [04 | x | y] or [02 | x | sign]
int
from_bytes
y_recover
aECPyException
T uInvalid encoded point
u Decodes a point P according to *P1363-2008*.
Args:
eP (bytes)    : encoded point
curve (Curve) : curve on witch point is
Returns:
Point : decoded point
a_aff2jac
a_dbl_jac
a_add_jac
a_jac2aff
infinity
u See :func:`Curve.add_point`
:l nnw1ax2
y2
z2
x1
y1
z1
u See :func:`Curve.mul_point`
l T aname
type
size
wawdafield
generator
order
u Built an new short twisted Edward curve with the provided parameters.
aEd25519
l aEd448
l9u%s not supported
curve
wdaxx
u Retrieves the x coordinate according to the y one,             such that point (x,y) is on curve.
Args:
y (int): y coordinate
sign (int): sign of x
Returns:
int: the computed x coordinate
a_coord_size
little
l  u Encodes a point P according to *draft_irtf-cfrg-eddsa-04*.
Args:
P: point to encode
Returns:
bytes : encoded point
q  ax_recover
u Decodes a point P according to *draft_irtf-cfrg-eddsa-04*.
Args:
eP (bytes)    : encoded point
curve (Curve) : curve on witch point is
Returns:
Point : decoded point
l  l l l@u decode scalar according to RF7748 and draft-irtf-cfrg-eddsa
Args:
k (bytes) : scalar to decode
Returns:
int: decoded scalar
T l alittle
u encode scalar according to RF7748 and draft-irtf-cfrg-eddsa
Args:
k (int) : scalar to encode
Returns:
bytes: encoded scalar
a_aff2ext
a_dbl_ext
a_add_ext
a_ext2aff
t2
t1
T aname
type
size
wawbafield
generator
order
a24
has_y
u Encodes a point P according to *RFC7748*.
Args:
P: point to encode
Returns:
bytes : encoded point
u Decodes a point P according to *RFC7748*.
Args:
eP (bytes)    : encoded point
curve (Curve) : curve on witch point is
Returns:
Point : decoded point
a_mul_point
a_ladder_step
x3
z3
a_ladder_recover_y

u Return the unique (singleton) point at infinity
Returns:
Point : infinity Point
a_x
a_y
a_curve
is_on_curve
T uPoint not on curve
u Tell is this pointn is the inifinity one
Returns:
bool: true if self is infinity
is_infinity
T aInfinity
T ux coordinate not set
u X affine coordinate of this point
Returns:
x coordinate
Raises:
ECPyException: if point is infinity
ECPyException: if point has no x coordinate
T uy coordinate not set
u Y affine coordinate of this point
Returns:
x coordinate
Raises:
ECPyException: if point is infinity
ECPyException: if point has no y coordinate
u Tell if this point has y coordinate
Returns:
Trueu if x coordinate is set, False else
u Tell if this point has y coordinate
Returns:
Trueu if y coordinate is set, False else
u Returned the curve on which this point is defined
Returns:
Curve: this point curve
u" Tells if this point is on the curve
Returns:
bool: True if point on curve, False else
u Recvoer the missing corrdinate according to the know one and the provided sign of the missing one
Args:
sign (int): zero or one
T u__add__: points on same curve
a_add_point
u__add__: type not supported: %s
T u__sub__: points on same curve
u__sub__: type not supported: %s
order
u__mul__: type not supported: %s
a__mul__
a_neg_point
ueq: type not supported: %s
inf
has_x
u(0x%x , 0x%x)
u(0x%x , .)
u(. , 0x%x)
u(. , .)
a__add__
u Return the addition of self and provided point.
Args:
Q(Point): Point to add
Returns:
Point: self+Q
a__sub__
u Return the subtraction of felf and provided point.
Args:
Q(Point): Point to subtract
Returns:
Point: self-Q
u Return the scalar multiplication of self by k
Args:
k(int): the scalar to multiply
Returns:
Point: k*self
a__neg__
u Return the opposite self point bycallinf Curve.neg function
Returns:
Point: -self
a__eq__
u Tells is the provided Point and this point have the same coordinate.
Args:
Q(Point): Point to check the equality
Returns:
bool: True if P==Q, False else.
value
rept
u Elliptic Curve and Point manipulation
.. moduleauthor:: C  dric Mesnil <cedric.mesnil@ubinity.com>
a__doc__
a__file__
origin
has_location
a__cached__
binascii
random

T acurve_defs
