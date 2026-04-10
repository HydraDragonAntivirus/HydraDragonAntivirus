# Reconstructed from integrated Nuitka blob
# Module: uecpy.curves

uElliptic Curve abstraction
You should not directly create such Object.
Use `get_curve` to get the predefined curve or create a well-know type
of curve with your parameters
Supported well know elliptic curve are:
- Short Weierstrass form:  y  =x  +a*x+b
- Twisted Edward           a*x  +y  =1+d*x  *y
- Montgomery:              b.y  =x  +a*x  +x.
Attributes:
name (str)       : curve name, the one given to get_curve or return by get_curve_names
size (int)       : bit size of curve
a (int)          : first curve parameter
b d (int)        : second curve parameter
field (int)      : curve field
generator (Point): curve point generator
order (int)      : order of generator
a__qualname__
get_curve
uCurve.get_curve
get_curve_names
uCurve.get_curve_names
a__init__
uCurve.__init__
uCurve._set
a__getattr__
uCurve.__getattr__
a__str__
uCurve.__str__
uCurve.infinity
uCurve.is_on_curve
add_point
uCurve.add_point
sub_point
uCurve.sub_point
mul_point
uCurve.mul_point
neg_point
uCurve.neg_point
uCurve._add_point
uCurve._mul_point
uCurve._neg_point
T l
uCurve.y_recover
uCurve.x_recover
encode_point
uCurve.encode_point
decode_point
uCurve.decode_point
uCurve._sqrt
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uAn elliptic curve defined by the equation: y  =x  +a*x+b.
The given domain must be a dictionary providing the following keys/values:
- name (str)         : curve unique name
- size (int)         : bit size
- a    (int)         : `a` equation coefficient
- b    (int)         : `b` equation coefficient
- field (inf)        : field value
- generator (int[2]) : x,y coordinate of generator
- order (int)        : order of generator
- cofactor (int)     : cofactor
*Note*: you should not use the constructor and only use :func:`Curve.get_curve`
builder to ensure using supported curve.
Args:
domain (dict): a dictionary providing curve parameters
uWeierstrassCurve.__init__
uWeierstrassCurve.is_on_curve
uWeierstrassCurve.y_recover
T FuWeierstrassCurve.encode_point
uWeierstrassCurve.decode_point
uWeierstrassCurve._add_point
uWeierstrassCurve._mul_point
uWeierstrassCurve._neg_point
staticmethod
uWeierstrassCurve._aff2jac
uWeierstrassCurve._jac2aff
uWeierstrassCurve._dbl_jac
uWeierstrassCurve._add_jac
a__orig_bases__
uAn elliptic curve defined by the equation: a*x  +y  =1+d*x  *y
The given domain must be a dictionary providing the following keys/values:
- name (str)         : curve unique name
- size (int)         : bit size
- a    (int)         : `a` equation coefficient
- d    (int)         : `b` equation coefficient
- field (inf)        : field value
- generator (int[2]) : x,y coordinate of generator
- order (int)        : order of generator
*Note*: you should not use the constructor and only use :func:`Curve.get_curve`
builder to ensure using supported curve.
Args:
domain (dict): a dictionary providing curve domain parameters
uTwistedEdwardCurve.__init__
uTwistedEdwardCurve._coord_size
uTwistedEdwardCurve.is_on_curve
uTwistedEdwardCurve.x_recover
uTwistedEdwardCurve.encode_point
uTwistedEdwardCurve.decode_point
decode_scalar_25519
uTwistedEdwardCurve.decode_scalar_25519
encode_scalar_25519
uTwistedEdwardCurve.encode_scalar_25519
uTwistedEdwardCurve._add_point
uTwistedEdwardCurve._mul_point
uTwistedEdwardCurve._neg_point
uTwistedEdwardCurve._aff2ext
uTwistedEdwardCurve._ext2aff
uTwistedEdwardCurve._dbl_ext
uTwistedEdwardCurve._add_ext
uAn elliptic curve defined by the equation: b.y  =x  +a*x  +x.
The given domain must be a dictionary providing the following keys/values:
- name (str)         : curve unique name
- size (int)         : bit size
- a    (int)         : `a` equation coefficient
- b    (int)         : `b` equation coefficient
- field (inf)        : field value
- generator (int[2]) : x,y coordinate of generator
- order (int)        : order of generator
*Note*: you should not use the constructor and only use :func:`Curve.get_curve`
builder to ensure using supported curve.
Args:
domain (dict): a dictionary providing curve domain parameters
uMontgomeryCurve.__init__
uMontgomeryCurve.is_on_curve
uMontgomeryCurve.y_recover
uMontgomeryCurve.encode_point
uMontgomeryCurve.decode_point
uMontgomeryCurve._add_point
uMontgomeryCurve._mul_point
uMontgomeryCurve._neg_point
uMontgomeryCurve._ladder_step
uMontgomeryCurve._ladder_recover_y
uImmutable Elliptic Curve Point.
A Point support the following operator:
- `-` : Point Subtraction.
- `+` : Point Addition, with automatic doubling support.
- `*` : Scalar multiplication, can write as k*P or P*k, with P :class:Point and  k :class:int.
- `==`: Point comparison.
- `-` : Point negation (unary operator).
Attributes:
x (int)       : Affine x coordinate
y (int)       : Affine y coordinate
curve (Curve) : Curve on which the point is define
check(bool)   : Check or not if the built point is on curve
Args:
x (int) :     x coordinate
y (int) :     y coordinate
check (bool): if True enforce x,y is on curve
Raises:
ECPyException : if check=True and x,y is not on curve
T a_x
a_y
a_curve
a_at_infinity
a__slots__
uPoint.infinity
T tuPoint.__init__
uPoint.is_infinity
uPoint.x
uPoint.y
uPoint.has_x
uPoint.has_y
uPoint.curve
uPoint.is_on_curve
recover
uPoint.recover
uPoint.__add__
uPoint.__sub__
uPoint.__mul__
a__rmul__
uPoint.__rmul__
uPoint.__neg__
uPoint.__eq__
uPoint.__str__
add
uPoint.add
sub
uPoint.sub
mul
uPoint.mul
neg
uPoint.neg
eq
uPoint.eq
T l
pnFT EException
uECPyException.__init__
uECPyException.__str__
uecpy\curves.py
u<module ecpy.curves>
T a__class__
T aself
wQT aself
name
T aself
parameters
T aself
value
T aself
domain
T aself
wxwyacurve
check
T aself
scal
T aself
T aself
wsT aX1
aY1
aZ1
aXY1
aX2
aY2
aZ2
aXY2
wqwawAwBwCwDwEat0
t1
t2
t3
wFat4
wGwHaX3
aY3
aXY3
aZ3
T aX1
aY1
aZ1
aX2
aY2
aZ2
wqaZ1Z1
aZ2Z2
aU1
aU2
aS1
aS2
wHwIwJwrwVaX3
aY3
aZ3
T aself
wPwQTaself
wPwQax1
y1
x2
y2
wpainvx2x1
invx2x1_2
invx2x1_3
x3
y3
T aself
wPwQwqwaaPx
aPy
aPz
aPt
wxwywzwtaQx
aQy
aQz
aQt
Taself
wPwQwqaPx
aPy
aPz
wxwywzaQx
aQy
aQz
T wxwywqwzwtT wxwywqT aself
size
T aX1
aY1
aZ1
aXY1
wqwawAwBwCwDwEwGwFwHaX3
aY3
aXY3
aZ3
T aX1
aY1
aZ1
wqwaaXX
aYY
aYYYY
aZZ
wSwMwTaX3
aY3
aZ3
T wxwywzaxy
wqainvz
T wxwywzwqainvz
sqinvz
T aself
xp
yp
xq
zq
xa
za
wpav1
v2
v3
v4
wywxwzT aself
x_qp
x_p
z_p
x_q
z_q
wpat1
t6
t2
t7
t5
t3
t4
t8
t9
x_pq
z_pq
x_2p
z_2p
T aself
wkwPT aself
wkwPasz
x1
x2
z2
x3
z3
wiaki
wpay2
zinv
kx
ky
T aself
wkwPwqwaax1
y1
z1
t1
sz
x2
y2
z2
t2
wiwxwyT aself
wkwPwqwaax1
y1
z1
sz
x2
y2
z2
wiwxwyT aself
wPT aself
params
keys
wkwxwyTwnwpasign
p_1
wswqwrwzwcwtwmwiwbT aself
eP
T aself
eP
wxT aself
eP
wyasign
wxT aself
eP
size
xy
wxwyT wkT aself
wPasize
wxT aself
wPasize
wyT aself
wPacompressed
size
wxwyaenc
T aname
wlacp
cv
T aself
wPwpwxaright
wyaleft
T	aself
wPwqwxasqx
wyasqy
left
right
T	aself
wPwqwxasq3x
wyasqy
left
right
T aself
wkT aself
sign
T aself
wyasign
T aself
wyasign
wqwawdayy
wuwvaxx
wxwIT aself
wxasign
T aself
wxasign
wpaby2
binv
y2
wyT aself
wxasign
wpay2
wya__spec__
.ecpy.ecdsa
g
Q
fmt
l
maxtries
curve
order
ecrand
rnd
self
a_do_sign
msg
pv_key
canonical
u Signs a message hash.
Args:
msg (bytes)                    : the message hash to sign
pv_key (ecpy.keys.ECPrivateKey): key to use for signing
rnd_rfc6979
wdahasher
wVu Signs a message hash  according to  RFC6979
Args:
msg (bytes)                    : the message hash to sign
pv_key (ecpy.keys.ECPrivateKey): key to use for signing
hasher (hashlib)               : hasher conform to hashlib interface
u Signs a message hash  with provided random
Args:
msg (bytes)                    : the hash of message to sign
pv_key (ecpy.keys.ECPrivateKey): key to use for signing
k (ecpy.keys.ECPrivateKey)     : random to use for signing
aECPyException
T uprivate key haz no curve
generator
l aint
from_bytes
big
size
is_infinity
pow
l wxaencode_sig
decode_sig
wWu Verifies a message signature.
Args:
msg (bytes)                   : the message hash to verify the signature
sig (bytes)                   : signature to verify
pu_key (ecpy.keys.ECPublicKey): key to use for verifying
a__doc__
a__file__
origin
has_location
a__cached__
uecpy.curves
T aCurve
aPoint
aCurve
aPoint
uecpy.keys
T aECPublicKey
aECPrivateKey
aECPublicKey
aECPrivateKey
uecpy.formatters
T adecode_sig
encode_sig
ecpy
T aecrand
hashlib
