# Reconstructed from integrated Nuitka blob
# Module: uecdsa.ellipticcurve


:term:`Short Weierstrass Elliptic Curve <short Weierstrass curve>` over a
prime field.
a__qualname__
T nuCurveFp.__init__
a__eq__
uCurveFp.__eq__
a__ne__
uCurveFp.__ne__
a__hash__
uCurveFp.__hash__
uCurveFp.p
uCurveFp.a
uCurveFp.b
uCurveFp.cofactor
uCurveFp.contains_point
a__str__
uCurveFp.__str__
a__orig_bases__
uParameters for a Twisted Edwards Elliptic Curve
T nnuCurveEdTw.__init__
uCurveEdTw.__eq__
uCurveEdTw.__ne__
uCurveEdTw.__hash__
uCurveEdTw.contains_point
uCurveEdTw.p
uCurveEdTw.a
uCurveEdTw.d
hash_func
uCurveEdTw.hash_func
uCurveEdTw.cofactor
uCurveEdTw.__str__
aAbstractPoint
uClass for common methods of elliptic curve points.
staticmethod
uAbstractPoint._from_raw_encoding
uAbstractPoint._from_compressed
classmethod
uAbstractPoint._from_hybrid
uAbstractPoint._from_edwards
T tnuAbstractPoint.from_bytes
uAbstractPoint._raw_encode
uAbstractPoint._compressed_encode
uAbstractPoint._hybrid_encode
uAbstractPoint._edwards_encode
T araw
to_bytes
uAbstractPoint.to_bytes
uAbstractPoint._naf

Point on a short Weierstrass elliptic curve. Uses Jacobi coordinates.
In Jacobian coordinates, there are three parameters, X, Y and Z.
They correspond to affine parameters 'x' and 'y' like so:
x = X / Z
y = Y / Z
T nFuPointJacobi.__init__
T tnnFuPointJacobi.from_bytes
uPointJacobi._maybe_precompute
a__getstate__
uPointJacobi.__getstate__
a__setstate__
uPointJacobi.__setstate__
uPointJacobi.__eq__
uPointJacobi.__ne__
uPointJacobi.order
uPointJacobi.curve
uPointJacobi.x
uPointJacobi.y
uPointJacobi.scale
to_affine
uPointJacobi.to_affine
T FuPointJacobi.from_affine
uPointJacobi._double_with_z_1
uPointJacobi._double
uPointJacobi.double
uPointJacobi._add_with_z_1
uPointJacobi._add_with_z_eq
uPointJacobi._add_with_z2_1
uPointJacobi._add_with_z_ne
a__radd__
uPointJacobi.__radd__
uPointJacobi._add
a__add__
uPointJacobi.__add__
a__rmul__
uPointJacobi.__rmul__
uPointJacobi._mul_precompute
a__mul__
uPointJacobi.__mul__
mul_add
uPointJacobi.mul_add
a__neg__
uPointJacobi.__neg__
uA point on a short Weierstrass elliptic curve. Altering x and y is
forbidden, but they can be read by the x() and y() methods.
uPoint.__init__
T tnnuPoint.from_bytes
uPoint.__eq__
uPoint.__ne__
uPoint.__neg__
uPoint.__add__
uPoint.__mul__
uPoint.__rmul__
uPoint.__str__
uPoint.double
uPoint.x
uPoint.y
uPoint.curve
uPoint.order
uPoint on Twisted Edwards curve.
Internally represents the coordinates on the curve using four parameters,
X, Y, Z, T. They correspond to affine parameters 'x' and 'y' like so:
x = X / Z
y = Y / Z
x*y = T / Z
uPointEdwards.__init__
T nnnFuPointEdwards.from_bytes
uPointEdwards._maybe_precompute
uPointEdwards.x
uPointEdwards.y
uPointEdwards.curve
uPointEdwards.order
uPointEdwards.scale
uPointEdwards.__eq__
uPointEdwards.__ne__
uPointEdwards._add
uPointEdwards.__add__
uPointEdwards.__radd__
uPointEdwards._double
uPointEdwards.double
uPointEdwards.__rmul__
uPointEdwards._mul_precompute
uPointEdwards.__mul__
T nnnuecdsa\ellipticcurve.py
T a.0
wiu<module ecdsa.ellipticcurve>
T a__class__
T aself
other
wpwlax3
y3
T aself
other
wpwaaX1
aY1
aZ1
aT1
aX2
aY2
aZ2
aT2
aX3
aY3
aZ3
aT3
T aself
other
wpaX1
aY1
aZ1
aX2
aY2
aZ2
aX3
aY3
aZ3
T aself
other
wpT aself
other
T aself
other
x1
y1
z1
t1
x2
y2
z2
t2
wpaxn1
xn2
yn1
yn2
T aself
other
x1
y1
z1
x2
y2
z2
wpazz1
zz2
T aself
state
T aself
T aself
wpwawdwhahash_func
T aself
wpwawbwhT aself
curve
wxwyaorder
a__class__
T	aself
curve
wxwywzwtaorder
generator
a__class__
T aself
curve
wxwywzaorder
generator
a__class__
T aself
other
leftmost_bit
weae3
negative_self
wiaresult
T aself
other
aX2
aY2
aZ2
aT2
aX3
aY3
aZ3
aT3
wpwaa_double
a_add
wiTaself
other
aX2
aY2
w_aX3
aY3
aZ3
wpwaa_double
a_add
wiT aself
wxwywzT aself
aX1
aY1
aZ1
aT1
aX2
aY2
aZ2
aT2
wpwawAwBwCwDwEwFwGwHaX3
aY3
aT3
aZ3
T aself
aX1
aY1
aZ1
aX2
aY2
aZ2
wpT aself
aX1
aY1
aZ1
aX2
aY2
wpaZ1Z1
aU2
aS2
wHaHH
wIwJwrwVaX3
aY3
aZ3
T aself
aX1
aY1
aX2
aY2
wpwHaHH
wIwJwrwVaX3
aY3
aZ3
T aself
aX1
aY1
aZ1
aX2
aY2
wpwAwBwCwDaX3
aY3
aZ3
T aself
aX1
aY1
aZ1
aX2
aY2
aZ2
wpaZ1Z1
aZ2Z2
aU1
aU2
aS1
aS2
wHwIwJwrwVaX3
aY3
aZ3
T aself
prime
x_str
T aself
aX1
aY1
aZ1
aT1
wpwawAwBwCwDwEwGwFwHaX3
aY3
aT3
aZ3
T aself
aX1
aY1
aZ1
wpwaaXX
aYY
aYYYY
aZZ
wSwMwTaY3
aZ3
Taself
aX1
aY1
wpwaaXX
aYY
aYYYY
wSwMwTaY3
aZ3
T aself
wxwywpaenc_len
y_str
T	adata
curve
is_even
wxwpaalpha
beta
wewyT
cls
curve
data
wpaexp_len
x_0
wyax2
wxweT acls
data
raw_encoding_length
validate_encoding
wxwyT adata
raw_encoding_length
xs
ys
coord_x
coord_y
T aself
raw_enc
T
self
order
precompute
wiacoord_x
coord_y
coord_z
coord_t
prime
doubler
T aself
order
precompute
wiacoord_x
coord_y
coord_z
doubler
Taself
other
aX3
aY3
aZ3
aT3
wpwaa_add
aX2
aY2
aT2
rem
T	aself
other
aX3
aY3
aZ3
wpa_add
aX2
aY2
T amult
ret
nd
T aself
prime
x_str
y_str
T aself
wxwyT aself
wpwawlax3
y3
T aself
aX1
aY1
aZ1
aT1
wpwaaX3
aY3
aZ3
aT3
T	aself
aX1
aY1
aZ1
wpwaaX3
aY3
aZ3
T apoint
generator
T	acls
curve
data
validate_encoding
valid_encodings
key_len
raw_encoding_length
coord_x
coord_y
T	acls
curve
data
validate_encoding
valid_encodings
order
coord_x
coord_y
a__class__
T
cls
curve
data
validate_encoding
valid_encodings
order
generator
coord_x
coord_y
a__class__
T aself
data
T wxaresult
T!aself
self_mul
other
other_mul
aX3
aY3
aZ3
wpwaaX1
aY1
aZ1
aX2
aY2
aZ2
a_double
a_add
mAmB_X
mAmB_Y
mAmB_Z
pAmB_X
pAmB_Y
pAmB_Z
mApB_X
mApB_Y
mApB_Z
pApB_X
pApB_Y
pApB_Z
self_naf
other_naf
wAwBT
self
aX1
aY1
aZ1
w_wpaz_inv
wxwywtT aself
wxwywzwpaz_inv
zz_inv
T aself
w_wywzwxT aself
encoding
curve
T aself
aX1
w_aZ1
wpaz_inv
T aself
wxw_wzwpT aself
w_aY1
aZ1
wpaz_inv
T aself
w_wywzwpa__spec__
.ecdsa.errors
p
a__doc__
a__file__
origin
has_location
a__cached__
T EAssertionError
a__prepare__
aMalformedPointError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
