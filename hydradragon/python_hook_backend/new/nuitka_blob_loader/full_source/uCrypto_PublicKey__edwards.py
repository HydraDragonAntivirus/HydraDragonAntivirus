# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey._edwards

ued25519_curve.<locals>.EcLib
a__qualname__
a_ed25519_lib
ed25519_new_point
new_point
ed25519_clone
clone
ed25519_free_point
free_point
ed25519_cmp
cmp
ed25519_neg
neg
ed25519_get_xy
get_xy
ed25519_double
double
ed25519_add
add
ed25519_scalar
scalar
a__orig_bases__
a_Curve
aInteger
T g	                                         T g
^          T g	!                                      yT g	f                                        l  u1.3.101.112
aEd25519
ussh-ed25519
T uCrypto.PublicKey._ed448

typedef void EcContext;
typedef void PointEd448;
int ed448_new_context(EcContext **pec_ctx);
void ed448_context(EcContext *ec_ctx);
void ed448_free_context(EcContext *ec_ctx);
int ed448_new_point(PointEd448 **out,
const uint8_t x[56],
const uint8_t y[56],
size_t len,
const EcContext *context);
int ed448_clone(PointEd448 **P, const PointEd448 *Q);
void ed448_free_point(PointEd448 *p);
int ed448_cmp(const PointEd448 *p1, const PointEd448 *p2);
int ed448_neg(PointEd448 *p);
int ed448_get_xy(uint8_t *xb, uint8_t *yb, size_t len, const PointEd448 *p);
int ed448_double(PointEd448 *p);
int ed448_add(PointEd448 *P1, const PointEd448 *P2);
int ed448_scalar(PointEd448 *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
ued448_curve.<locals>.EcLib
a_ed448_lib
ed448_new_point
ed448_clone
ed448_free_point
ed448_cmp
ed448_neg
ed448_get_xy
ed448_double
ed448_add
ed448_scalar
aVoidPointer
ed448_new_context
address_of
uError %d initializing Ed448 context
aSmartPointer
get
ed448_free_context
T g                                                                         T g                                              N        [               T g  '                            x                                        T g  4                                                                      l  u1.3.101.113
aEd448
a__doc__
a__file__
origin
has_location
a__cached__
a_curve
T a_Curve
uCrypto.Math.Numbers
T aInteger
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
ed25519_curve
ed448_curve
uCrypto\PublicKey\_edwards.py
u<module Crypto.PublicKey._edwards>
T a__class__
a_ed25519_lib
T a__class__
a_ed448_lib
T wpaorder
aGx
aGy
a_ed25519_lib
aEcLib
ed25519
T
wpaorder
aGx
aGy
a_ed448_lib
aEcLib
ed448_context
result
context
ed448

a__spec__
.Crypto.PublicKey._montgomery
]
^
g	                                         aload_pycryptodome_raw_lib
T uCrypto.PublicKey._curve25519

typedef void Point;
int curve25519_new_point(Point **out,
const uint8_t x[32],
size_t modsize,
const void* context);
int curve25519_clone(Point **P, const Point *Q);
void curve25519_free_point(Point *p);
int curve25519_get_x(uint8_t *xb, size_t modsize, Point *p);
int curve25519_scalar(Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
int curve25519_cmp(const Point *ecp1, const Point *ecp2);
T Oobject
a__prepare__
aEcLib
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
