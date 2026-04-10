# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey._curve

a__qualname__
T na__init__
u_Curve.__init__
a__orig_bases__
uCrypto\PublicKey\_curve.py
u<module Crypto.PublicKey._curve>
T a__class__
T aself
wpwbaorder
aGx
aGy
wGamodulus_bits
oid
context
canonical
openssh
rawlib
validate

a__spec__
.Crypto.PublicKey._edwards
Z
load_pycryptodome_raw_lib
T uCrypto.PublicKey._ed25519

typedef void Point;
int ed25519_new_point(Point **out,
const uint8_t x[32],
const uint8_t y[32],
size_t modsize,
const void *context);
int ed25519_clone(Point **P, const Point *Q);
void ed25519_free_point(Point *p);
int ed25519_cmp(const Point *p1, const Point *p2);
int ed25519_neg(Point *p);
int ed25519_get_xy(uint8_t *xb, uint8_t *yb, size_t modsize, Point *p);
int ed25519_double(Point *p);
int ed25519_add(Point *P1, const Point *P2);
int ed25519_scalar(Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
T Oobject
a__prepare__
aEcLib
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
