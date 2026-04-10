# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey._montgomery

ucurve25519_curve.<locals>.EcLib
a__qualname__
a_curve25519_lib
curve25519_new_point
new_point
curve25519_clone
clone
curve25519_free_point
free_point
curve25519_get_x
get_x
curve25519_scalar
scalar
curve25519_cmp
cmp
a__orig_bases__
a_validate_x25519_point
ucurve25519_curve.<locals>._validate_x25519_point
a_Curve
aInteger
T g
^          T l	l  u1.3.101.110
aCurve25519
wpl g
g	W   F                                   wxuInvalid Curve25519 public key
g                                                                         T uCrypto.PublicKey._curve448

typedef void Curve448Context;
typedef void Curve448Point;
int curve448_new_context(Curve448Context **pec_ctx);
void curve448_free_context(Curve448Context *ec_ctx);
int curve448_new_point(Curve448Point **out,
const uint8_t *x,
size_t len,
const Curve448Context *ec_ctx);
void curve448_free_point(Curve448Point *p);
int curve448_clone(Curve448Point **P, const Curve448Point *Q);
int curve448_get_x(uint8_t *xb, size_t modsize, const Curve448Point *p);
int curve448_scalar(Curve448Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
int curve448_cmp(const Curve448Point *ecp1, const Curve448Point *ecp2);
ucurve448_curve.<locals>.EcLib
a_curve448_lib
curve448_new_context
new_context
curve448_free_context
free_context
curve448_new_point
curve448_clone
curve448_free_point
curve448_get_x
curve448_scalar
curve448_cmp
aVoidPointer
address_of
uError %d initializing Curve448 context
a_validate_x448_point
ucurve448_curve.<locals>._validate_x448_point
T g                                              N        [               T l l  u1.3.101.111
aSmartPointer
get
aCurve448
uInvalid Curve448 public key
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
curve25519_curve
curve448_curve
uCrypto\PublicKey\_montgomery.py
u<module Crypto.PublicKey._montgomery>
T a__class__
a_curve25519_lib
T a__class__
a_curve448_lib
T apoint
p2
x1
x2
deny_list
valid
wpT wpT apoint
deny_list
valid
wpT wpaorder
a_curve25519_lib
aEcLib
a_validate_x25519_point
curve25519
T wpaorder
a_curve448_lib
aEcLib
curve448_context
result
a_validate_x448_point
curve448

a__spec__
.Crypto.PublicKey._nist_ecc
long_to_bytes
T g ?                              l T g     !                         l T g ?                              l aVoidPointer
a_ec_lib
ec_ws_new_context
address_of
c_uint8_ptr
c_size_t
c_ulonglong
getrandbits
T l@uError %d initializing P-192 context
aSmartPointer
get
ec_ws_free_context
a_Curve
aInteger
T g ?                              T g     !                         T g ?                              T g                   t         T g                                l  u1.2.840.10045.3.1.1
uNIST P-192
uecdsa-sha2-nistp192
aEcLib
T g
l T g Z
l T g                                    l uError %d initializing P-224 context
T g
T g Z
T g                                    T g [                                   T g ^                            M   (l  u1.3.132.0.33
uNIST P-224
uecdsa-sha2-nistp224
T g	       @
l T g	Z        u                              l T g	       ?                              l uError %d initializing P-256 context
T g	       @
T g	Z        u                              T g	       ?                              T g	k   _                                   T g	O        4                              l  u1.2.840.10045.3.1.7
uNIST P-256
uecdsa-sha2-nistp256
T g
l0T g     K                  v             	                    l0T g                                                              l0uError %d initializing P-384 context
T g
T g     K                  v             	                    T g                                                              T g                         t                                   T g                                                              l  u1.3.132.0.34
uNIST P-384
uecdsa-sha2-nistp384
T g                                                                                     lBT g                                                d                                   lBT g                                                                                     lBuError %d initializing P-521 context
T g                                                                                     T g                                                d                                   T g                                                                                     T g                                                                                    T g                                                                         N          l  u1.3.132.0.35
uNIST P-521
uecdsa-sha2-nistp521
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
c_size_t
c_uint8_ptr
c_ulonglong
load_pycryptodome_raw_lib
uCrypto.Util.number
T along_to_bytes
uCrypto.Random.random
T agetrandbits
T uCrypto.PublicKey._ec_ws

typedef void EcContext;
typedef void EcPoint;
int ec_ws_new_context(EcContext **pec_ctx,
const uint8_t *modulus,
const uint8_t *b,
const uint8_t *order,
size_t len,
uint64_t seed);
void ec_ws_free_context(EcContext *ec_ctx);
int ec_ws_new_point(EcPoint **pecp,
const uint8_t *x,
const uint8_t *y,
size_t len,
const EcContext *ec_ctx);
void ec_ws_free_point(EcPoint *ecp);
int ec_ws_get_xy(uint8_t *x,
uint8_t *y,
size_t len,
const EcPoint *ecp);
int ec_ws_double(EcPoint *p);
int ec_ws_add(EcPoint *ecpa, EcPoint *ecpb);
int ec_ws_scalar(EcPoint *ecp,
const uint8_t *k,
size_t len,
uint64_t seed);
int ec_ws_clone(EcPoint **pecp2, const EcPoint *ecp);
int ec_ws_cmp(const EcPoint *ecp1, const EcPoint *ecp2);
int ec_ws_neg(EcPoint *p);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
