# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey._point

a__qualname__
l l l l l l	a__orig_bases__
a_Curves
aRLock
L ap192
uNIST P-192
uP-192
prime192v1
secp192r1
nistp192
L ap224
uNIST P-224
uP-224
prime224v1
secp224r1
nistp224
L ap256
uNIST P-256
uP-256
prime256v1
secp256r1
nistp256
L ap384
uNIST P-384
uP-384
prime384v1
secp384r1
nistp384
L ap521
uNIST P-521
uP-521
prime521v1
secp521r1
nistp521
ed25519
aEd25519
ed448
aEd448
curve25519
aCurve25519
aX25519
curve448
aCurve448
aX448
a__contains__
u_Curves.__contains__
a__dir__
u_Curves.__dir__
u_Curves.load
u_Curves.__getitem__
u_Curves.items
uA class to model a point on an Elliptic Curve.
The class supports operators for:
* Adding two points: ``R = S + T``
* In-place addition: ``S += T``
* Negating a point: ``R = -T``
* Comparing two points: ``if S == T: ...`` or ``if S != T: ...``
* Multiplying a point by a scalar: ``R = S*k``
* In-place multiplication by a scalar: ``T *= k``
:ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
:vartype curve: string
:ivar x: The affine X-coordinate of the ECC point
:vartype x: integer
:ivar y: The affine Y-coordinate of the ECC point
:vartype y: integer
:ivar xy: The tuple with affine X- and Y- coordinates
T ap256
a__init__
uEccPoint.__init__
set
uEccPoint.set
a__eq__
uEccPoint.__eq__
a__ne__
uEccPoint.__ne__
a__neg__
uEccPoint.__neg__
uEccPoint.copy
is_point_at_infinity
uEccPoint.is_point_at_infinity
uEccPoint.point_at_infinity
property
uEccPoint.x
wyuEccPoint.y
uEccPoint.xy
uEccPoint.size_in_bytes
uEccPoint.size_in_bits
uEccPoint.double
a__iadd__
uEccPoint.__iadd__
a__add__
uEccPoint.__add__
a__imul__
uEccPoint.__imul__
uEccPoint.__mul__
a__rmul__
uEccPoint.__rmul__
uA class to model a point on an Elliptic Curve,
where only the X-coordinate is exposed.
The class supports operators for:
* Multiplying a point by a scalar: ``R = S*k``
* In-place multiplication by a scalar: ``T *= k``
:ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
:vartype curve: string
:ivar x: The affine X-coordinate of the ECC point
:vartype x: integer
uEccXPoint.__init__
uEccXPoint.set
uEccXPoint.__eq__
uEccXPoint.copy
uEccXPoint.is_point_at_infinity
uEccXPoint.point_at_infinity
uEccXPoint.x
uEccXPoint.size_in_bytes
uEccXPoint.size_in_bits
uEccXPoint.__imul__
uEccXPoint.__mul__
uEccXPoint.__rmul__
uCrypto\PublicKey\_point.py
u<module Crypto.PublicKey._point>
T a__class__
T aself
point
np
T aself
item
T aself
T aself
point
cmp_func
T aself
point
cmp_func
p1
p2
res
T aself
name
curve
T aself
point
add_func
result
T aself
scalar
scalar_func
sb
result
T aself
wxwyacurve
modulus_bytes
xb
yb
new_point
free_func
context
result
T	aself
wxacurve
new_point
free_func
context
modulus_bytes
xb
result
T aself
scalar
np
T aself
point
T aself
neg_func
np
result
T aself
left_hand
T aself
wxwyanp
T aself
wxT aself
double_func
result
T aself
w_T aself
name
w_T aself
name
a_nist_ecc
p192
p224
p256
p384
p521
a_edwards
ed25519
ed448
a_montgomery
curve25519
curve448
T aself
point
clone
free_func
result
T aself
modulus_bytes
xb
get_x
result
T aself
modulus_bytes
xb
yb
get_xy
result
a__spec__
.Crypto.PublicKey
Z
/
aDerSequence
decode
D anr_elements
l D anr_elements
T l l aDerObjectId
aDerBitString
value
aDerNull
uParse a SubjectPublicKeyInfo structure.
It returns a triple with:
* OID (string)
* encoded public key (bytes)
* Algorithm parameters (bytes or None)
encode
D anr_elements
l D anr_elements
;l l l l aDerInteger
T l
T aexplicit
T l l uIncorrect X.509 certificate version
l uExtract subjectPublicKeyInfo from a DER X.509 certificate.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aPublicKey
T aNUITKA_PACKAGE_Crypto_PublicKey
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uCrypto.Util.asn1
T aDerSequence
aDerInteger
aDerBitString
aDerObjectId
aDerNull
a_expand_subject_public_key_info
a_create_subject_public_key_info
a_extract_subject_public_key_info
uCrypto\PublicKey\__init__.py
u<module Crypto.PublicKey>
T aalgo_oid
public_key
params
algorithm
spki
T aencoded
spki
algo
algo_oid
spk
algo_params
T ax509_certificate
certificate
tbs_certificate
index
version

a__spec__
.Crypto.Random
D
2
urandom
uReturn a random byte string of the desired size.
a_UrandomRNG
uReturn a file-like object that outputs cryptographically random bytes.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aRandom
T aNUITKA_PACKAGE_Crypto_Random
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
new
get_random_bytes
a__all__
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
