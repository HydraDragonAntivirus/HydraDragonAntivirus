# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.conf

uECC configuration class.
aEccConf
a__qualname__
a__annotations__
aUSE_COINCURVE
ubip_utils\ecc\conf.py
u<module bip_utils.ecc.conf>
T a__class__

a__spec__
.bip_utils.ecc
h
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ecc
T aNUITKA_PACKAGE_bip_utils_ecc
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.ecc.common.ikeys
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
ubip_utils.ecc.curve.elliptic_curve
T aEllipticCurve
aEllipticCurve
ubip_utils.ecc.curve.elliptic_curve_getter
T aEllipticCurveGetter
aEllipticCurveGetter
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
aEllipticCurveTypes
ubip_utils.ecc.ed25519.ed25519
T aEd25519
aEd25519
ubip_utils.ecc.ed25519.ed25519_keys
T aEd25519PrivateKey
aEd25519PublicKey
aEd25519PrivateKey
aEd25519PublicKey
ubip_utils.ecc.ed25519.ed25519_point
T aEd25519Point
aEd25519Point
ubip_utils.ecc.ed25519.ed25519_utils
T aEd25519Utils
aEd25519Utils
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b
T aEd25519Blake2b
aEd25519Blake2b
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_keys
T aEd25519Blake2bPrivateKey
aEd25519Blake2bPublicKey
aEd25519Blake2bPrivateKey
aEd25519Blake2bPublicKey
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_point
T aEd25519Blake2bPoint
aEd25519Blake2bPoint
ubip_utils.ecc.ed25519_kholaw.ed25519_kholaw
T aEd25519Kholaw
aEd25519Kholaw
ubip_utils.ecc.ed25519_kholaw.ed25519_kholaw_keys
T aEd25519KholawPrivateKey
aEd25519KholawPublicKey
aEd25519KholawPrivateKey
aEd25519KholawPublicKey
ubip_utils.ecc.ed25519_kholaw.ed25519_kholaw_point
T aEd25519KholawPoint
aEd25519KholawPoint
ubip_utils.ecc.ed25519_monero.ed25519_monero
T aEd25519Monero
aEd25519Monero
ubip_utils.ecc.ed25519_monero.ed25519_monero_keys
T aEd25519MoneroPrivateKey
aEd25519MoneroPublicKey
aEd25519MoneroPrivateKey
aEd25519MoneroPublicKey
ubip_utils.ecc.ed25519_monero.ed25519_monero_point
T aEd25519MoneroPoint
aEd25519MoneroPoint
ubip_utils.ecc.nist256p1.nist256p1
T aNist256p1
aNist256p1
ubip_utils.ecc.nist256p1.nist256p1_keys
T aNist256p1PrivateKey
aNist256p1PublicKey
aNist256p1PrivateKey
aNist256p1PublicKey
ubip_utils.ecc.nist256p1.nist256p1_point
T aNist256p1Point
aNist256p1Point
ubip_utils.ecc.secp256k1.secp256k1
T aSecp256k1
aSecp256k1Point
aSecp256k1PrivateKey
aSecp256k1PublicKey
aSecp256k1
aSecp256k1Point
aSecp256k1PrivateKey
aSecp256k1PublicKey
ubip_utils.ecc.sr25519.sr25519
T aSr25519
aSr25519
ubip_utils.ecc.sr25519.sr25519_keys
T aSr25519PrivateKey
aSr25519PublicKey
aSr25519PrivateKey
aSr25519PublicKey
ubip_utils.ecc.sr25519.sr25519_point
T aSr25519Point
aSr25519Point
ubip_utils\ecc\__init__.py
u<module bip_utils.ecc>

a__spec__
.bip_utils.ecc.curve
m
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uecc\curve
T aNUITKA_PACKAGE_bip_utils_ecc
u\not_existing
curve
T aNUITKA_PACKAGE_bip_utils_ecc_curve
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\ecc\curve\__init__.py
u<module bip_utils.ecc.curve>

a__spec__
.bip_utils.ecc.curve.elliptic_curve
m
?
m_name
m_order
m_generator
m_point_cls
m_pub_key_cls
m_priv_key_cls

Construct class.
Args:
name (str)                      : Curve name
order (int)                     : Curve order
generator (IPoint object)       : Curve generator point
point_cls (IPoint class)        : Point class
pub_key_cls (IPublicKey class)  : Public key class
priv_key_cls (IPrivateKey class): Private key class

Return the curve name.
Returns:
str: Curve name

Return the curve order.
Returns:
int: Curve order

Get the curve generator point.
Returns:
IPoint object: IPoint object

Return the point class.
Returns:
IPoint class: Point class

Return the public key class.
Returns:
IPublicKey class: Public key class

Return the private key class.
Returns:
IPrivateKey class: Private key class
uModule with helper class for elliptic curves.
a__doc__
a__file__
origin
has_location
a__cached__
aType
ubip_utils.ecc.common.ikeys
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
