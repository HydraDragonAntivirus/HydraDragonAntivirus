# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.curve.elliptic_curve


Class for a generic elliptic curve.
This is not meant to be complete but just the minimum required to abstract the bip module from
the specific ECC library.
aEllipticCurve
a__qualname__
a__annotations__
name
order
generator
point_cls
pub_key_cls
priv_key_cls
a__init__
uEllipticCurve.__init__
D areturn
Ostr
aName
uEllipticCurve.Name
D areturn
Oint
aOrder
uEllipticCurve.Order
return
aGenerator
uEllipticCurve.Generator
aPointClass
uEllipticCurve.PointClass
aPublicKeyClass
uEllipticCurve.PublicKeyClass
aPrivateKeyClass
uEllipticCurve.PrivateKeyClass
ubip_utils\ecc\curve\elliptic_curve.py
u<module bip_utils.ecc.curve.elliptic_curve>
T a__class__
T aself
T aself
name
order
generator
point_cls
pub_key_cls
priv_key_cls

a__spec__
.bip_utils.ecc.curve.elliptic_curve_getter
x
>
aEllipticCurveTypes
uCurve type is not an enumerative of EllipticCurveTypes
aEllipticCurveGetterConst
aTYPE_TO_INSTANCE

Get the elliptic curve class from its type.
Args:
curve_type (EllipticCurveTypes): Curve type
Returns:
EllipticCurve object: EllipticCurve object
Raises:
TypeError: If curve type is not a EllipticCurveTypes enum
uModule for getting elliptic curves classes.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
ubip_utils.ecc.curve.elliptic_curve
T aEllipticCurve
aEllipticCurve
ubip_utils.ecc.curve.elliptic_curve_types
T aEllipticCurveTypes
ubip_utils.ecc.ed25519.ed25519
T aEd25519
aEd25519
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b
T aEd25519Blake2b
aEd25519Blake2b
ubip_utils.ecc.ed25519_kholaw.ed25519_kholaw
T aEd25519Kholaw
aEd25519Kholaw
ubip_utils.ecc.ed25519_monero.ed25519_monero
T aEd25519Monero
aEd25519Monero
ubip_utils.ecc.nist256p1.nist256p1
T aNist256p1
aNist256p1
ubip_utils.ecc.secp256k1.secp256k1
T aSecp256k1
aSecp256k1
ubip_utils.ecc.sr25519.sr25519
T aSr25519
aSr25519
