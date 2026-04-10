# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator

uClass container for BIP32 SLIP-0010 master key generator constants.
a__qualname__
a__annotations__
l ced25519 seed
cNist256p1 seed
cBitcoin seed

BIP32 SLIP-0010 generic master key generator class.
It allows master keys generation in according to BIP32 SLIP-0010.
seed_bytes
curve_type
return
T Obytes
pu_Bip32Slip10MstKeyGenerator.GenerateFromSeed
a__prepare__
aBip32Slip10Ed2519MstKeyGenerator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

BIP32 SLIP-0010 ed25519 master key generator class.
It allows master keys generation in according to BIP32 SLIP-0010 for ed25519 curve.
classmethod
bytes
uBip32Slip10Ed2519MstKeyGenerator.GenerateFromSeed
a__orig_bases__
aBip32Slip10Nist256p1MstKeyGenerator

BIP32 SLIP-0010 nist256p1 master key generator class.
It allows master keys generation in according to BIP32 SLIP-0010 for nist256p1 curve.
uBip32Slip10Nist256p1MstKeyGenerator.GenerateFromSeed
aBip32Slip10Secp256k1MstKeyGenerator

BIP32 SLIP-0010 secp256k1 master key generator class.
It allows master keys generation in according to BIP32 SLIP-0010 for secp256k1 curve.
uBip32Slip10Secp256k1MstKeyGenerator.GenerateFromSeed
ubip_utils\bip\bip32\slip10\bip32_slip10_mst_key_generator.py
u<module bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator>
T a__class__
T acls
seed_bytes
T aseed_bytes
hmac_key_bytes
curve_type
hmac_half_len
priv_key_cls
hmac
hmac_data
success
a__spec__
.bip_utils.bip.bip32.slip10.bip32_slip10_nist256p1
<
aEllipticCurveTypes
aNIST256P1

Return the elliptic curve type.
Returns:
EllipticCurveTypes: Curve type
aBip32Const
aMAIN_NET_KEY_NET_VERSIONS

Return the default key net version.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
aBip32Slip10EcdsaDerivator

Return the key derivator class.
Returns:
IBip32KeyDerivator class: Key derivator class
aBip32Slip10Nist256p1MstKeyGenerator

Return the master key generator class.
Returns:
IBip32MstKeyGenerator class: Master key generator class
uModule for derivation scheme based on nist256p1 curve as defined by BIP32 SLIP-0010.
a__doc__
a__file__
origin
has_location
a__cached__
aType
ubip_utils.bip.bip32.base
T aBip32Base
aIBip32KeyDerivator
aIBip32MstKeyGenerator
aBip32Base
aIBip32KeyDerivator
aIBip32MstKeyGenerator
ubip_utils.bip.bip32.bip32_const
T aBip32Const
ubip_utils.bip.bip32.bip32_key_net_ver
T aBip32KeyNetVersions
aBip32KeyNetVersions
ubip_utils.bip.bip32.slip10.bip32_slip10_key_derivator
T aBip32Slip10EcdsaDerivator
ubip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator
T aBip32Slip10Nist256p1MstKeyGenerator
ubip_utils.ecc
T aEllipticCurveTypes
a__prepare__
aBip32Slip10Nist256p1
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
