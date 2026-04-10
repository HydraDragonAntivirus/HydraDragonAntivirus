# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.slip10.bip32_slip10_nist256p1


BIP32 SLIP-0010 nist256p1 class.
It allows master keys generation and keys derivation using nist256p1 curve.
a__qualname__
staticmethod
return
aCurveType
uBip32Slip10Nist256p1.CurveType
a_DefaultKeyNetVersion
uBip32Slip10Nist256p1._DefaultKeyNetVersion
a_KeyDerivator
uBip32Slip10Nist256p1._KeyDerivator
a_MasterKeyGenerator
uBip32Slip10Nist256p1._MasterKeyGenerator
a__orig_bases__
aBip32Nist256p1
ubip_utils\bip\bip32\slip10\bip32_slip10_nist256p1.py
u<module bip_utils.bip.bip32.slip10.bip32_slip10_nist256p1>
T a__class__

a__spec__
.bip_utils.bip.bip32.slip10.bip32_slip10_secp256k1
<
aEllipticCurveTypes
aSECP256K1

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
aBip32Slip10Secp256k1MstKeyGenerator

Return the master key generator class.
Returns:
IBip32MstKeyGenerator class: Master key generator class
uModule for derivation scheme based on secp256k1 curve as defined by BIP32 SLIP-0010.
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
T aBip32Slip10Secp256k1MstKeyGenerator
ubip_utils.ecc
T aEllipticCurveTypes
a__prepare__
aBip32Slip10Secp256k1
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
