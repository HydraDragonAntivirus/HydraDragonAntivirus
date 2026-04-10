# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.kholaw.bip32_kholaw_mst_key_generator

uClass container for BIP32 Khovratovich/Law master key generator constants.
a__qualname__
a__annotations__
aHMAC_KEY_ED25519_BYTES
a__prepare__
aBip32KholawEd25519MstKeyGenerator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

BIP32 Khovratovich/Law ed25519 master key generator class.
It allows master keys generation in according to BIP32 Khovratovich/Law for ed25519 curve.
classmethod
seed_bytes
bytes
return
aGenerateFromSeed
uBip32KholawEd25519MstKeyGenerator.GenerateFromSeed
data_bytes
hmac_key_bytes
a__HashRepeatedly
uBip32KholawEd25519MstKeyGenerator.__HashRepeatedly
staticmethod
key_bytes
a__TweakMasterKeyBits
uBip32KholawEd25519MstKeyGenerator.__TweakMasterKeyBits
a__orig_bases__
ubip_utils\bip\bip32\kholaw\bip32_kholaw_mst_key_generator.py
u<module bip_utils.bip.bip32.kholaw.bip32_kholaw_mst_key_generator>
T a__class__
T acls
seed_bytes
kl_bytes
kr_bytes
chain_code_bytes
T acls
data_bytes
hmac_key_bytes
kl_bytes
kr_bytes
T akey_bytes
a__spec__
.bip_utils.bip.bip32.kholaw
$
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip32\kholaw
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
ubip32\kholaw
T aNUITKA_PACKAGE_bip_utils_bip_bip32
u\not_existing
kholaw
T aNUITKA_PACKAGE_bip_utils_bip_bip32_kholaw
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519
T aBip32Ed25519Kholaw
aBip32KholawEd25519
aBip32Ed25519Kholaw
aBip32KholawEd25519
ubip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519_key_derivator
T aBip32KholawEd25519KeyDerivator
aBip32KholawEd25519KeyDerivator
ubip_utils.bip.bip32.kholaw.bip32_kholaw_key_derivator_base
T aBip32KholawEd25519KeyDerivatorBase
aBip32KholawEd25519KeyDerivatorBase
ubip_utils.bip.bip32.kholaw.bip32_kholaw_mst_key_generator
T aBip32KholawEd25519MstKeyGenerator
aBip32KholawEd25519MstKeyGenerator
ubip_utils\bip\bip32\kholaw\__init__.py
u<module bip_utils.bip.bip32.kholaw>

a__spec__
.bip_utils.bip.bip32.slip10.bip32_slip10_ed25519
<
aEllipticCurveTypes
aED25519

Return the elliptic curve type.
Returns:
EllipticCurveTypes: Curve type
aBip32Const
aMAIN_NET_KEY_NET_VERSIONS

Return the default key net version.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
aBip32Slip10Ed25519Derivator

Return the key derivator class.
Returns:
IBip32KeyDerivator class: Key derivator class
aBip32Slip10Ed2519MstKeyGenerator

Return the master key generator class.
Returns:
IBip32MstKeyGenerator class: Master key generator class
uModule for derivation scheme based on ed25519 curve as defined by BIP32 SLIP-0010.
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
T aBip32Slip10Ed25519Derivator
ubip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator
T aBip32Slip10Ed2519MstKeyGenerator
ubip_utils.ecc
T aEllipticCurveTypes
a__prepare__
aBip32Slip10Ed25519
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
