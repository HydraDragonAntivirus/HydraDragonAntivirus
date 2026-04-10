# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.bip32.cardano_byron_legacy_bip32


Cardano Byron legacy BIP32 class.
It allows master keys generation and keys derivation for Cardano-Byron (legacy, used by old Daedalus).
Derivation based on BIP32 ed25519 Khovratovich/Law with a different algorithm for master key generation and
keys derivation.
a__qualname__
staticmethod
return
aCurveType
uCardanoByronLegacyBip32.CurveType
a_DefaultKeyNetVersion
uCardanoByronLegacyBip32._DefaultKeyNetVersion
a_KeyDerivator
uCardanoByronLegacyBip32._KeyDerivator
a_MasterKeyGenerator
uCardanoByronLegacyBip32._MasterKeyGenerator
a__orig_bases__
ubip_utils\cardano\bip32\cardano_byron_legacy_bip32.py
u<module bip_utils.cardano.bip32.cardano_byron_legacy_bip32>
T a__class__

a__spec__
.bip_utils.cardano.bip32.cardano_byron_legacy_key_derivator
v
J
aToBytes
T abig
T aendianness

Serialize key index.
Args:
index (Bip32KeyIndex object): Key index
Returns:
bytes: Serialized index
aBytesUtils
aMultiplyScalarNoCarry
l aToInteger
D aendianness
little
aIntegerUtils
aOrder
D abytes_num
endianness
l alittle

Compute the new private key left part for private derivation.
Args:
zl_bytes (bytes)            : Leftmost Z 32-byte
kl_bytes (bytes)            : Leftmost private key 32-byte
curve (EllipticCurve object): EllipticCurve object
Returns:
bytes: Leftmost new private key 32-byte
aAddNoCarry

Compute the new private key right part for private derivation.
Args:
zr_bytes (bytes): Rightmost Z 32-byte
kr_bytes (bytes): Rightmost private key 32-byte
Returns:
bytes: Rightmost new private key 32-byte
aPoint
aCurve
aGenerator

Compute new public key point for public derivation.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
zl_bytes (bytes)              : Leftmost Z 32-byte
Returns:
IPoint object: IPoint object

Module for Cardano Byron legacy BIP32 keys derivation.
References:
https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
https://cips.cardano.org/cips/cip3/byron.md
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.bip.bip32
T aBip32KeyIndex
aBip32KholawEd25519KeyDerivatorBase
aBip32PublicKey
aBip32KeyIndex
aBip32KholawEd25519KeyDerivatorBase
aBip32PublicKey
ubip_utils.ecc
T aEllipticCurve
aIPoint
aEllipticCurve
aIPoint
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
a__prepare__
aCardanoByronLegacyKeyDerivator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
