# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519


BIP32 Khovratovich/Law ed25519 class.
It allows master keys generation and keys derivation using ed25519 curve.
a__qualname__
staticmethod
return
aCurveType
uBip32KholawEd25519.CurveType
a_DefaultKeyNetVersion
uBip32KholawEd25519._DefaultKeyNetVersion
a_KeyDerivator
uBip32KholawEd25519._KeyDerivator
a_MasterKeyGenerator
uBip32KholawEd25519._MasterKeyGenerator
a__orig_bases__
aBip32Ed25519Kholaw
ubip_utils\bip\bip32\kholaw\bip32_kholaw_ed25519.py
u<module bip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519>
T a__class__

a__spec__
.bip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519_key_derivator
V
aToBytes
T alittle
T aendianness

Serialize key index.
Args:
index (Bip32KeyIndex object): Key index
Returns:
bytes: Serialized index
aBytesUtils
aToInteger
:nl nD aendianness
little
l aOrder
aBip32KeyError
T uComputed child key is not valid, very unlucky index
aIntegerUtils
aEd25519KholawPrivateKey
aLength
l alittle
T abytes_num
endianness

Compute the new private key left part for private derivation.
Args:
zl_bytes (bytes)            : Leftmost Z 32-byte
kl_bytes (bytes)            : Leftmost private key 32-byte
curve (EllipticCurve object): EllipticCurve object
Returns:
bytes: Leftmost new private key 32-byte
l  u
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
zl_bytes (bytes)               : Leftmost Z 32-byte
Returns:
IPoint object: IPoint object

Module for BIP32 Khovratovich/Law keys derivation.
Reference: https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.bip.bip32.bip32_ex
T aBip32KeyError
ubip_utils.bip.bip32.bip32_key_data
T aBip32KeyIndex
aBip32KeyIndex
ubip_utils.bip.bip32.bip32_keys
T aBip32PublicKey
aBip32PublicKey
ubip_utils.bip.bip32.kholaw.bip32_kholaw_key_derivator_base
T aBip32KholawEd25519KeyDerivatorBase
aBip32KholawEd25519KeyDerivatorBase
ubip_utils.ecc
T aEd25519KholawPrivateKey
aEllipticCurve
aIPoint
aEllipticCurve
aIPoint
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
a__prepare__
aBip32KholawEd25519KeyDerivator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
