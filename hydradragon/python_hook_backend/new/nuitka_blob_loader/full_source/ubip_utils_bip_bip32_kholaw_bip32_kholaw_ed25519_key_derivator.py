# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519_key_derivator


BIP32 Khovratovich/Law ed25519 key derivator class.
It allows keys derivation for ed25519 curves in according to BIP32 Khovratovich/Law.
a__qualname__
staticmethod
index
return
bytes
a_SerializeIndex
uBip32KholawEd25519KeyDerivator._SerializeIndex
zl_bytes
kl_bytes
curve
a_NewPrivateKeyLeftPart
uBip32KholawEd25519KeyDerivator._NewPrivateKeyLeftPart
zr_bytes
kr_bytes
a_NewPrivateKeyRightPart
uBip32KholawEd25519KeyDerivator._NewPrivateKeyRightPart
pub_key
a_NewPublicKeyPoint
uBip32KholawEd25519KeyDerivator._NewPublicKeyPoint
a__orig_bases__
ubip_utils\bip\bip32\kholaw\bip32_kholaw_ed25519_key_derivator.py
u<module bip_utils.bip.bip32.kholaw.bip32_kholaw_ed25519_key_derivator>
T a__class__
T azl_bytes
kl_bytes
curve
zl_int
kl_int
prvl_int
T azr_bytes
kr_bytes
zr_int
kpr_int
kr_int
T apub_key
zl_bytes
zl_int
T aindex

a__spec__
.bip_utils.bip.bip32.kholaw.bip32_kholaw_key_derivator_base
j
a_SerializeIndex
aChainCode
aToBytes
aRaw
aRawCompressed
:l nnaIsHardened
aHmacSha512
aQuickDigest
d
aQuickDigestHalves
d d d aDigestSize
l a_NewPrivateKeyLeftPart
aCurve
a_NewPrivateKeyRightPart

Derive a child key with the specified index using private derivation.
Args:
priv_key (Bip32PrivateKey object): Bip32PrivateKey object
pub_key (Bip32PublicKey object)  : Bip32PublicKey object
index (Bip32KeyIndex object)     : Key index
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the index results in an invalid key
a_NewPublicKeyPoint
wXwYaBip32KeyError
T uComputed public child key is not valid, very unlucky index

Derive a child key with the specified index using public derivation.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
index (Bip32KeyIndex object)   : Key index
Returns:
tuple[bytes or IPoint, bytes]: Public key bytes or point (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the index results in an invalid key

Module for BIP32 Khovratovich/Law keys derivation (base).
Reference: https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
aTuple
aUnion
ubip_utils.bip.bip32.base
T aIBip32KeyDerivator
aIBip32KeyDerivator
ubip_utils.bip.bip32.bip32_ex
T aBip32KeyError
ubip_utils.bip.bip32.bip32_key_data
T aBip32KeyIndex
aBip32KeyIndex
ubip_utils.bip.bip32.bip32_keys
T aBip32PrivateKey
aBip32PublicKey
aBip32PrivateKey
aBip32PublicKey
ubip_utils.ecc
T aEllipticCurve
aIPoint
aEllipticCurve
aIPoint
ubip_utils.utils.crypto
T aHmacSha512
a__prepare__
aBip32KholawEd25519KeyDerivatorBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
