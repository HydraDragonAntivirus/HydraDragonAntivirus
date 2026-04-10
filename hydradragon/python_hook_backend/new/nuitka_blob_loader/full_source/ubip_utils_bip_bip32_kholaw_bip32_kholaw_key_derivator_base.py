# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.kholaw.bip32_kholaw_key_derivator_base


BIP32 Khovratovich/Law ed25519 key derivator base class.
It allows keys derivation for ed25519 curves in according to BIP32 Khovratovich/Law.
It shall be inherited by child classes to customize the derivation algorithm.
a__qualname__
staticmethod
return
bool

Get if public derivation is supported.
Returns:
bool: True if supported, false otherwise.
aIsPublicDerivationSupported
uBip32KholawEd25519KeyDerivatorBase.IsPublicDerivationSupported
classmethod
priv_key
pub_key
index
bytes
aCkdPriv
uBip32KholawEd25519KeyDerivatorBase.CkdPriv
aCkdPub
uBip32KholawEd25519KeyDerivatorBase.CkdPub

Serialize key index.
Args:
index (Bip32KeyIndex object): Key index
Returns:
bytes: Serialized index
uBip32KholawEd25519KeyDerivatorBase._SerializeIndex
zl_bytes
kl_bytes
curve

Compute the new private key left part for private derivation.
Args:
zl_bytes (bytes)            : Leftmost Z 32-byte
kl_bytes (bytes)            : Leftmost private key 32-byte
curve (EllipticCurve object): EllipticCurve object
Returns:
bytes: Leftmost new private key 32-byte
uBip32KholawEd25519KeyDerivatorBase._NewPrivateKeyLeftPart
zr_bytes
kr_bytes

Compute the new private key right part for private derivation.
Args:
zr_bytes (bytes): Rightmost Z 32-byte
kr_bytes (bytes): Rightmost private key 32-byte
Returns:
bytes: Rightmost new private key 32-byte
uBip32KholawEd25519KeyDerivatorBase._NewPrivateKeyRightPart

Compute new public key point for public derivation.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
zl_bytes (bytes)               : Leftmost Z 32-byte
Returns:
IPoint object: IPoint object
uBip32KholawEd25519KeyDerivatorBase._NewPublicKeyPoint
a__orig_bases__
ubip_utils\bip\bip32\kholaw\bip32_kholaw_key_derivator_base.py
u<module bip_utils.bip.bip32.kholaw.bip32_kholaw_key_derivator_base>
T a__class__
T acls
priv_key
pub_key
index
index_bytes
chain_code_bytes
priv_key_bytes
pub_key_bytes
z_bytes
hmac_half_len
kl_bytes
kr_bytes
T	acls
pub_key
index
index_bytes
chain_code_bytes
pub_key_bytes
z_bytes
hmac_half_len
new_pub_key_point
T azl_bytes
kl_bytes
curve
T azr_bytes
kr_bytes
T apub_key
zl_bytes
T aindex

a__spec__
.bip_utils.bip.bip32.kholaw.bip32_kholaw_mst_key_generator
M
aBip32KholawMstKeyGeneratorConst
aSEED_MIN_BYTE_LEN
uInvalid seed length (

w)a_Bip32KholawEd25519MstKeyGenerator__HashRepeatedly
aMASTER_KEY_HMAC_KEY
a_Bip32KholawEd25519MstKeyGenerator__TweakMasterKeyBits
aHmacSha256
aQuickDigest
d u
Generate a master key from the specified seed.
Args:
seed_bytes (bytes): Seed bytes
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the seed is not suitable for master key generation
ValueError: If seed length is not valid
aHmacSha512
aQuickDigestHalves
aBitUtils
aAreBitsSet
l l u
Continue to hash the data bytes until the third-highest bit of the last byte is not zero.
Args:
data_bytes (bytes)    : Data bytes
hmac_key_bytes (bytes): HMAC key bytes
Returns:
tuple[bytes, bytes]: Two halves of the computed hash
aResetBits
l l  aSetBits
l@u
Tweak master key bits.
Args:
key_bytes (bytes): Key bytes
Returns:
bytes: Tweaked key bytes

Module for BIP32 Khovratovich/Law master key generation.
Reference: https://github.com/LedgerHQ/orakolo/blob/master/papers/Ed25519_BIP%20Final.pdf
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ubip_utils.bip.bip32.base
T aIBip32MstKeyGenerator
aIBip32MstKeyGenerator
ubip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator
T aBip32Slip10MstKeyGeneratorConst
aBip32Slip10MstKeyGeneratorConst
ubip_utils.utils.crypto
T aHmacSha256
aHmacSha512
ubip_utils.utils.misc
T aBitUtils
