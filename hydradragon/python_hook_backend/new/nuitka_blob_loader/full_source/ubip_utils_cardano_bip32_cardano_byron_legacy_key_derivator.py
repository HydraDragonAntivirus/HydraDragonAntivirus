# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.bip32.cardano_byron_legacy_key_derivator


Cardano Byron legacy key derivator class.
It allows keys derivation for Cardano-Byron (legacy, used by old versions of Daedalus).
Derivation based on BIP32 ed25519 Khovratovich/Law with some differences on keys computation.
a__qualname__
staticmethod
index
return
bytes
a_SerializeIndex
uCardanoByronLegacyKeyDerivator._SerializeIndex
zl_bytes
kl_bytes
curve
a_NewPrivateKeyLeftPart
uCardanoByronLegacyKeyDerivator._NewPrivateKeyLeftPart
zr_bytes
kr_bytes
a_NewPrivateKeyRightPart
uCardanoByronLegacyKeyDerivator._NewPrivateKeyRightPart
pub_key
a_NewPublicKeyPoint
uCardanoByronLegacyKeyDerivator._NewPublicKeyPoint
a__orig_bases__
ubip_utils\cardano\bip32\cardano_byron_legacy_key_derivator.py
u<module bip_utils.cardano.bip32.cardano_byron_legacy_key_derivator>
T a__class__
T azl_bytes
kl_bytes
curve
zl8_bytes
zl8_int
kl_int
T azr_bytes
kr_bytes
T apub_key
zl_bytes
zl8_int
T aindex

a__spec__
.bip_utils.cardano.bip32.cardano_byron_legacy_mst_key_generator
l
L
aCardanoByronLegacyMstKeyGeneratorConst
aSEED_BYTE_LEN
uInvalid seed length (

w)a_CardanoByronLegacyMstKeyGenerator__HashRepeatedly
cbor2
dumps

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
aHMAC_MESSAGE_FORMAT
a_CardanoByronLegacyMstKeyGenerator__TweakMasterKeyBits
aSha512
aQuickDigest
aBitUtils
aAreBitsSet
l l u
Continue to hash the data bytes until the third-highest bit of the last byte is not zero.
Args:
data_bytes (bytes): Data bytes
itr_num (int)     : Iteration number
Returns:
tuple[bytes, bytes]: Key bytes (index 0) and chain code bytes (index 1)
aResetBits
l l  aSetBits
l@u
Tweak master key bits.
Args:
key_bytes (bytes): Key bytes
Returns:
bytes: Tweaked key bytes

Module for Cardano Byron legacy master key generation.
References:
https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
https://cips.cardano.org/cips/cip3/byron.md
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ubip_utils.bip.bip32
T aIBip32MstKeyGenerator
aIBip32MstKeyGenerator
ubip_utils.utils.crypto
T aHmacSha512
aSha512
ubip_utils.utils.misc
T aBitUtils
