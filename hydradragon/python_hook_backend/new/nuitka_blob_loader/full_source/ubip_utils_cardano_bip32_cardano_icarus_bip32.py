# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.bip32.cardano_icarus_bip32


Cardano Icarus BIP32 class.
It allows master keys generation and keys derivation for Cardano Icarus.
Derivation based on BIP32 ed25519 Khovratovich/Law with a different algorithm for master key generation.
a__qualname__
staticmethod
return
a_MasterKeyGenerator
uCardanoIcarusBip32._MasterKeyGenerator
a__orig_bases__
ubip_utils\cardano\bip32\cardano_icarus_bip32.py
u<module bip_utils.cardano.bip32.cardano_icarus_bip32>
T a__class__

a__spec__
.bip_utils.cardano.bip32.cardano_icarus_mst_key_generator
H
aBip32Slip10MstKeyGeneratorConst
aSEED_MIN_BYTE_LEN
uInvalid seed length (

w)aPbkdf2HmacSha512
aDeriveKey
aCardanoIcarusMasterKeyGeneratorConst
aPBKDF2_PASSWORD
aPBKDF2_ROUNDS
aPBKDF2_OUT_BYTE_LEN
a_CardanoIcarusMstKeyGenerator__TweakMasterKeyBits
aEd25519KholawPrivateKey
aLength

Generate a master key from the specified seed.
Args:
seed_bytes (bytes): Seed bytes
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the seed is not suitable for master key generation
ValueError: If seed length is not valid
aBitUtils
aResetBits
l l l  aSetBits
l@u
Tweak master key bits.
Args:
key_bytes (bytes): Key bytes
Returns:
bytes: Tweaked key bytes

Module for Cardano Icarus master key generation.
References:
https://input-output-hk.github.io/cardano-wallet/concepts/master-key-generation
https://cips.cardano.org/cips/cip3/icarus.md
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ubip_utils.bip.bip32
T aIBip32MstKeyGenerator
aIBip32MstKeyGenerator
ubip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator
T aBip32Slip10MstKeyGeneratorConst
ubip_utils.ecc
T aEd25519KholawPrivateKey
ubip_utils.utils.crypto
T aPbkdf2HmacSha512
ubip_utils.utils.misc
T aBitUtils
