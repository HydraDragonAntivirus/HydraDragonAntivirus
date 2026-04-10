# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.base.ibip32_mst_key_generator

uInterface for generic BIP32 master key generator.
a__qualname__
classmethod
seed_bytes
bytes
return

Generate a master key from the specified seed.
Args:
seed_bytes (bytes): Seed bytes
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the seed is not suitable for master key generation
ValueError: If seed length is not valid
aGenerateFromSeed
uIBip32MstKeyGenerator.GenerateFromSeed
a__orig_bases__
ubip_utils\bip\bip32\base\ibip32_mst_key_generator.py
u<module bip_utils.bip.bip32.base.ibip32_mst_key_generator>
T acls
seed_bytes
T a__class__

a__spec__
.bip_utils.bip.bip32.bip32_const
uModule with BIP32 constants.
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.bip.bip32.bip32_key_net_ver
T aBip32KeyNetVersions
aBip32KeyNetVersions
