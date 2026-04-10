# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.mnemonic.cardano_byron_legacy_seed_generator


Cardano Byron legacy seed generator class.
It generates seeds from a BIP39 mnemonic for Cardano Byron (legacy).
aCardanoByronLegacySeedGenerator
a__qualname__
a__annotations__
m_ser_seed_bytes
T namnemonic
lang
return
a__init__
uCardanoByronLegacySeedGenerator.__init__
D areturn
Obytes
aGenerate
uCardanoByronLegacySeedGenerator.Generate
ubip_utils\cardano\mnemonic\cardano_byron_legacy_seed_generator.py
u<module bip_utils.cardano.mnemonic.cardano_byron_legacy_seed_generator>
T a__class__
T aself
T aself
mnemonic
lang

a__spec__
.bip_utils.cardano.mnemonic.cardano_icarus_seed_generator
)
aBip39MnemonicDecoder
aDecode
m_entropy_bytes

Construct class.
Args:
mnemonic (str or Mnemonic object): Mnemonic
lang (Bip39Languages, optional)  : Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid

Generate seed. The seed is simply the entropy bytes in Cardano case.
There is no really need of this method, since the seed is always the same, but it's
kept in this way to have the same usage of Bip39/Substrate seed generator
(i.e. CardanoSeedGenerator(mnemonic).Generate() ).
Returns:
bytes: Generated seed
uModule for Cardano Icarus mnemonic seed generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.bip.bip39
T aBip39Languages
aBip39MnemonicDecoder
aBip39Languages
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
