# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_validator


Electrum v1 mnemonic validator class.
It validates a mnemonic phrase.
a__qualname__
a__annotations__
m_mnemonic_decoder
aENGLISH
lang
return
uElectrumV1MnemonicValidator.__init__
a__orig_bases__
ubip_utils\electrum\mnemonic_v1\electrum_v1_mnemonic_validator.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_validator>
T a__class__
T aself
lang
a__class__

a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_seed_generator
A
aElectrumV1MnemonicDecoder
aDecode
a_ElectrumV1SeedGenerator__GenerateSeed
m_seed

Construct class.
Language is set to English by default because Electrum v1 mnemonic only support one language,
so it's useless (and slower) to automatically detect the language.
Args:
mnemonic (str or Mnemonic object)   : Mnemonic
lang (ElectrumV1Languages, optional): Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid

Generate seed.
There is no really need of this method, since the seed is always the same, but it's
kept in this way to have the same usage of Bip39/Substrate seed generator
(i.e. ElectrumV1SeedGenerator(mnemonic).Generate() ).
Returns:
bytes: Generated seed
aAlgoUtils
aEncode
aBytesUtils
aToHexString
aElectrumV1SeedGeneratorConst
aHASH_ITR_NUM
aSha256
aQuickDigest
whaentropy_hex

Generate seed from entropy bytes.
Args:
entropy_bytes (bytes): Entropy bytes
Returns:
bytes: Generated seed
uModule for Electrum v1 mnemonic seed generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1Languages
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder
T aElectrumV1MnemonicDecoder
ubip_utils.utils.crypto
T aSha256
ubip_utils.utils.misc
T aAlgoUtils
aBytesUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
