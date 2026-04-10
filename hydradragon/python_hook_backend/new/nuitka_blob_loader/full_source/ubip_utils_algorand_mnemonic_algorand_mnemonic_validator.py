# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.algorand.mnemonic.algorand_mnemonic_validator


Algorand mnemonic validator class.
It validates a mnemonic phrase.
a__qualname__
a__annotations__
m_mnemonic_decoder
aENGLISH
lang
return
uAlgorandMnemonicValidator.__init__
a__orig_bases__
ubip_utils\algorand\mnemonic\algorand_mnemonic_validator.py
u<module bip_utils.algorand.mnemonic.algorand_mnemonic_validator>
T a__class__
T aself
lang
a__class__

a__spec__
.bip_utils.algorand.mnemonic.algorand_seed_generator
+
aAlgorandMnemonicDecoder
aDecode
m_entropy_bytes

Construct class.
Language is set to English by default because Algorand mnemonic only support one language,
so it's useless (and slower) to automatically detect the language.
Args:
mnemonic (str or Mnemonic object) : Mnemonic
lang (AlgorandLanguages, optional): Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid

Generate seed. The seed is simply the entropy bytes in Algorand case.
There is no really need of this method, since the seed is always the same, but it's
kept in this way to have the same usage of Bip39/Substrate seed generator
(i.e. AlgorandSeedGenerator(mnemonic).Generate() ).
Returns:
bytes: Generated seed
uModule for Algorand mnemonic seed generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.algorand.mnemonic.algorand_mnemonic
T aAlgorandLanguages
aAlgorandLanguages
ubip_utils.algorand.mnemonic.algorand_mnemonic_decoder
T aAlgorandMnemonicDecoder
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
