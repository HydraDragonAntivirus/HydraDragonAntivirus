# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_encoder


Electrum v1 mnemonic encoder class.
It encodes bytes to the mnemonic phrase.
a__qualname__
aENGLISH
lang
return
uElectrumV1MnemonicEncoder.__init__
entropy_bytes
bytes
aEncode
uElectrumV1MnemonicEncoder.Encode
a__orig_bases__
ubip_utils\electrum\mnemonic_v1\electrum_v1_mnemonic_encoder.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_encoder>
T a__class__
T aself
entropy_bytes
entropy_byte_len
mnemonic
wiT aself
lang
a__class__
a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_generator
W
>
aElectrumV1MnemonicEncoder
m_mnemonic_encoder

Construct class.
Args:
lang (ElectrumV1Languages, optional): Language (default: English)
Raises:
TypeError: If the language is not a ElectrumV1Languages enum
ValueError: If language words list is not valid
aElectrumV1MnemonicConst
aMNEMONIC_WORD_NUM
uWords number for mnemonic (

u) is not valid
aElectrumV1WordsNum
aElectrumV1MnemonicGeneratorConst
aWORDS_NUM_TO_ENTROPY_LEN
aElectrumV1EntropyGenerator
aGenerate
aFromEntropy

Generate mnemonic with the specified words number from random entropy.
There is no really need of this method, since the words number can only be 12, but it's
kept to have the same usage of Bip39/Monero mnemonic generator.
Args:
words_num (int or ElectrumV1WordsNum): Number of words (12)
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If words number is not valid
aEncode

Generate mnemonic from the specified entropy bytes.
Args:
entropy_bytes (bytes): Entropy bytes
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If entropy byte length is not valid
uModule for Electrum v1 mnemonic generation.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aUnion
ubip_utils.electrum.mnemonic_v1.electrum_v1_entropy_generator
T aElectrumV1EntropyBitLen
aElectrumV1EntropyGenerator
aElectrumV1EntropyBitLen
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1MnemonicConst
aElectrumV1WordsNum
aElectrumV1Languages
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_encoder
T aElectrumV1MnemonicEncoder
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
