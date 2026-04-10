# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.algorand.mnemonic.algorand_mnemonic_encoder


Algorand mnemonic encoder class.
It encodes bytes to the mnemonic phrase.
a__qualname__
aENGLISH
lang
return
uAlgorandMnemonicEncoder.__init__
entropy_bytes
bytes
aEncode
uAlgorandMnemonicEncoder.Encode
indexes
int
str
a__IndexesToWords
uAlgorandMnemonicEncoder.__IndexesToWords
a__orig_bases__
ubip_utils\algorand\mnemonic\algorand_mnemonic_encoder.py
u<module bip_utils.algorand.mnemonic.algorand_mnemonic_encoder>
T a__class__
T aself
entropy_bytes
entropy_byte_len
chksum_word_idx
word_indexes
T aself
indexes
T aself
lang
a__class__
a__spec__
.bip_utils.algorand.mnemonic.algorand_mnemonic_generator
>
aAlgorandMnemonicEncoder
m_mnemonic_encoder

Construct class.
Args:
lang (AlgorandLanguages, optional): Language (default: English)
Raises:
TypeError: If the language is not a AlgorandLanguages enum
ValueError: If language words list is not valid
aAlgorandMnemonicConst
aMNEMONIC_WORD_NUM
uWords number for mnemonic (

u) is not valid
aAlgorandWordsNum
aAlgorandMnemonicGeneratorConst
aWORDS_NUM_TO_ENTROPY_LEN
aAlgorandEntropyGenerator
aGenerate
aFromEntropy

Generate mnemonic with the specified words number from random entropy.
There is no really need of this method, since the words number can only be 25, but it's
kept to have the same usage of Bip39/Monero mnemonic generator.
Args:
words_num (int or AlgorandWordsNum): Number of words (25)
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
uModule for Algorand mnemonic generation.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aUnion
ubip_utils.algorand.mnemonic.algorand_entropy_generator
T aAlgorandEntropyBitLen
aAlgorandEntropyGenerator
aAlgorandEntropyBitLen
ubip_utils.algorand.mnemonic.algorand_mnemonic
T aAlgorandLanguages
aAlgorandMnemonicConst
aAlgorandWordsNum
aAlgorandLanguages
ubip_utils.algorand.mnemonic.algorand_mnemonic_encoder
T aAlgorandMnemonicEncoder
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
