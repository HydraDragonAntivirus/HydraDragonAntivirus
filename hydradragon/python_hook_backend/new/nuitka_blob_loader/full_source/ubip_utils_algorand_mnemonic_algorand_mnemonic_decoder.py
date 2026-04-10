# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.algorand.mnemonic.algorand_mnemonic_decoder


Algorand mnemonic decoder class.
It decodes a mnemonic phrase to bytes.
a__qualname__
aENGLISH
lang
return
uAlgorandMnemonicDecoder.__init__
mnemonic
str
bytes
aDecode
uAlgorandMnemonicDecoder.Decode
staticmethod
entropy_bytes
chksum_word_idx_exp
int
a__ValidateChecksum
uAlgorandMnemonicDecoder.__ValidateChecksum
a__orig_bases__
ubip_utils\algorand\mnemonic\algorand_mnemonic_decoder.py
u<module bip_utils.algorand.mnemonic.algorand_mnemonic_decoder>
T a__class__
T	aself
mnemonic
mnemonic_obj
words
words_list
w_aword_indexes
entropy_list
entropy_bytes
T aentropy_bytes
chksum_word_idx_exp
words_list
chksum_word_idx
T aself
lang
a__class__
a__spec__
.bip_utils.algorand.mnemonic.algorand_mnemonic_encoder
o
K
aAlgorandLanguages
uLanguage is not an enumerative of AlgorandLanguages
a__class__
a__init__
value
aBip39WordsListGetter

Construct class.
Args:
lang (AlgorandLanguages, optional): Language (default: English)
Raises:
TypeError: If the language is not a AlgorandLanguages enum
ValueError: If loaded words list is not valid
aAlgorandEntropyGenerator
aIsValidEntropyByteLen
uEntropy byte length (

u) is not valid
aAlgorandMnemonicUtils
aComputeChecksumWordIndex
aConvertBits
l l aAlgorandMnemonic
aFromList
a_AlgorandMnemonicEncoder__IndexesToWords

Encode bytes to mnemonic phrase.
Args:
entropy_bytes (bytes): Entropy bytes
Returns:
Mnemonic object: Encoded mnemonic
Raises:
ValueError: If bytes length is not valid
self
m_words_list
aGetWordAtIdx

Get a list of words from a list of indexes.
Args:
indexes (list[int]): List of indexes
Returns:
list[str]: List of words

Module for Algorand mnemonic encoding.
Reference: https://github.com/algorand/py-algorand-sdk
a__doc__
a__file__
origin
has_location
a__cached__
aList
ubip_utils.algorand.mnemonic.algorand_entropy_generator
T aAlgorandEntropyGenerator
ubip_utils.algorand.mnemonic.algorand_mnemonic
T aAlgorandLanguages
aAlgorandMnemonic
ubip_utils.algorand.mnemonic.algorand_mnemonic_utils
T aAlgorandMnemonicUtils
ubip_utils.bip.bip39.bip39_mnemonic_utils
T aBip39WordsListGetter
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicEncoderBase
aMnemonic
aMnemonicEncoderBase
a__prepare__
aAlgorandMnemonicEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
