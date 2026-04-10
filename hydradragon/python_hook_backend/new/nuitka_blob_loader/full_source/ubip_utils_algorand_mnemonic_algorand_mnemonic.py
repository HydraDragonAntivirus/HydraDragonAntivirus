# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.algorand.mnemonic.algorand_mnemonic

uEnumerative for Algorand words number.
a__qualname__
l aWORDS_NUM_25
a__orig_bases__
aAlgorandLanguages
uEnumerative for Algorand languages.
aENGLISH
uClass container for Algorand mnemonic constants.
aAlgorandMnemonicConst
a__annotations__
aMNEMONIC_WORD_NUM
l aCHECKSUM_BYTE_LEN
aAlgorandMnemonic
uAlgorand mnemonic class.
ubip_utils\algorand\mnemonic\algorand_mnemonic.py
u<module bip_utils.algorand.mnemonic.algorand_mnemonic>
T a__class__

a__spec__
.bip_utils.algorand.mnemonic.algorand_mnemonic_decoder
A
Y
aAlgorandLanguages
uLanguage is not an enumerative of AlgorandLanguages
a__class__
a__init__
value
aBip39WordsListFinder
aBip39WordsListGetter

Construct class.
Language is set to English by default because Algorand mnemonic only support one language,
so it's useless (and slower) to automatically detect the language.
Args:
lang (AlgorandLanguages, optional): Language, None for automatic detection
Raises:
TypeError: If the language is not a AlgorandLanguages enum
ValueError: If loaded words list is not valid
aAlgorandMnemonic
aFromString
aWordsCount
aAlgorandMnemonicConst
aMNEMONIC_WORD_NUM
uMnemonic words count is not valid (

w)aToList
a_FindLanguage
words_list
aGetWordIdx
aAlgorandMnemonicUtils
aConvertBits
:nq nl l aBytesUtils
aFromList
a_AlgorandMnemonicDecoder__ValidateChecksum

Decode a mnemonic phrase to bytes (no checksum).
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
aComputeChecksumWordIndex
aMnemonicChecksumError
uInvalid checksum (expected
aGetWordAtIdx
u, got

Validate a mnemonic checksum.
Args:
entropy_bytes (list)          : Entropy bytes
chksum_word_idx_exp (int)     : Expected checksum word index
words_list (MnemonicWordsList): Words list
Raises:
MnemonicChecksumError: If checksum is not valid

Module for Algorand mnemonic decoding.
Reference: https://github.com/algorand/py-algorand-sdk
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.algorand.mnemonic.algorand_mnemonic
T aAlgorandLanguages
aAlgorandMnemonic
aAlgorandMnemonicConst
ubip_utils.algorand.mnemonic.algorand_mnemonic_utils
T aAlgorandMnemonicUtils
ubip_utils.bip.bip39.bip39_mnemonic_utils
T aBip39WordsListFinder
aBip39WordsListGetter
ubip_utils.utils.misc
T aBytesUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicChecksumError
aMnemonicDecoderBase
aMnemonicWordsList
aMnemonic
aMnemonicDecoderBase
aMnemonicWordsList
a__prepare__
aAlgorandMnemonicDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
