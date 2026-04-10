# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.mnemonic.monero_mnemonic

uEnumerative for Monero words number.
a__qualname__
l aWORDS_NUM_12
laWORDS_NUM_13
l aWORDS_NUM_24
l aWORDS_NUM_25
a__orig_bases__
aMoneroLanguages
uEnumerative for Monero languages.
aCHINESE_SIMPLIFIED
aDUTCH
aENGLISH
aFRENCH
aGERMAN
aITALIAN
aJAPANESE
aPORTUGUESE
aSPANISH
aRUSSIAN
uClass container for Monero mnemonic constants.
aMoneroMnemonicConst
a__annotations__
aMNEMONIC_WORD_NUM
aMNEMONIC_WORD_NUM_CHKSUM
l l aLANGUAGE_UNIQUE_PREFIX_LEN
uwordlist/chinese_simplified.txt
uwordlist/dutch.txt
uwordlist/english.txt
uwordlist/french.txt
uwordlist/german.txt
uwordlist/italian.txt
uwordlist/japanese.txt
uwordlist/portuguese.txt
uwordlist/spanish.txt
uwordlist/russian.txt
aLANGUAGE_FILES
l  aWORDS_LIST_NUM
aMoneroMnemonic
uMonero mnemonic class (alias for Mnemonic).
ubip_utils\monero\mnemonic\monero_mnemonic.py
u<module bip_utils.monero.mnemonic.monero_mnemonic>
T a__class__

a__spec__
.bip_utils.monero.mnemonic.monero_mnemonic_decoder
R
a__class__
a__init__
aMoneroWordsListFinder
aMoneroWordsListGetter

Construct class.
Args:
lang (MoneroLanguages, optional): Language, None for automatic detection
Raises:
TypeError: If the language is not a MoneroLanguages enum
ValueError: If loaded words list is not valid
aMoneroMnemonic
aFromString
aWordsCount
aMoneroMnemonicConst
aMNEMONIC_WORD_NUM
uMnemonic words count is not valid (

w)a_FindLanguage
aMoneroLanguages
aToList
a_MoneroMnemonicDecoder__ValidateChecksum
c
l aentropy_bytes
aMnemonicUtils
aWordsToBytesChunk
words_list
little

Decode a mnemonic phrase to bytes (no checksum).
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
aMNEMONIC_WORD_NUM_CHKSUM
aMoneroMnemonicUtils
aComputeChecksum
:nq naMnemonicChecksumError
uInvalid checksum (expected
u, got

Validate a mnemonic checksum.
Args:
words (list[str])       : Words list
lang (MnemonicLanguages): Language
Raises:
MnemonicChecksumError: If checksum is not valid
uModule for Monero mnemonic decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aList
aOptional
aUnion
ubip_utils.monero.mnemonic.monero_mnemonic
T aMoneroLanguages
aMoneroMnemonic
aMoneroMnemonicConst
ubip_utils.monero.mnemonic.monero_mnemonic_utils
T aMoneroMnemonicUtils
aMoneroWordsListFinder
aMoneroWordsListGetter
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicChecksumError
aMnemonicDecoderBase
aMnemonicLanguages
aMnemonicUtils
aMnemonic
aMnemonicDecoderBase
aMnemonicLanguages
a__prepare__
aMoneroMnemonicDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
