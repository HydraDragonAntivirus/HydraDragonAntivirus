# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic

uEnumerative for Electrum words number (v1).
a__qualname__
l aWORDS_NUM_12
a__orig_bases__
aElectrumV1Languages
uEnumerative for Electrum languages (v1).
aENGLISH
uClass container for Electrum v1 mnemonic constants.
aElectrumV1MnemonicConst
a__annotations__
aMNEMONIC_WORD_NUM
uwordlist/english.txt
aLANGUAGE_FILES
l  aWORDS_LIST_NUM
aElectrumV1Mnemonic
uElectrum v1 mnemonic class.
ubip_utils\electrum\mnemonic_v1\electrum_v1_mnemonic.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic>
T a__class__

a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder
B
a__class__
a__init__
aElectrumV1WordsListFinder
aElectrumV1WordsListGetter

Construct class.
Language is set to English by default because Electrum v1 mnemonic only support one language,
so it's useless (and slower) to automatically detect the language.
Args:
lang (ElectrumV1Languages, optional): Language, None for automatic detection
Raises:
TypeError: If the language is not a ElectrumV1Languages enum
ValueError: If loaded words list is not valid
aElectrumV1Mnemonic
aFromString
aWordsCount
aElectrumV1MnemonicConst
aMNEMONIC_WORD_NUM
uMnemonic words count is not valid (

w)a_FindLanguage
aToList
c
l aentropy_bytes
aMnemonicUtils
aWordsToBytesChunk
words_list
big

Decode a mnemonic phrase to bytes.
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes
Raises:
ValueError: If mnemonic is not valid

Module for Electrum v1 mnemonic decoding.
Reference: https://github.com/spesmilo/electrum
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1Mnemonic
aElectrumV1MnemonicConst
aElectrumV1Languages
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_utils
T aElectrumV1WordsListFinder
aElectrumV1WordsListGetter
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicDecoderBase
aMnemonicUtils
aMnemonic
aMnemonicDecoderBase
a__prepare__
aElectrumV1MnemonicDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
