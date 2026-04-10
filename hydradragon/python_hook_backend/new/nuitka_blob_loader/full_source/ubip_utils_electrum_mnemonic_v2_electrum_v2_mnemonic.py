# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic

uEnumerative for Electrum words number (v2).
a__qualname__
l aWORDS_NUM_12
l aWORDS_NUM_24
a__orig_bases__
aElectrumV2Languages
uEnumerative for Electrum languages (v2).
aCHINESE_SIMPLIFIED
aENGLISH
aPORTUGUESE
aSPANISH
aElectrumV2MnemonicTypes
uEnumerative for Electrum v2 mnemonic types.
aSTANDARD
aSEGWIT
aSTANDARD_2FA
aSEGWIT_2FA
uClass container for Electrum v2 mnemonic constants.
aElectrumV2MnemonicConst
a__annotations__
aMNEMONIC_WORD_NUM
u01
u100
u101
u102
aTYPE_TO_PREFIX
aWORD_BIT_LEN
aElectrumV2Mnemonic
uElectrum mnemonic class.
ubip_utils\electrum\mnemonic_v2\electrum_v2_mnemonic.py
u<module bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic>
T a__class__

a__spec__
.bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_decoder
1
P
aElectrumV2MnemonicTypes
uMnemonic type is not an enumerative of ElectrumV2MnemonicTypes
aElectrumV2Languages
uLanguage is not an enumerative of ElectrumV2Languages
a__class__
a__init__
value
aBip39WordsListFinder
aBip39WordsListGetter
m_mnemonic_type

Construct class.
Args:
mnemonic_type (ElectrumV2MnemonicTypes, optional): Mnemonic type, None for all types
lang (ElectrumV2Languages, optional)             : Language, None for automatic detection
Raises:
TypeError: If the language is not a ElectrumV2Languages enum
ValueError: If loaded words list is not valid
aElectrumV2Mnemonic
aFromString
aWordsCount
aElectrumV2MnemonicConst
aMNEMONIC_WORD_NUM
uMnemonic words count is not valid (

w)aElectrumV2MnemonicUtils
aIsValidMnemonic
uInvalid mnemonic
aToList
a_FindLanguage
aLength
entropy_int
wnawords_list
aGetWordIdx
aIntegerUtils
aToBytes

Decode a mnemonic phrase to bytes (no checksum).
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid

Module for Electrum v2 mnemonic decoding.
Reference: https://github.com/electrum/py-electrum-sdk
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.bip.bip39.bip39_mnemonic_utils
T aBip39WordsListFinder
aBip39WordsListGetter
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2Languages
aElectrumV2Mnemonic
aElectrumV2MnemonicConst
aElectrumV2MnemonicTypes
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_utils
T aElectrumV2MnemonicUtils
ubip_utils.utils.misc
T aIntegerUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicDecoderBase
aMnemonic
aMnemonicDecoderBase
a__prepare__
aElectrumV2MnemonicDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
