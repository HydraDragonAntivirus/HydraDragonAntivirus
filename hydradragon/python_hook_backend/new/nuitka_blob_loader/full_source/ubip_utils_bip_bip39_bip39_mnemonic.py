# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip39.bip39_mnemonic

uEnumerative for BIP39 words number.
a__qualname__
l aWORDS_NUM_12
l aWORDS_NUM_15
l aWORDS_NUM_18
l aWORDS_NUM_21
l aWORDS_NUM_24
a__orig_bases__
aBip39Languages
uEnumerative for BIP39 languages.
aCHINESE_SIMPLIFIED
aCHINESE_TRADITIONAL
aCZECH
aENGLISH
aFRENCH
aITALIAN
aKOREAN
aPORTUGUESE
aSPANISH
uClass container for BIP39 mnemonic constants.
aBip39MnemonicConst
a__annotations__
aMNEMONIC_WORD_NUM
uwordlist/english.txt
uwordlist/italian.txt
uwordlist/french.txt
uwordlist/spanish.txt
uwordlist/portuguese.txt
uwordlist/czech.txt
uwordlist/chinese_simplified.txt
uwordlist/chinese_traditional.txt
uwordlist/korean.txt
aLANGUAGE_FILES
l  aWORDS_LIST_NUM
l aWORD_BIT_LEN
aBip39Mnemonic

BIP39 mnemonic class.
It adds NFKD normalization to mnemonic.
staticmethod
mnemonic
str
return
uBip39Mnemonic._Normalize
ubip_utils\bip\bip39\bip39_mnemonic.py
T wsu<module bip_utils.bip.bip39.bip39_mnemonic>
T a__class__
T amnemonic

a__spec__
.bip_utils.bip.bip39.bip39_mnemonic_decoder
x
t
a__class__
a__init__
aBip39WordsListFinder
aBip39WordsListGetter

Construct class.
Args:
lang (Bip39Languages, optional): Language, None for automatic detection
Raises:
TypeError: If the language is not a Bip39Languages enum
ValueError: If loaded words list is not valid
a_Bip39MnemonicDecoder__DecodeAndVerifyBinaryStr
a_Bip39MnemonicDecoder__EntropyBytesFromBinaryStr

Decode a mnemonic phrase to bytes (no checksum).
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes (no checksum)
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
l aBytesUtils
aFromBinaryStr
l u
Decode a mnemonic phrase to bytes (with checksum).
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes (with checksum)
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
aBip39Mnemonic
aFromString
aWordsCount
aBip39MnemonicConst
aMNEMONIC_WORD_NUM
uMnemonic words count is not valid (

w)a_FindLanguage
a_Bip39MnemonicDecoder__MnemonicToBinaryStr
a_Bip39MnemonicDecoder__GetChecksumLen
a_Bip39MnemonicDecoder__ComputeChecksumBinaryStr
aMnemonicChecksumError
uInvalid checksum (expected
u, got

Decode a mnemonic phrase to its mnemonic binary string by verifying the checksum.
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
str: Mnemonic binary string
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
aToBinaryStr
aSha256
aQuickDigest
aDigestSize

Compute checksum from mnemonic binary string.
Args:
mnemonic_bin_str (str): Mnemonic binary string
Returns:
str: Computed checksum binary string

Get entropy bytes from mnemonic binary string.
Args:
mnemonic_bin_str (str): Mnemonic binary string
Returns:
bytes: Entropy bytes
u<lambda>
uBip39MnemonicDecoder.__MnemonicToBinaryStr.<locals>.<lambda>
aToList

Get mnemonic binary string from mnemonic phrase.
Args:
mnemonic (Mnemonic object)           : Mnemonic object
words_list (MnemonicWordsList object): Words list object
Returns:
str: Mnemonic binary string
Raises:
ValueError: If the one of the mnemonic word is not valid
aIntegerUtils
words_list
aGetWordIdx
aWORD_BIT_LEN
l!u
Get checksum length from mnemonic binary string.
Args:
mnemonic_bin_str (str): Mnemonic binary string
Returns:
int: Checksum length

Module for BIP39 mnemonic decoding.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.bip.bip39.bip39_mnemonic
T aBip39Languages
aBip39Mnemonic
aBip39MnemonicConst
aBip39Languages
ubip_utils.bip.bip39.bip39_mnemonic_utils
T aBip39WordsListFinder
aBip39WordsListGetter
ubip_utils.utils.crypto
T aSha256
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicChecksumError
aMnemonicDecoderBase
aMnemonicWordsList
aMnemonic
aMnemonicDecoderBase
aMnemonicWordsList
a__prepare__
aBip39MnemonicDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
