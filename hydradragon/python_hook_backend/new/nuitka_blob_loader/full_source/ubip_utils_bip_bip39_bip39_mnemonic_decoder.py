# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip39.bip39_mnemonic_decoder


BIP39 mnemonic decoder class.
It decodes a mnemonic phrase to bytes.
a__qualname__
T nalang
return
uBip39MnemonicDecoder.__init__
mnemonic
str
bytes
aDecode
uBip39MnemonicDecoder.Decode
aDecodeWithChecksum
uBip39MnemonicDecoder.DecodeWithChecksum
a__DecodeAndVerifyBinaryStr
uBip39MnemonicDecoder.__DecodeAndVerifyBinaryStr
mnemonic_bin_str
a__ComputeChecksumBinaryStr
uBip39MnemonicDecoder.__ComputeChecksumBinaryStr
a__EntropyBytesFromBinaryStr
uBip39MnemonicDecoder.__EntropyBytesFromBinaryStr
staticmethod
a__MnemonicToBinaryStr
uBip39MnemonicDecoder.__MnemonicToBinaryStr
int
a__GetChecksumLen
uBip39MnemonicDecoder.__GetChecksumLen
a__orig_bases__
ubip_utils\bip\bip39\bip39_mnemonic_decoder.py
T aword
words_list
T awords_list
u<module bip_utils.bip.bip39.bip39_mnemonic_decoder>
T a__class__
T aself
mnemonic
mnemonic_bin_str
T aself
mnemonic
mnemonic_bin_str
mnemonic_bit_len
pad_bit_len
T aself
mnemonic_bin_str
entropy_bytes
entropy_hash_bin_str
T aself
mnemonic
mnemonic_obj
words_list
w_amnemonic_bin_str
checksum_bin_str
checksum_bin_str_got
T aself
mnemonic_bin_str
checksum_len
entropy_bin_str
T amnemonic_bin_str
T amnemonic
words_list
mnemonic_bin_str
T aself
lang
a__class__
a__spec__
.bip_utils.bip.bip39.bip39_mnemonic_encoder
n
I
a__class__
a__init__
aBip39WordsListGetter

Construct class.
Args:
lang (Bip39Languages, optional): Language (default: English)
Raises:
TypeError: If the language is not a Bip39Languages enum
ValueError: If loaded words list is not valid
aBip39EntropyGenerator
aIsValidEntropyByteLen
uEntropy byte length (

u) is not valid
aBytesUtils
aToBinaryStr
l aSha256
aQuickDigest
aDigestSize
l aBip39MnemonicConst
aWORD_BIT_LEN
aIntegerUtils
aFromBinaryStr
mnemonic
self
m_words_list
aGetWordAtIdx
aBip39Mnemonic
aFromList

Encode bytes to mnemonic phrase.
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 160, 192, 224, 256)
Returns:
Mnemonic object: Encoded mnemonic
Raises:
ValueError: If entropy is not valid

Module for BIP39 mnemonic encoding.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.bip.bip39.bip39_entropy_generator
T aBip39EntropyGenerator
ubip_utils.bip.bip39.bip39_mnemonic
T aBip39Languages
aBip39Mnemonic
aBip39MnemonicConst
aBip39Languages
ubip_utils.bip.bip39.bip39_mnemonic_utils
T aBip39WordsListGetter
ubip_utils.utils.crypto
T aSha256
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicEncoderBase
aMnemonic
aMnemonicEncoderBase
a__prepare__
aBip39MnemonicEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
