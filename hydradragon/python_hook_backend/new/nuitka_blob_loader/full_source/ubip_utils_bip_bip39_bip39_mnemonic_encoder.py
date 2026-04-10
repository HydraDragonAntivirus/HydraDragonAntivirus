# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip39.bip39_mnemonic_encoder


BIP39 mnemonic encoder class.
It encodes bytes to the mnemonic phrase.
a__qualname__
aENGLISH
lang
return
uBip39MnemonicEncoder.__init__
entropy_bytes
bytes
aEncode
uBip39MnemonicEncoder.Encode
a__orig_bases__
ubip_utils\bip\bip39\bip39_mnemonic_encoder.py
u<module bip_utils.bip.bip39.bip39_mnemonic_encoder>
T a__class__
T
self
entropy_bytes
entropy_byte_len
entropy_bin_str
entropy_hash_bin_str
mnemonic_bin_str
mnemonic
wiaword_bin_str
word_idx
T aself
lang
a__class__
a__spec__
.bip_utils.bip.bip39.bip39_mnemonic_generator
?
aBip39MnemonicEncoder
m_mnemonic_encoder

Construct class.
Args:
lang (Bip39Languages, optional): Language (default: English)
Raises:
TypeError: If the language is not a Bip39Languages enum
ValueError: If language words list is not valid
aBip39MnemonicConst
aMNEMONIC_WORD_NUM
uWords number for mnemonic (

u) is not valid
a_Bip39MnemonicGenerator__EntropyBitLenFromWordsNum
aBip39EntropyGenerator
aGenerate
aFromEntropy

Generate mnemonic with the specified words number from random entropy.
Args:
words_num (int or Bip39WordsNum): Number of words (12, 15, 18, 21, 24)
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If words number is not valid
aEncode

Generate mnemonic from the specified entropy bytes.
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 160, 192, 224, 256)
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If entropy byte length is not valid
aWORD_BIT_LEN
l u
Get entropy length from words number.
Args:
words_num (int): Words number
Returns:
int: Correspondent entropy length
uModule for BIP39 mnemonic generation.
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
ubip_utils.bip.bip39.bip39_entropy_generator
T aBip39EntropyGenerator
ubip_utils.bip.bip39.bip39_mnemonic
T aBip39Languages
aBip39MnemonicConst
aBip39WordsNum
aBip39Languages
aBip39WordsNum
ubip_utils.bip.bip39.bip39_mnemonic_encoder
T aBip39MnemonicEncoder
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
