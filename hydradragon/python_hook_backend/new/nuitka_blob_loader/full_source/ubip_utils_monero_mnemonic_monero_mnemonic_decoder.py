# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.mnemonic.monero_mnemonic_decoder


Monero mnemonic decoder class.
It decodes a mnemonic phrase to bytes.
a__qualname__
T nalang
return
uMoneroMnemonicDecoder.__init__
mnemonic
str
bytes
aDecode
uMoneroMnemonicDecoder.Decode
staticmethod
words
a__ValidateChecksum
uMoneroMnemonicDecoder.__ValidateChecksum
a__orig_bases__
ubip_utils\monero\mnemonic\monero_mnemonic_decoder.py
u<module bip_utils.monero.mnemonic.monero_mnemonic_decoder>
T aself
mnemonic
mnemonic_obj
words_list
lang
words
entropy_bytes
wiaword1
word2
word3
T a__class__
T awords
lang
chksum_word
T aself
lang
a__class__
a__spec__
.bip_utils.monero.mnemonic.monero_mnemonic_encoder
^
a__class__
a__init__
aMoneroWordsListGetter
m_lang

Construct class.
Args:
lang (MoneroLanguages, optional): Language (default: English)
Raises:
TypeError: If the language is not a Bip39Languages enum
ValueError: If loaded words list is not valid
aMoneroEntropyGenerator
aIsValidEntropyByteLen
uEntropy byte length (

u) is not valid
l amnemonic
aMnemonicUtils
aBytesChunkToWords
self
m_words_list
little

Encode bytes to list of mnemonic words.
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
list[str]: List of encoded mnemonic words
Raises:
ValueError: If bytes length is not valid
aMoneroMnemonic
aFromList
a_EncodeToList

Encode bytes to mnemonic phrase (no checksum).
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
Mnemonic object: Encoded mnemonic (no checksum)
Raises:
ValueError: If entropy is not valid
aMoneroMnemonicUtils
aComputeChecksum

Encode bytes to mnemonic phrase (with checksum).
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
Mnemonic object: Encoded mnemonic (with checksum)
Raises:
ValueError: If entropy is not valid
aMoneroMnemonicNoChecksumEncoder
m_no_chk_enc
aMoneroMnemonicWithChecksumEncoder
m_with_chk_enc

Construct class.
Args:
lang (MoneroLanguages, optional): Language (default: English)
Raises:
TypeError: If the language is not a MoneroLanguages enum
ValueError: If loaded words list is not valid
aEncode

Encode bytes to mnemonic phrase (no checksum).
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
Mnemonic object: Encoded mnemonic (no checksum)
Raises:
ValueError: If bytes length is not valid

Encode bytes to mnemonic phrase (with checksum).
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
Mnemonic object: Encoded mnemonic (with checksum)
Raises:
ValueError: If bytes length is not valid
uModule for Monero mnemonic encoding.
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
aABC
aList
ubip_utils.monero.mnemonic.monero_entropy_generator
T aMoneroEntropyGenerator
ubip_utils.monero.mnemonic.monero_mnemonic
T aMoneroLanguages
aMoneroMnemonic
aMoneroLanguages
ubip_utils.monero.mnemonic.monero_mnemonic_utils
T aMoneroMnemonicUtils
aMoneroWordsListGetter
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicEncoderBase
aMnemonicUtils
aMnemonic
aMnemonicEncoderBase
a__prepare__
aMoneroMnemonicEncoderBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
