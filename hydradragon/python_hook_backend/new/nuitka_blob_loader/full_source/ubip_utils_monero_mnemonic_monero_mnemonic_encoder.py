# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.mnemonic.monero_mnemonic_encoder


Monero mnemonic encoder base class.
It encodes bytes to the mnemonic phrase.
a__qualname__
a__annotations__
aENGLISH
lang
return
uMoneroMnemonicEncoderBase.__init__
entropy_bytes
bytes
str
uMoneroMnemonicEncoderBase._EncodeToList
a__orig_bases__

Monero mnemonic encoder class (no checksum).
It encodes bytes to the mnemonic phrase without checksum.
uMoneroMnemonicNoChecksumEncoder.Encode

Monero mnemonic encoder class (with checksum).
It encodes bytes to the mnemonic phrase with checksum.
uMoneroMnemonicWithChecksumEncoder.Encode

Monero mnemonic encoder class.
Helper class to encode bytes to the mnemonic phrase with or without checksum.
aMoneroMnemonicEncoder
uMoneroMnemonicEncoder.__init__
aEncodeNoChecksum
uMoneroMnemonicEncoder.EncodeNoChecksum
aEncodeWithChecksum
uMoneroMnemonicEncoder.EncodeWithChecksum
ubip_utils\monero\mnemonic\monero_mnemonic_encoder.py
u<module bip_utils.monero.mnemonic.monero_mnemonic_encoder>
T aself
entropy_bytes
T aself
entropy_bytes
words
checksum_word
T a__class__
T aself
entropy_bytes
entropy_byte_len
mnemonic
wiT aself
lang
T aself
lang
a__class__
a__spec__
.bip_utils.monero.mnemonic.monero_mnemonic_generator
G
aMoneroMnemonicEncoder
m_mnemonic_encoder

Construct class.
Args:
lang (MoneroLanguages, optional): Language (default: English)
Raises:
TypeError: If the language is not a MoneroLanguages enum
ValueError: If language words list is not valid
aMoneroMnemonicConst
aMNEMONIC_WORD_NUM
uWords number for mnemonic (

u) is not valid
aMoneroWordsNum
aMoneroMnemonicGeneratorConst
aWORDS_NUM_TO_ENTROPY_LEN
aMoneroEntropyGenerator
aGenerate
aMNEMONIC_WORD_NUM_CHKSUM
aFromEntropyWithChecksum
aFromEntropyNoChecksum

Generate mnemonic with the specified words number from random entropy.
Args:
words_num (int or MoneroWordsNum): Number of words (12, 13, 24, 25)
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If words number is not valid
aEncodeNoChecksum

Generate mnemonic from the specified entropy bytes (no checksum).
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
Mnemonic object: Generated mnemonic (no checksum)
Raises:
ValueError: If entropy byte length is not valid
aEncodeWithChecksum

Generate mnemonic from the specified entropy bytes (with checksum).
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)
Returns:
Mnemonic object: Generated mnemonic (with checksum)
Raises:
ValueError: If entropy byte length is not valid
uModule for Monero mnemonic generation.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aUnion
ubip_utils.monero.mnemonic.monero_entropy_generator
T aMoneroEntropyBitLen
aMoneroEntropyGenerator
aMoneroEntropyBitLen
ubip_utils.monero.mnemonic.monero_mnemonic
T aMoneroLanguages
aMoneroMnemonicConst
aMoneroWordsNum
aMoneroLanguages
ubip_utils.monero.mnemonic.monero_mnemonic_encoder
T aMoneroMnemonicEncoder
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
