# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder


Electrum v1 mnemonic decoder class.
It decodes a mnemonic phrase to bytes.
a__qualname__
aENGLISH
lang
return
uElectrumV1MnemonicDecoder.__init__
mnemonic
str
bytes
aDecode
uElectrumV1MnemonicDecoder.Decode
a__orig_bases__
ubip_utils\electrum\mnemonic_v1\electrum_v1_mnemonic_decoder.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder>
T aself
mnemonic
mnemonic_obj
words_list
w_awords
entropy_bytes
wiaword1
word2
word3
T a__class__
T aself
lang
a__class__
a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_encoder
=
a__class__
a__init__
aElectrumV1WordsListGetter

Construct class.
Args:
lang (ElectrumV1Languages, optional): Language (default: English)
Raises:
TypeError: If the language is not a ElectrumV1Languages enum
ValueError: If loaded words list is not valid
aElectrumV1EntropyGenerator
aIsValidEntropyByteLen
uEntropy byte length (

u) is not valid
l amnemonic
aMnemonicUtils
aBytesChunkToWords
self
m_words_list
big
aElectrumV1Mnemonic
aFromList

Encode bytes to mnemonic phrase.
Args:
entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128)
Returns:
Mnemonic object: Encoded mnemonic
Raises:
ValueError: If bytes length is not valid

Module for Electrum v1 mnemonic encoding.
Reference: https://github.com/spesmilo/electrum
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.electrum.mnemonic_v1.electrum_v1_entropy_generator
T aElectrumV1EntropyGenerator
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1Mnemonic
aElectrumV1Languages
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_utils
T aElectrumV1WordsListGetter
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicEncoderBase
aMnemonicUtils
aMnemonic
aMnemonicEncoderBase
a__prepare__
aElectrumV1MnemonicEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
