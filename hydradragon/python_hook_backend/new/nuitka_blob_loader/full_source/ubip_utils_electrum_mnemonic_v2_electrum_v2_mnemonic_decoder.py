# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_decoder


Electrum v2 mnemonic decoder class.
It decodes a mnemonic phrase to bytes.
a__qualname__
a__annotations__
T nnamnemonic_type
lang
return
uElectrumV2MnemonicDecoder.__init__
mnemonic
str
bytes
aDecode
uElectrumV2MnemonicDecoder.Decode
a__orig_bases__
ubip_utils\electrum\mnemonic_v2\electrum_v2_mnemonic_decoder.py
u<module bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_decoder>
T	aself
mnemonic
mnemonic_obj
words
words_list
w_wnaentropy_int
word
T a__class__
T aself
mnemonic_type
lang
a__class__
a__spec__
.bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_encoder
p
L
aElectrumV2MnemonicTypes
uMnemonic type is not an enumerative of ElectrumV2MnemonicTypes
aElectrumV2Languages
uLanguage is not an enumerative of ElectrumV2Languages
a__class__
a__init__
value
aBip39WordsListGetter
m_mnemonic_type

Construct class.
Args:
mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type
lang (ElectrumV2Languages, optional)   : Language (default: English)
Raises:
TypeError: If the language is not a ElectrumV2Languages enum or
the mnemonic type is not a ElectrumV2MnemonicTypes enum
ValueError: If loaded words list is not valid
aBytesUtils
aToInteger
aElectrumV2EntropyGenerator
aAreEntropyBitsEnough
uEntropy bit length is not enough for generating a valid mnemonic
m_words_list
aLength
entropy_int
wnamnemonic
self
aGetWordAtIdx
aElectrumV2Mnemonic
aFromList
aElectrumV2MnemonicUtils
aIsValidMnemonic
uEntropy bytes are not suitable for generating a valid mnemonic

Encode bytes to mnemonic phrase.
Args:
entropy_bytes (bytes): Entropy bytes
Returns:
Mnemonic object: Encoded mnemonic
Raises:
ValueError: If bytes length is not valid or a mnemonic cannot be generated

Module for Electrum v2 mnemonic encoding.
Reference: https://github.com/spesmilo/electrum
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.bip.bip39.bip39_mnemonic_utils
T aBip39WordsListGetter
ubip_utils.electrum.mnemonic_v2.electrum_v2_entropy_generator
T aElectrumV2EntropyGenerator
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2Languages
aElectrumV2Mnemonic
aElectrumV2MnemonicTypes
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_utils
T aElectrumV2MnemonicUtils
ubip_utils.utils.misc
T aBytesUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicEncoderBase
aMnemonic
aMnemonicEncoderBase
a__prepare__
aElectrumV2MnemonicEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
