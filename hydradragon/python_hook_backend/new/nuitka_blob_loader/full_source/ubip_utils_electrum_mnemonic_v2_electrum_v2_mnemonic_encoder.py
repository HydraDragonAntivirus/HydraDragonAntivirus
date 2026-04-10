# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_encoder


Electrum v2 mnemonic encoder class.
It encodes bytes to the mnemonic phrase.
a__qualname__
a__annotations__
aENGLISH
mnemonic_type
lang
return
uElectrumV2MnemonicEncoder.__init__
entropy_bytes
bytes
aEncode
uElectrumV2MnemonicEncoder.Encode
a__orig_bases__
ubip_utils\electrum\mnemonic_v2\electrum_v2_mnemonic_encoder.py
u<module bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_encoder>
T a__class__
T aself
entropy_bytes
entropy_int
wnamnemonic
word_idx
mnemonic_obj
T aself
mnemonic_type
lang
a__class__

a__spec__
.bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_generator
N
aElectrumV2MnemonicEncoder
m_mnemonic_encoder

Construct class.
Args:
mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type
lang (ElectrumV2Languages, optional)   : Language (default: English)
Raises:
TypeError: If the language is not a ElectrumV2Languages enum or
the mnemonic type is not a ElectrumV2MnemonicTypes enum
ValueError: If language words list is not valid
aElectrumV2MnemonicConst
aMNEMONIC_WORD_NUM
uWords number for mnemonic (

u) is not valid
aElectrumV2WordsNum
aElectrumV2MnemonicGeneratorConst
aWORDS_NUM_TO_ENTROPY_LEN
aElectrumV2EntropyGenerator
aGenerate
aFromEntropy

Generate mnemonic with the specified words number and type from random entropy.
Args:
words_num (int or ElectrumV2WordsNum)  : Number of words (12)
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If words number is not valid
aAreEntropyBitsEnough
aBytesUtils
aToInteger
aMAX_ATTEMPTS
entropy_int
self
aEncode
aIntegerUtils
aToBytes
uUnable to generate a valid mnemonic

Generate mnemonic from the specified entropy bytes.
Because of the mnemonic encoding algorithm used by Electrum, the specified entropy will only be a starting
point to find a suitable one. Therefore, it's very likely that the actual entropy bytes will be different.
To get the actual entropy bytes, just decode the generated mnemonic.
Please note that, to successfully generate a mnemonic, the bits of the big endian integer encoded entropy
shall be at least 121 (for 12 words) or 253 (for 24 words). Otherwise, a mnemonic generation is not possible
nd a ValueError exception will be raised.
Args:
entropy_bytes (bytes): Entropy bytes
Returns:
Mnemonic object: Generated mnemonic
Raises:
ValueError: If entropy byte length is not valid or a mnemonic cannot be generated
uModule for Electrum v2 mnemonic generation.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aUnion
ubip_utils.electrum.mnemonic_v2.electrum_v2_entropy_generator
T aElectrumV2EntropyBitLen
aElectrumV2EntropyGenerator
aElectrumV2EntropyBitLen
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2Languages
aElectrumV2MnemonicConst
aElectrumV2MnemonicTypes
aElectrumV2WordsNum
aElectrumV2Languages
aElectrumV2MnemonicTypes
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_encoder
T aElectrumV2MnemonicEncoder
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
