# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.algorand.mnemonic.algorand_mnemonic_generator

uClass container for Algorand mnemonic generator constants.
a__qualname__
a__annotations__
aWORDS_NUM_25
aBIT_LEN_256

Algorand mnemonic generator class.
It generates 25-words mnemonic in according to Algorand wallets.
aAlgorandMnemonicGenerator
aENGLISH
lang
return
a__init__
uAlgorandMnemonicGenerator.__init__
words_num
aFromWordsNumber
uAlgorandMnemonicGenerator.FromWordsNumber
entropy_bytes
uAlgorandMnemonicGenerator.FromEntropy
ubip_utils\algorand\mnemonic\algorand_mnemonic_generator.py
u<module bip_utils.algorand.mnemonic.algorand_mnemonic_generator>
T a__class__
T aself
entropy_bytes
T aself
words_num
entropy_bit_len
entropy_bytes
T aself
lang
a__spec__
.bip_utils.algorand.mnemonic.algorand_mnemonic_utils
3
aSha512_256
aQuickDigest
aAlgorandMnemonicConst
aCHECKSUM_BYTE_LEN

Compute checksum.
Args:
data_bytes (bytes): Data bytes
Returns:
bytes: Computed checksum
aAlgorandMnemonicUtils
aComputeChecksum
aConvertBits
l l u
Compute checksum word index.
Args:
data_bytes (bytes): Data bytes
Returns:
str: Computed checksum word index
from_bits
acc
bits
to_bits
ret
max_out_val

Perform bit conversion.
The function takes the input data (list of integers or byte sequence) and convert every value from
the specified number of bits to the specified one.
It returns a list of integer where every number is less than 2^to_bits.
Args:
data (list[int] or bytes): Data to be converted
from_bits (int)          : Number of bits to start from
to_bits (int)            : Number of bits to end with
Returns:
list[int]: List of converted values, None in case of errors
uModule for Algorand mnemonic utility classes.
a__doc__
a__file__
origin
has_location
a__cached__
aList
aOptional
aUnion
ubip_utils.algorand.mnemonic.algorand_mnemonic
T aAlgorandMnemonicConst
ubip_utils.utils.crypto
T aSha512_256
