# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.algorand.mnemonic.algorand_seed_generator


Algorand seed generator class.
It generates the seed from a mnemonic.
aAlgorandSeedGenerator
a__qualname__
a__annotations__
aENGLISH
mnemonic
lang
return
a__init__
uAlgorandSeedGenerator.__init__
D areturn
Obytes
aGenerate
uAlgorandSeedGenerator.Generate
ubip_utils\algorand\mnemonic\algorand_seed_generator.py
u<module bip_utils.algorand.mnemonic.algorand_seed_generator>
T a__class__
T aself
T aself
mnemonic
lang

a__spec__
.bip_utils.algorand.mnemonic
-
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ualgorand\mnemonic
T aNUITKA_PACKAGE_bip_utils_algorand
u\not_existing
mnemonic
T aNUITKA_PACKAGE_bip_utils_algorand_mnemonic
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.algorand.mnemonic.algorand_entropy_generator
T aAlgorandEntropyBitLen
aAlgorandEntropyGenerator
aAlgorandEntropyBitLen
aAlgorandEntropyGenerator
ubip_utils.algorand.mnemonic.algorand_mnemonic
T aAlgorandLanguages
aAlgorandMnemonic
aAlgorandWordsNum
aAlgorandLanguages
aAlgorandMnemonic
aAlgorandWordsNum
ubip_utils.algorand.mnemonic.algorand_mnemonic_decoder
T aAlgorandMnemonicDecoder
aAlgorandMnemonicDecoder
ubip_utils.algorand.mnemonic.algorand_mnemonic_encoder
T aAlgorandMnemonicEncoder
aAlgorandMnemonicEncoder
ubip_utils.algorand.mnemonic.algorand_mnemonic_generator
T aAlgorandMnemonicGenerator
aAlgorandMnemonicGenerator
ubip_utils.algorand.mnemonic.algorand_mnemonic_validator
T aAlgorandMnemonicValidator
aAlgorandMnemonicValidator
ubip_utils.algorand.mnemonic.algorand_seed_generator
T aAlgorandSeedGenerator
aAlgorandSeedGenerator
ubip_utils\algorand\mnemonic\__init__.py
u<module bip_utils.algorand.mnemonic>

a__spec__
.bip_utils.base58.base58
"
c
aDoubleSha256
aQuickDigest
aBase58Const
aCHECKSUM_BYTE_LEN

Compute Base58 checksum.
Args:
data_bytes (bytes): Data bytes
Returns:
bytes: Computed checksum
aBase58Alphabets
uAlphabet index is not an enumerative of Base58Alphabets

aALPHABETS
aBytesUtils
aToInteger
val
aRADIX
enc
lstrip
T d

Encode bytes into a Base58 string.
Args:
data_bytes (bytes)                  : Data bytes
lph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
Returns:
str: Encoded string
Raises:
TypeError: If alphabet index is not a Base58Alphabets enumerative
aBase58Encoder
aEncode
aBase58Utils
aComputeChecksum

Encode bytes into Base58 string with checksum.
Args:
data_bytes (bytes)                  : Data bytes
lph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
Returns:
str: Encoded string with checksum
Raises:
TypeError: If alphabet index is not a Base58Alphabets enumerative
:nnq aalphabet
index
B
l  adec
append
d

Decode bytes from a Base58 string.
Args:
data_str (str)                      : Data string
lph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
Returns:
bytes: Decoded bytes
Raises:
TypeError: If alphabet index is not a Base58Alphabets enumerative
aBase58Decoder
aDecode
aBase58ChecksumError
uInvalid checksum (expected
aToHexString
u, got
w)u
Decode bytes from a Base58 string with checksum.
Args:
data_str (str)                      : Data string
lph_idx (Base58Alphabets, optional): Alphabet index, Bitcoin by default
Returns:
bytes: Decoded bytes (checksum removed)
Raises:
ValueError: If the string is not a valid Base58 format
TypeError: If alphabet index is not a Base58Alphabets enumerative
Base58ChecksumError: If checksum is not valid
uModule for base58 decoding/encoding.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
auto
unique
aEnum
auto
unique
aDict
ubip_utils.base58.base58_ex
T aBase58ChecksumError
ubip_utils.utils.crypto
T aDoubleSha256
ubip_utils.utils.misc
T aBytesUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
