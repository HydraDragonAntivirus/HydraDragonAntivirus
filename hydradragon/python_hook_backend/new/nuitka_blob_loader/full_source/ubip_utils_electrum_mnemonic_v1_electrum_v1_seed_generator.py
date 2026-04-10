# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_seed_generator

uClass container for Electrum v1 seed generator constants.
a__qualname__
a__annotations__
l   u
Electrum seed generator class (v1).
It generates the seed from a mnemonic.
aElectrumV1SeedGenerator
aENGLISH
mnemonic
lang
return
a__init__
uElectrumV1SeedGenerator.__init__
D areturn
Obytes
aGenerate
uElectrumV1SeedGenerator.Generate
D aentropy_bytes
return
Obytes
pa__GenerateSeed
uElectrumV1SeedGenerator.__GenerateSeed
ubip_utils\electrum\mnemonic_v1\electrum_v1_seed_generator.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_seed_generator>
T a__class__
T aself
T aentropy_bytes
entropy_hex
whw_T aself
mnemonic
lang
entropy_bytes

a__spec__
.bip_utils.electrum.mnemonic_v2
.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uelectrum\mnemonic_v2
T aNUITKA_PACKAGE_bip_utils_electrum
u\not_existing
mnemonic_v2
T aNUITKA_PACKAGE_bip_utils_electrum_mnemonic_v2
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.electrum.mnemonic_v2.electrum_v2_entropy_generator
T aElectrumV2EntropyBitLen
aElectrumV2EntropyGenerator
aElectrumV2EntropyBitLen
aElectrumV2EntropyGenerator
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2Languages
aElectrumV2Mnemonic
aElectrumV2MnemonicTypes
aElectrumV2WordsNum
aElectrumV2Languages
aElectrumV2Mnemonic
aElectrumV2MnemonicTypes
aElectrumV2WordsNum
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_decoder
T aElectrumV2MnemonicDecoder
aElectrumV2MnemonicDecoder
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_encoder
T aElectrumV2MnemonicEncoder
aElectrumV2MnemonicEncoder
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_generator
T aElectrumV2MnemonicGenerator
aElectrumV2MnemonicGenerator
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_validator
T aElectrumV2MnemonicValidator
aElectrumV2MnemonicValidator
ubip_utils.electrum.mnemonic_v2.electrum_v2_seed_generator
T aElectrumV2SeedGenerator
aElectrumV2SeedGenerator
ubip_utils\electrum\mnemonic_v2\__init__.py
u<module bip_utils.electrum.mnemonic_v2>

a__spec__
.bip_utils.electrum.mnemonic_v2.electrum_v2_entropy_generator
Q
aIsValidEntropyBitLen
uEntropy bit length is not valid (

w)a__class__
a__init__

Construct class.
Args:
bit_len (int or ElectrumV2EntropyBitLen): Entropy length in bits
Raises:
ValueError: If the bit length is not valid
aElectrumV2EntropyGeneratorConst
aENTROPY_BIT_LEN
bit_len
aElectrumV2MnemonicConst
aWORD_BIT_LEN

Get if the specified entropy bit length is valid.
Args:
bit_len (int): Entropy length in bits
Returns:
bool: True if valid, false otherwise
aElectrumV2EntropyGenerator
l u
Get if the specified entropy byte length is valid.
Args:
byte_len (int): Entropy length in bytes
Returns:
bool: True if valid, false otherwise
aBytesUtils
aToInteger
math
floor
log
l u
Get if the entropy bits are enough to generate a valid mnemonic.
Args:
entropy (bytes or int): Entropy
Returns:
bool: True if enough, false otherwise
uModule for Electrum v2 mnemonic entropy generation.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aIntEnum
unique
aIntEnum
unique
aList
aUnion
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2MnemonicConst
ubip_utils.utils.misc
T aBytesUtils
ubip_utils.utils.mnemonic
T aEntropyGenerator
aEntropyGenerator
a__prepare__
aElectrumV2EntropyBitLen
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
