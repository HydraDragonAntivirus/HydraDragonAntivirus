# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_generator

uClass container for Electrum v2 mnemonic generator constants.
a__qualname__
a__annotations__
aWORDS_NUM_12
aBIT_LEN_132
aWORDS_NUM_24
aBIT_LEN_264
l  =u
Electrum v2 mnemonic generator class.
It generates 12 or 24-words mnemonic in according to Electrum wallets.
aElectrumV2MnemonicGenerator
aENGLISH
mnemonic_type
lang
return
a__init__
uElectrumV2MnemonicGenerator.__init__
words_num
aFromWordsNumber
uElectrumV2MnemonicGenerator.FromWordsNumber
entropy_bytes
uElectrumV2MnemonicGenerator.FromEntropy
ubip_utils\electrum\mnemonic_v2\electrum_v2_mnemonic_generator.py
u<module bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_generator>
T a__class__
T aself
entropy_bytes
entropy_int
wianew_entropy_int
T aself
words_num
entropy_bit_len
entropy_bytes
T aself
mnemonic_type
lang
a__spec__
.bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_utils
G
aElectrumV2MnemonicUtils
a_ElectrumV2MnemonicUtils__IsBip39OrV1Mnemonic
a_ElectrumV2MnemonicUtils__IsType
a_ElectrumV2MnemonicUtils__IsAnyType

Get if the specified mnemonic is valid.
Args:
mnemonic (Mnemonic)                    : Mnemonic
mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type
Returns:
bool: True if valid, false otherwise
aBip39MnemonicValidator
aIsValid
aElectrumV1MnemonicValidator

Get if the specified mnemonic is a valid BIP39 or v1 Electrum mnemonic.
Args:
mnemonic (Mnemonic): Mnemonic
Returns:
bool: True if valid, false otherwise
aHmacSha512
aQuickDigest
aElectrumV2MnemonicUtilsConst
aHMAC_KEY
aToStr
aElectrumV2MnemonicTypes
aBytesUtils
aToHexString
whastartswith
aElectrumV2MnemonicConst
aTYPE_TO_PREFIX

Get if the specified mnemonic is of any valid type.
Args:
mnemonic (Mnemonic): Mnemonic
Returns:
bool: True if valid, false otherwise

Get if the specified mnemonic is of the specified type.
Args:
mnemonic (Mnemonic)                    : Mnemonic
mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type
Returns:
bool: True if valid, false otherwise
uModule for Electrum v2 mnemonic generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
ubip_utils.bip.bip39
T aBip39MnemonicValidator
ubip_utils.electrum.mnemonic_v1
T aElectrumV1MnemonicValidator
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2MnemonicConst
aElectrumV2MnemonicTypes
ubip_utils.utils.crypto
T aHmacSha512
ubip_utils.utils.misc
T aBytesUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
