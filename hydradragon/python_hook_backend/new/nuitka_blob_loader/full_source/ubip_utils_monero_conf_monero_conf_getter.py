# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.conf.monero_conf_getter

uClass container for Monero configuration getter constants.
a__qualname__
a__annotations__
aMONERO_MAINNET
aMainNet
aMONERO_STAGENET
aStageNet
aMONERO_TESTNET
aTestNet

Monero configuration getter class.
It allows to get the Monero configuration of a specific coin.
aMoneroConfGetter
coin_type
return
aGetConfig
uMoneroConfGetter.GetConfig
ubip_utils\monero\conf\monero_conf_getter.py
u<module bip_utils.monero.conf.monero_conf_getter>
T acoin_type
T a__class__

a__spec__
.bip_utils.monero
A
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
monero
T aNUITKA_PACKAGE_bip_utils_monero
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.monero.monero
T aMonero
aMonero
ubip_utils.monero.monero_ex
T aMoneroKeyError
aMoneroKeyError
ubip_utils.monero.monero_keys
T aMoneroPrivateKey
aMoneroPublicKey
aMoneroPrivateKey
aMoneroPublicKey
ubip_utils.monero.monero_subaddr
T aMoneroSubaddress
aMoneroSubaddress
ubip_utils\monero\__init__.py
u<module bip_utils.monero>

a__spec__
.bip_utils.monero.mnemonic
'
/
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
umonero\mnemonic
T aNUITKA_PACKAGE_bip_utils_monero
u\not_existing
mnemonic
T aNUITKA_PACKAGE_bip_utils_monero_mnemonic
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.monero.mnemonic.monero_entropy_generator
T aMoneroEntropyBitLen
aMoneroEntropyGenerator
aMoneroEntropyBitLen
aMoneroEntropyGenerator
ubip_utils.monero.mnemonic.monero_mnemonic
T aMoneroLanguages
aMoneroMnemonic
aMoneroWordsNum
aMoneroLanguages
aMoneroMnemonic
aMoneroWordsNum
ubip_utils.monero.mnemonic.monero_mnemonic_decoder
T aMoneroMnemonicDecoder
aMoneroMnemonicDecoder
ubip_utils.monero.mnemonic.monero_mnemonic_encoder
T aMoneroMnemonicEncoder
aMoneroMnemonicNoChecksumEncoder
aMoneroMnemonicWithChecksumEncoder
aMoneroMnemonicEncoder
aMoneroMnemonicNoChecksumEncoder
aMoneroMnemonicWithChecksumEncoder
ubip_utils.monero.mnemonic.monero_mnemonic_generator
T aMoneroMnemonicGenerator
aMoneroMnemonicGenerator
ubip_utils.monero.mnemonic.monero_mnemonic_validator
T aMoneroMnemonicValidator
aMoneroMnemonicValidator
ubip_utils.monero.mnemonic.monero_seed_generator
T aMoneroSeedGenerator
aMoneroSeedGenerator
ubip_utils\monero\mnemonic\__init__.py
u<module bip_utils.monero.mnemonic>

a__spec__
.bip_utils.monero.mnemonic.monero_entropy_generator
<
?
aIsValidEntropyBitLen
uEntropy bit length is not valid (

w)a__class__
a__init__

Construct class.
Args:
bit_len (int or MoneroEntropyBitLen): Entropy length in bits
Raises:
ValueError: If the bit length is not valid
aMoneroEntropyGeneratorConst
aENTROPY_BIT_LEN

Get if the specified entropy bit length is valid.
Args:
bit_len (int or MoneroEntropyBitLen): Entropy length in bits
Returns:
bool: True if valid, false otherwise
aMoneroEntropyGenerator
l u
Get if the specified entropy byte length is valid.
Args:
byte_len (int): Entropy length in bytes
Returns:
bool: True if valid, false otherwise
uModule for Monero entropy generation.
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
ubip_utils.utils.mnemonic
T aEntropyGenerator
aEntropyGenerator
a__prepare__
aMoneroEntropyBitLen
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
