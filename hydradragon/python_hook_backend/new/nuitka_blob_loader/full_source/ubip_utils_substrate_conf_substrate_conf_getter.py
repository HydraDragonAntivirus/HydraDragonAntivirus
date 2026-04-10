# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.substrate.conf.substrate_conf_getter

uClass container for Substrate configuration getter constants.
a__qualname__
a__annotations__
aACALA
aAcala
aBIFROST
aBifrost
aCHAINX
aChainX
aEDGEWARE
aEdgeware
aGENERIC
aGeneric
aKARURA
aKarura
aKUSAMA
aKusama
aMOONBEAM
aMoonbeam
aMOONRIVER
aMoonriver
aPHALA
aPhala
aPLASM
aPlasm
aPOLKADOT
aPolkadot
aSORA
aSora
aSTAFI
aStafi

Substrate configuration getter class.
It allows to get the Substrate configuration of a specific coin.
aSubstrateConfGetter
coin_type
return
aGetConfig
uSubstrateConfGetter.GetConfig
ubip_utils\substrate\conf\substrate_conf_getter.py
u<module bip_utils.substrate.conf.substrate_conf_getter>
T acoin_type
T a__class__

a__spec__
.bip_utils.substrate
$
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
substrate
T aNUITKA_PACKAGE_bip_utils_substrate
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.substrate.substrate
T aSubstrate
aSubstrateCoins
aSubstrate
aSubstrateCoins
ubip_utils.substrate.substrate_ex
T aSubstrateKeyError
aSubstratePathError
aSubstrateKeyError
aSubstratePathError
ubip_utils.substrate.substrate_keys
T aSubstratePrivateKey
aSubstratePublicKey
aSubstratePrivateKey
aSubstratePublicKey
ubip_utils.substrate.substrate_path
T aSubstratePath
aSubstratePathElem
aSubstratePathParser
aSubstratePath
aSubstratePathElem
aSubstratePathParser
ubip_utils\substrate\__init__.py
u<module bip_utils.substrate>

a__spec__
.bip_utils.substrate.mnemonic
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
usubstrate\mnemonic
T aNUITKA_PACKAGE_bip_utils_substrate
u\not_existing
mnemonic
T aNUITKA_PACKAGE_bip_utils_substrate_mnemonic
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.substrate.mnemonic.substrate_bip39_seed_generator
T aSubstrateBip39SeedGenerator
aSubstrateBip39SeedGenerator
ubip_utils\substrate\mnemonic\__init__.py
u<module bip_utils.substrate.mnemonic>

a__spec__
.bip_utils.substrate.mnemonic.substrate_bip39_seed_generator
Z
A
a__class__
a__init__
aBip39MnemonicDecoder
aDecode
m_entropy_bytes

Construct class.
Args:
mnemonic (str or Mnemonic object): Mnemonic
lang (Bip39Languages, optional)  : Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid
aStringUtils
aNormalizeNfkd
aBip39SeedGeneratorConst
aSEED_SALT_MOD
aPbkdf2HmacSha512
aDeriveKey
aSEED_PBKDF2_ROUNDS

Generate the seed using the specified passphrase.
Args:
passphrase (str, optional): Passphrase, empty if not specified
Returns:
bytes: Generated seed
uModule for Substrate mnemonic seed generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.bip.bip39
T aBip39Languages
aBip39MnemonicDecoder
aIBip39SeedGenerator
aBip39Languages
aIBip39SeedGenerator
ubip_utils.bip.bip39.bip39_seed_generator
T aBip39SeedGeneratorConst
ubip_utils.utils.crypto
T aPbkdf2HmacSha512
ubip_utils.utils.misc
T aStringUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
a__prepare__
aSubstrateBip39SeedGenerator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
