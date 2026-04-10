# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.cip1852.conf.cip1852_conf_getter

uClass container for CIP-1852 configuration getter constants.
a__qualname__
a__annotations__
aCARDANO_ICARUS
aCardanoIcarusMainNet
aCARDANO_LEDGER
aCardanoLedgerMainNet
aCARDANO_ICARUS_TESTNET
aCardanoIcarusTestNet
aCARDANO_LEDGER_TESTNET
aCardanoLedgerTestNet

CIP-1852 configuration getter class.
It allows to get the CIP-1852 configuration of a specific coin.
aCip1852ConfGetter
coin_type
return
aGetConfig
uCip1852ConfGetter.GetConfig
ubip_utils\cardano\cip1852\conf\cip1852_conf_getter.py
u<module bip_utils.cardano.cip1852.conf.cip1852_conf_getter>
T a__class__
T acoin_type

a__spec__
.bip_utils.cardano.cip1852.conf
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ucardano\cip1852\conf
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
ucip1852\conf
T aNUITKA_PACKAGE_bip_utils_cardano_cip1852
u\not_existing
conf
T aNUITKA_PACKAGE_bip_utils_cardano_cip1852_conf
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.cardano.cip1852.conf.cip1852_coins
T aCip1852Coins
aCip1852Coins
ubip_utils.cardano.cip1852.conf.cip1852_conf
T aCip1852Conf
aCip1852Conf
ubip_utils.cardano.cip1852.conf.cip1852_conf_getter
T aCip1852ConfGetter
aCip1852ConfGetter
ubip_utils\cardano\cip1852\conf\__init__.py
u<module bip_utils.cardano.cip1852.conf>

a__spec__
.bip_utils.cardano.cip1852
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ucardano\cip1852
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
cip1852
T aNUITKA_PACKAGE_bip_utils_cardano_cip1852
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.cardano.cip1852.cip1852
T aCip1852
aCip1852
ubip_utils\cardano\cip1852\__init__.py
u<module bip_utils.cardano.cip1852>

a__spec__
.bip_utils.cardano
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
cardano
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\cardano\__init__.py
u<module bip_utils.cardano>

a__spec__
.bip_utils.cardano.mnemonic.cardano_byron_legacy_seed_generator
0
aBlake2b256
aQuickDigest
cbor2
dumps
aBip39MnemonicDecoder
aDecode
m_seed_bytes

Construct class.
Args:
mnemonic (str or Mnemonic object): Mnemonic
lang (Bip39Languages, optional)  : Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid

Generate seed. The seed is simply the entropy bytes in Cardano case.
There is no really need of this method, since the seed is always the same, but it's
kept in this way to have the same usage of Bip39/Substrate seed generator
(i.e. CardanoSeedGenerator(mnemonic).Generate() ).
Returns:
bytes: Generated seed
uModule for Cardano Byron legacy mnemonic seed generation (old Daedalus version).
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
aBip39Languages
ubip_utils.utils.crypto
T aBlake2b256
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
