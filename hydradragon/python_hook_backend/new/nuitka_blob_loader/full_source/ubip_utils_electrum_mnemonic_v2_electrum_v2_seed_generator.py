# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v2.electrum_v2_seed_generator

uClass container for Electrum seed generator constants (v2).
a__qualname__
a__annotations__
electrum
l  u
Electrum seed generator class (v2).
It generates the seed from a mnemonic.
aElectrumV2SeedGenerator
m_entropy_bytes
T namnemonic
lang
return
a__init__
uElectrumV2SeedGenerator.__init__
T u
D apassphrase
return
Ostr
Obytes
aGenerate
uElectrumV2SeedGenerator.Generate
ubip_utils\electrum\mnemonic_v2\electrum_v2_seed_generator.py
u<module bip_utils.electrum.mnemonic_v2.electrum_v2_seed_generator>
T a__class__
T aself
passphrase
salt
T aself
mnemonic
lang

a__spec__
.bip_utils.monero.conf
!
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
umonero\conf
T aNUITKA_PACKAGE_bip_utils_monero
u\not_existing
conf
T aNUITKA_PACKAGE_bip_utils_monero_conf
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.monero.conf.monero_coin_conf
T aMoneroCoinConf
aMoneroCoinConf
ubip_utils.monero.conf.monero_coins
T aMoneroCoins
aMoneroCoins
ubip_utils.monero.conf.monero_conf
T aMoneroConf
aMoneroConf
ubip_utils.monero.conf.monero_conf_getter
T aMoneroConfGetter
aMoneroConfGetter
ubip_utils\monero\conf\__init__.py
u<module bip_utils.monero.conf>

a__spec__
.bip_utils.monero.conf.monero_coin_conf
>
aCoinNames
aParamByKey
T aaddr_net_ver
T aaddr_int_net_ver
T asubaddr_net_ver
T acoin_names
addr_net_ver
int_addr_net_ver
subaddr_net_ver

Construct class.
Args:
coin_conf (CoinConf object): Generic coin configuration object
Returns:
MoneroCoinConf object: MoneroCoinConf object
m_coin_names
m_addr_net_ver
m_int_addr_net_ver
m_subaddr_net_ver

Construct class.
Args:
coin_names (CoinNames object): Coin names
ddr_net_ver (bytes)         : Address net version
int_addr_net_ver (bytes)     : Integrated address net version
subaddr_net_ver (bytes)      : Subaddress net version

Get coin names.
Returns:
CoinNames object: CoinNames object

Get address net version.
Returns:
bytes: Address net version

Get integrated address net version.
Returns:
bytes: Address net version

Get subaddress net version.
Returns:
bytes: Subaddress net version
uModule with helper class for Monero coins configuration handling.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aDict
ubip_utils.coin_conf
T aCoinConf
aCoinConf
ubip_utils.utils.conf
T aCoinNames
aUtilsCoinNames
