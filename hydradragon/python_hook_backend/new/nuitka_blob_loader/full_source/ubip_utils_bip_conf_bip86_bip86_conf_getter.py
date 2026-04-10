# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.conf.bip86.bip86_conf_getter

uClass container for BIP86 configuration getter constants.
a__qualname__
a__annotations__
aBITCOIN
aBitcoinMainNet
aBITCOIN_REGTEST
aBitcoinRegTest
aBITCOIN_TESTNET
aBitcoinTestNet

BIP86 configuration getter class.
It allows to get the BIP86 configuration of a specific coin.
aBip86ConfGetter
coin_type
return
aGetConfig
uBip86ConfGetter.GetConfig
ubip_utils\bip\conf\bip86\bip86_conf_getter.py
u<module bip_utils.bip.conf.bip86.bip86_conf_getter>
T a__class__
T acoin_type

a__spec__
.bip_utils.bip.conf.bip86
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\conf\bip86
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
uconf\bip86
T aNUITKA_PACKAGE_bip_utils_bip_conf
u\not_existing
bip86
T aNUITKA_PACKAGE_bip_utils_bip_conf_bip86
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.conf.bip86.bip86_coins
T aBip86Coins
aBip86Coins
ubip_utils.bip.conf.bip86.bip86_conf
T aBip86Conf
aBip86Conf
ubip_utils.bip.conf.bip86.bip86_conf_getter
T aBip86ConfGetter
aBip86ConfGetter
ubip_utils\bip\conf\bip86\__init__.py
u<module bip_utils.bip.conf.bip86>

a__spec__
.bip_utils.bip.conf.common.bip_bitcoin_cash_conf
N
a__class__
a__init__
T	acoin_names
coin_idx
is_testnet
def_path
key_net_ver
wif_net_ver
bip32_cls
addr_cls
addr_params
m_addr_cls_legacy
m_use_legacy_addr

Construct class.
Args:
coin_names (CoinNames object)           : Coin names
coin_idx (int)                          : Coin index
is_testnet (bool)                       : Test net flag
def_path (str)                          : Default path
key_net_ver (Bip32KeyNetVersions object): Key net versions
wif_net_ver (bytes)                     : WIF net version
bip32_cls (Bip32Base class)             : Bip32 class
ddr_params (dict)                      : Address parameters
ddr_cls (IAddrEncoder class)           : Address class
ddr_cls_legacy (IAddrEncoder class)    : Legacy ddress class

Select if use the legacy address.
Args:
value (bool): True for using legacy address, false for using the standard one
m_addr_cls

Get the address type. It overrides the method in BipCoinConf.
Returns:
IAddrEncoder class: Address class
m_addr_params
legacy
std

Get the address parameters. It overrides the method in BipCoinConf.
Returns:
dict: Address parameters
uModule with helper class for Bitcoin Cash configuration handling.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aType
ubip_utils.addr
T aIAddrEncoder
aIAddrEncoder
ubip_utils.bip.bip32
T aBip32KeyNetVersions
aBip32KeyNetVersions
ubip_utils.bip.conf.common.bip_coin_conf
T aBip32Base
aBipCoinConf
aBip32Base
aBipCoinConf
ubip_utils.utils.conf
T aCoinNames
aCoinNames
a__prepare__
aBipBitcoinCashConf
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
