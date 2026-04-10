# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.conf.common.bip_coins

uBase enum for bip coins.
a__qualname__
a__orig_bases__
ubip_utils\bip\conf\common\bip_coins.py
u<module bip_utils.bip.conf.common.bip_coins>

a__spec__
.bip_utils.bip.conf.common.bip_conf_const
I
uModule for generic BIP configuration constants.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
u0'/0'/0'
aDER_PATH_HARDENED_FULL
u0'
aDER_PATH_HARDENED_SHORT
u0'/0/0
aDER_PATH_NON_HARDENED_FULL
ubip_utils\bip\conf\common\bip_conf_const.py
u<module bip_utils.bip.conf.common.bip_conf_const>

a__spec__
.bip_utils.bip.conf.common.bip_litecoin_conf
S
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
m_alt_key_net_ver
m_use_alt_key_net_ver
m_use_depr_addr

Construct class.
Args:
coin_names (CoinNames object)               : Coin names
coin_idx (int)                              : Coin index
is_testnet (bool)                           : Test net flag
def_path (str)                              : Default path
key_net_ver (Bip32KeyNetVersions object)    : Key net versions
lt_key_net_ver (Bip32KeyNetVersions object): Key net versions (alternate)
wif_net_ver (bytes)                         : WIF net version
bip32_cls (Bip32Base class)                 : Bip32 class
ddr_params (dict)                          : Address parameters
ddr_cls (IAddrEncoder class)               : Address class

Select if use the alternate key net version.
Args:
value (bool): True for using alternate key net version, false for using the standard one

Select if use the deprecated address.
Args:
value (bool): True for using deprecated address, false for using the standard one
m_key_net_ver

Get key net versions. It overrides the method in BipCoinConf.
Litecoin overrides the method because it can have 2 different key net versions.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
net_ver
m_addr_params
depr_net_ver
std_net_ver

Get the address parameters. It overrides the method in BipCoinConf.
Returns:
dict: Address parameters
uModule with helper class for Litecoin configuration handling.
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
aBipLitecoinConf
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
