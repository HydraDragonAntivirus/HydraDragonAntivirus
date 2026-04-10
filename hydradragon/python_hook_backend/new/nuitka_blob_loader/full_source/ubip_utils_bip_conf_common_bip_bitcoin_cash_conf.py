# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.conf.common.bip_bitcoin_cash_conf


Bitcoin Cash configuration class.
It allows to return different addresses depending on the configuration.
a__qualname__
a__annotations__
bool
coin_names
coin_idx
int
is_testnet
def_path
str
key_net_ver
wif_net_ver
bytes
bip32_cls
addr_cls
addr_cls_legacy
addr_params
return
uBipBitcoinCashConf.__init__
value
aUseLegacyAddress
uBipBitcoinCashConf.UseLegacyAddress
aAddrClass
uBipBitcoinCashConf.AddrClass
aAddrParams
uBipBitcoinCashConf.AddrParams
a__orig_bases__
ubip_utils\bip\conf\common\bip_bitcoin_cash_conf.py
u<module bip_utils.bip.conf.common.bip_bitcoin_cash_conf>
T aself
T a__class__
T aself
value
T aself
coin_names
coin_idx
is_testnet
def_path
key_net_ver
wif_net_ver
bip32_cls
addr_cls
addr_cls_legacy
addr_params
a__class__

a__spec__
.bip_utils.bip.conf.common.bip_coin_conf
o
m_fct_names

Construct class.
Args:
rgs (str): Function names to be called
res

Resolve function calls and get the result.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
Returns:
Any: Result
m_coin_names
m_coin_idx
m_is_testnet
m_def_path
m_key_net_ver
m_wif_net_ver
m_bip32_cls
m_addr_params
values
m_any_addr_params_fct_call
m_addr_cls

Construct class.
Args:
coin_names (CoinNames object)           : Coin names
coin_idx (int)                          : Coin index
is_testnet (bool)                       : Test net flag
def_path (str)                          : Default path
key_net_ver (Bip32KeyNetVersions object): Key net versions
wif_net_ver (bytes)                     : WIF net version, None if not supported
bip32_cls (Bip32Base class)             : Bip32 class
ddr_params (dict)                      : Address parameters
ddr_cls (IAddrEncoder class)           : Address class
aBipCoinFctCallsConf
u<genexpr>
uBipCoinConf.__init__.<locals>.<genexpr>

Get coin names.
Returns:
CoinNames object: CoinNames object

Get coin index.
Returns:
int: Coin index

Get if test net.
Returns:
bool: True if test net, false otherwise

Get the default derivation path.
Returns:
str: Default derivation path

Get key net versions.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object

Get WIF net version.
Returns:
bytes: WIF net version bytes
None: If WIF is not supported

Get the Bip32 class.
Returns:
Bip32Base class: Bip32Base class

Get the address parameters.
Returns:
dict: Address parameters
aAddrParams
items
aResolveCalls
pub_key

Get the address parameters with resolved function calls.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
Returns:
dict: Address parameters

Get the address class.
Returns:
IAddrEncoder class: Address class
uModule with helper class for generic BIP coins configuration handling.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aOptional
aTuple
aType
ubip_utils.addr
T aIAddrEncoder
aIAddrEncoder
ubip_utils.bip.bip32
T aBip32Base
aBip32KeyNetVersions
aBip32PublicKey
aBip32Base
aBip32KeyNetVersions
aBip32PublicKey
ubip_utils.utils.conf
T aCoinNames
aCoinNames
aUtilsCoinNames
