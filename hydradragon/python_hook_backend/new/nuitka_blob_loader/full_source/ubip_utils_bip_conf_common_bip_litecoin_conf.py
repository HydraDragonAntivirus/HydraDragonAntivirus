# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.conf.common.bip_litecoin_conf


Litecoin configuration class.
It allows to return different addresses and key net versions depending on the configuration.
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
alt_key_net_ver
wif_net_ver
bytes
bip32_cls
addr_cls
addr_params
return
uBipLitecoinConf.__init__
value
aUseAlternateKeyNetVersions
uBipLitecoinConf.UseAlternateKeyNetVersions
aUseDeprecatedAddress
uBipLitecoinConf.UseDeprecatedAddress
aKeyNetVersions
uBipLitecoinConf.KeyNetVersions
aAddrParams
uBipLitecoinConf.AddrParams
a__orig_bases__
ubip_utils\bip\conf\common\bip_litecoin_conf.py
u<module bip_utils.bip.conf.common.bip_litecoin_conf>
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
alt_key_net_ver
wif_net_ver
bip32_cls
addr_cls
addr_params
a__class__

a__spec__
.bip_utils.bip.conf.common
)
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\conf\common
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
uconf\common
T aNUITKA_PACKAGE_bip_utils_bip_conf
u\not_existing
common
T aNUITKA_PACKAGE_bip_utils_bip_conf_common
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.conf.common.bip_bitcoin_cash_conf
T aBipBitcoinCashConf
aBipBitcoinCashConf
ubip_utils.bip.conf.common.bip_coin_conf
T aBipCoinConf
aBipCoinFctCallsConf
aBipCoinConf
aBipCoinFctCallsConf
ubip_utils.bip.conf.common.bip_coins
T aBipCoins
aBipCoins
ubip_utils.bip.conf.common.bip_conf_const
T aDER_PATH_HARDENED_FULL
aDER_PATH_HARDENED_SHORT
aDER_PATH_NON_HARDENED_FULL
aDER_PATH_HARDENED_FULL
aDER_PATH_HARDENED_SHORT
aDER_PATH_NON_HARDENED_FULL
ubip_utils.bip.conf.common.bip_litecoin_conf
T aBipLitecoinConf
aBipLitecoinConf
ubip_utils\bip\conf\common\__init__.py
u<module bip_utils.bip.conf.common>

a__spec__
.bip_utils.bip.conf
h
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\conf
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
conf
T aNUITKA_PACKAGE_bip_utils_bip_conf
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\bip\conf\__init__.py
u<module bip_utils.bip.conf>

a__spec__
.bip_utils.bip
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
bip
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\bip\__init__.py
u<module bip_utils.bip>

a__spec__
.bip_utils.brainwallet.brainwallet
E
aGenerateWithCustomAlgo
aBrainwalletAlgoGetter
aGetAlgo

Generate a brainwallet from the specified passphrase and coin with the specified algorithm.
Args:
passhrase (str)             : Passphrase
coin_type (BrainwalletCoins): Coin type
lgo_type (BrainwalletAlgos): Algorithm type
**algo_params               : Algorithm parameters, if any
Returns:
Brainwallet object: Algorithm class
Raises:
TypeError: If algorithm type is not of a BrainwalletAlgos enumerative
or coin type is not of a BrainwalletCoins enumerative
aBip44
aFromPrivateKey
aComputePrivateKey

Generate a brainwallet from the specified passphrase and coin with a custom algorithm.
Args:
passhrase (str)                  : Passphrase
coin_type (BrainwalletCoins)     : Coin type
lgo_cls (IBrainwalletAlgo class): Algorithm class
**algo_params                    : Algorithm parameters, if any
Returns:
Brainwallet object: Algorithm class
Raises:
TypeError: If algorithm type is not of a BrainwalletAlgos enumerative
or coin type is not of a BrainwalletCoins enumerative
bip44_obj

Construct class.
Args:
bip44_obj (Bip44Base object): Bip44Base object
aPublicKey

Return the public key.
Returns:
Bip44PublicKey object: Bip44PublicKey object
aPrivateKey

Return the private key.
Returns:
Bip44PrivateKey object: Bip44PrivateKey object
uModule for keys generation using a brainwallet (i.e. passphrase chosen by the user).
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aAny
aType
ubip_utils.bip.bip44
T aBip44
ubip_utils.bip.bip44_base
T aBip44Base
aBip44PrivateKey
aBip44PublicKey
aBip44Base
aBip44PrivateKey
aBip44PublicKey
ubip_utils.bip.conf.bip44
T aBip44Coins
aBip44Coins
ubip_utils.brainwallet.brainwallet_algo
T aBrainwalletAlgos
aBrainwalletAlgos
ubip_utils.brainwallet.brainwallet_algo_getter
T aBrainwalletAlgoGetter
ubip_utils.brainwallet.ibrainwallet_algo
T aIBrainwalletAlgo
aIBrainwalletAlgo
aBrainwalletCoins
