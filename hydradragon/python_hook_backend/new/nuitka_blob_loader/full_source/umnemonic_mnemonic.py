# Reconstructed from integrated Nuitka blob
# Module: umnemonic.mnemonic

a__qualname__
a__orig_bases__
D wvareturn
bytes
str
T Oobject
T aenglish
nD alanguage
wordlist
str
ulist[str] | None
a__init__
uMnemonic.__init__
classmethod
D areturn
ulist[str]
uMnemonic.list_languages
staticmethod
D atxt
return
ut.AnyStr
str
uMnemonic.normalize_string
D acode
return
str
padetect_language
uMnemonic.detect_language
T l  D astrength
return
int
str
generate
uMnemonic.generate
D awords
return
ulist[str] | str
bytearray
to_entropy
uMnemonic.to_entropy
D adata
return
bytes
str
uMnemonic.to_mnemonic
D amnemonic
return
str
bool
check
uMnemonic.check
D aprefix
return
str
puMnemonic.expand_word
D amnemonic
return
str
paexpand
uMnemonic.expand
T u
D amnemonic
passphrase
return
str
pabytes
to_seed
uMnemonic.to_seed
T FD aseed
testnet
return
bytes
bool
str
to_hd_master_key
uMnemonic.to_hd_master_key
D areturn
aNone
main
umnemonic\mnemonic.py
T a.0
lang
cls
T a.0
wpT a.0
wpaword
T a.0
wcaword
T a.0
wcT wxaself
T aself
u<module mnemonic.mnemonic>
T a__class__
T aself
language
wordlist
wdwfT wvaalphabet
wpaacc
wcastring
idx
T
self
mnemonic
mnemonic_list
idx
wbwlwdwhand
nh
T acls
code
possible
words
word
complete
exact
T aself
mnemonic
T aself
prefix
matches
T aself
strength
T acls
T asys
hex_data
data
wmT atxt
utxt
T aself
words
concatLenBits
concatBits
wordindex
word
ndx
ii
checksumLengthBits
entropyLengthBits
entropy
jj
hashBytes
hashBits
wiT aseed
testnet
xprv
hashed_xprv
T aself
data
whwbaresult
wiaidx
T acls
mnemonic
passphrase
mnemonic_bytes
passphrase_bytes
stretched
a__spec__
.modules.balance.apis
e
,

realtokens
print
aFore
aYELLOW
u[
aRED
uCONFIG
u]
aLIGHTRED_EX
uPlease insert at least one key from each website for mnemonic checks
uPRESS ENTER TO EXIT
l arandom
choice
a__doc__
a__file__
origin
has_location
a__cached__
sys
colorama
T aFore
init
init
colorama_init
T aconfig
l aconfig
T tT aautoreset
api_keys
aBLOCKCYPHER_TOKENS
aCRYPTOAPIS_TOKENS
aTRONSCAN_TOKENS
aTRONGRID_TOKENS
aETHERSCAN_TOKENS
aNOWNODES_TOKENS
aBSCSCAN_TOKENS
D atokenslist
return
AOlist
T Ostr
Ostr
get_random_token
umodules\balance\apis.py
u<module modules.balance.apis>
T atokenslist
realtokens
token
a__spec__
.modules.balance.bitcoin
L
l   /uhttps://blockchain.info/balance?active=

wcasession
get
status_code
l  ajson
final_balance
convert_to_btc
uhttps://api.blockchair.com/bitcoin/dashboards/address/
uhttps://blockstream.info/api/address/
T achain_stats
T afunded_txo_sum
l
T aspent_txo_sum
l
print
uRequest failed with status code:
uhttps://mempool.space/api/address/
uhttps://chainz.cryptoid.info/btc/api.dws?q=getbalance&a=
text
uhttps://api.bitcore.io/api/BTC/mainnet/address/
T abalance
uhttps://api.cryptoapis.io/v1/bc/btc/mainnet/address/
u/balance
uX-API-Key
get_random_token
aCRYPTOAPIS_TOKENS
payload
aBLOCKCYPHER_TOKENS
uhttps://api.blockcypher.com/v1/btc/main/addrs/
u/balance?token=
aNOWNODES_TOKENS
uhttps://btcbook.nownodes.io/api/v2/address/
uapi-key
balance
fetch_from_blockcypher
fetch_from_cryptoapis
fetch_from_nownodes
fetch_from_blockchair
fetch_from_cryptoid
fetch_from_bitcore
fetch_from_blockstream
fetch_from_mempool
random
shuffle
address
a__name__
T nna__doc__
a__file__
origin
has_location
a__cached__
sys
apis
T aget_random_token
aCRYPTOAPIS_TOKENS
aBLOCKCYPHER_TOKENS
aNOWNODES_TOKENS
proxyconnector
T aStealthConnection
aStealthConnection
T aconfig
l aconfig
fetch_from_blockchain
fetch_bitcoin_balance
umodules\balance\bitcoin.py
u<module modules.balance.bitcoin>
T asatoshis_amount
T aaddress
aPAIDAPIS_fetch_functions
aFREEAPIS_fetch_functions
fetch_functions
fetch_function
balance_btc
weT aaddress
url
response
balance_btc
T aaddress
url
response
data
balance_satoshi
balance_btc
T aaddress
token
url
response
balance_satoshis
T aaddress
url
response
chain_stats
funded_txo_sum
spent_txo_sum
balance_satoshis
T aaddress
url
headers
response
balance_btc
T aaddress
api_key
url
headers
response
data
balance
a__spec__
.modules.balance.bnb_bsc
-
%
get_random_token
aBSCSCAN_TOKENS
uhttps://api.bscscan.com/api?module=account&action=balance&address=

u&tag=latest&apikey=
wcasession
get
status_code
l  ajson
T astatus
w1aresult
f
Ngm  Cafetch_from_bscscan
aBSCScan
T nna__doc__
a__file__
origin
has_location
a__cached__
apis
T aget_random_token
aBSCSCAN_TOKENS
proxyconnector
T aStealthConnection
aStealthConnection
T aconfig
l aconfig
fetch_bnb_balance
umodules\balance\bnb_bsc.py
u<module modules.balance.bnb_bsc>
T aaddress
balance_bnb
weT aaddress
aAPI_KEY
url
response
data
a__spec__
.modules.balance
-
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_modules
u\not_existing
balance
T aNUITKA_PACKAGE_modules_balance
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
bitcoin
T afetch_bitcoin_balance
fetch_bitcoin_balance
ethereum
T afetch_eth_balance
fetch_eth_balance
litecoin
T afetch_litecoin_balance
fetch_litecoin_balance
tron
T afetch_tron_balance
fetch_tron_balance
polygon_eth
T afetch_polygon_balance
fetch_polygon_balance
bnb_bsc
T afetch_bnb_balance
fetch_bnb_balance
xrp
T afetch_xrp_balance
fetch_xrp_balance
currency_converter
T aconvert_crypto_to_usd
convert_crypto_to_usd
L afetch_bitcoin_balance
fetch_eth_balance
fetch_litecoin_balance
fetch_tron_balance
fetch_polygon_balance
fetch_bnb_balance
fetch_xrp_balance
convert_crypto_to_usd
a__all__
umodules\balance\__init__.py
u<module modules.balance>

a__spec__
.modules.balance.currency_converter
ids
w,avs_currencies
usd
requests
get
T uhttps://api.coingecko.com/api/v3/simple/price
T aparams
status_code
l  ajson
get_crypto_prices
aFAILED
round
l a__doc__
a__file__
origin
has_location
a__cached__
convert_crypto_to_usd
umodules\balance\currency_converter.py
u<module modules.balance.currency_converter>
T acrypto_amount
crypto_id
prices
price_in_usd
T acrypto_ids
url
params
response

a__spec__
.modules.balance.ethereum
b
%
g           aget_random_token
aETHERSCAN_TOKENS
uhttps://api.etherscan.io/api?module=account&action=balance&address=

u&tag=latest&apikey=
wcasession
get
status_code
l  ajson
T astatus
w1T aresult
l
convert_to_eth
fetch_from_etherscan
etherscan
T nna__doc__
a__file__
origin
has_location
a__cached__
sys
apis
T aget_random_token
aETHERSCAN_TOKENS
proxyconnector
T aStealthConnection
aStealthConnection
fetch_eth_balance
umodules\balance\ethereum.py
u<module modules.balance.ethereum>
T awei_amount
T aaddress
balance_eth
weT aaddress
token
url
response
response_json
balance_wei
a__spec__
.modules.balance.litecoin
?
l   /wcasession
uhttps://api.blockchair.com/litecoin/dashboards/address/

get
json
T adata
data
address
T abalance
convert_to_ltc
uhttp://chainz.cryptoid.info/ltc/api.dws?q=getbalance&a=
text
get_random_token
aBLOCKCYPHER_TOKENS
uhttps://api.blockcypher.com/v1/ltc/main/addrs/
u/balance?token=
T abalance
naNOWNODES_TOKENS
uapi-key
uhttps://ltcbook.nownodes.io/api/v2/address/
status_code
l  abalance
uhttps://rest.cryptoapis.io/v2/blockchain-data/mainnet/litecoin/addresses/
u/balance
uContent-Type
uapplication/json
uX-API-Key
aCRYPTOAPIS_TOKENS
item

Fetches the balance of a given address from CryptoAPIs.
fetch_from_blockcypher
fetch_from_cryptoapis
fetch_from_nownodes
fetch_from_blockchair
fetch_from_cryptoid
random
shuffle
a__name__
T nna__doc__
a__file__
origin
has_location
a__cached__
apis
T aget_random_token
aCRYPTOAPIS_TOKENS
aBLOCKCYPHER_TOKENS
aNOWNODES_TOKENS
proxyconnector
T aStealthConnection
aStealthConnection
fetch_litecoin_balance
umodules\balance\litecoin.py
u<module modules.balance.litecoin>
T asatoshis_amount
T aaddress
session
url
response
jsonresp
balance_satoshis
T aaddress
session
token
url
response
jsonresp
balance_satoshis
T aaddress
url
headers
session
response
balance_data
balance
weT aaddress
session
url
response
balance_ltc
T aaddress
api_key
headers
session
url
response
data
balance
T aaddress
aPAIDAPIS_fetch_functions
aFREEAPIS_fetch_functions
fetch_functions
fetch_function
balance_ltc
wea__spec__
.modules.balance.polygon_eth
web3
to_checksum_address
eth
get_balance
from_wei
ether
print
uAn error occurred:

fetch_from_polygon_rpc
aPolygonRPC
T nnuEntry function
a__doc__
a__file__
origin
has_location
a__cached__
T aWeb3
aWeb3
uhttps://polygon-rpc.com/
polygon_rpc
aHTTPProvider
is_connected
fetch_polygon_balance
umodules\balance\polygon_eth.py
u<module modules.balance.polygon_eth>
T aaddress
checksum_address
balance_wei
balance_matic
weT aaddress
balance_matic
wea__spec__
.modules.balance.proxyconnector
6
ur+
readlines
strip
a_use_proxy
loadProxies
random
choice
http
uhttp://

https
proxies
available_browser_spoof
tls_client
aSession
client_identifier
T aclient_identifier
random_tls_extension_order
a_applyProxy
uUser-Agent
user_agent
headers
update
a__doc__
a__file__
origin
has_location
a__cached__
T aconfig
l aconfig
proxyfile
D aproxyfile
return
Ostr
HT AOlist
T Ostr
M
L D aname
client_identifier
user_agent
uiPhone | iOS 18
safari_ios_18_0
uMozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1
D aname
client_identifier
user_agent
uiPhone | iOS 17
safari_ios_17_0
uMozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1
D aname
client_identifier
user_agent
uChrome | Windows NT
chrome_129
uMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
D aname
client_identifier
user_agent
uChrome | Linux
chrome_134
uMozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
D aname
client_identifier
user_agent
uChrome | Windows NT
chrome_128
uMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
D aname
client_identifier
user_agent
uChrome | Linux
chrome_133
uMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
