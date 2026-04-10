# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip44_base.bip44_base_ex

uException in case of derivation from wrong depth.
a__qualname__
a__orig_bases__
ubip_utils\bip\bip44_base\bip44_base_ex.py
u<module bip_utils.bip.bip44_base.bip44_base_ex>

a__spec__
.bip_utils.bip.bip44_base.bip44_keys
g
aCurveType
aBip32Class
uThe public key elliptic curve (

u) shall match the coin configuration one (
w)am_pub_key
m_coin_conf

Construct class.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
coin_conf (BipCoinConf object) : BipCoinConf object
Raises:
ValueError: If the key elliptic curve is different from the coin configuration one

Return the BIP32 key object.
Returns:
Bip32PublicKey object: BIP32 key object
aToExtended

Return key in serialized extended format.
Returns:
str: Key in serialized extended format
aChainCode

Return the chain code.
Returns:
Bip32ChainCode object: Bip32ChainCode object
aRawCompressed

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
aRawUncompressed

Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
aAddrClass
aKeyObject
aAdaShelleyAddrEncoder
uUse the CardanoShelley class to get Cardano Shelley addresses
aXmrAddrEncoder
uUse the Monero class to get Monero addresses
aEncodeKey
aAddrParamsWithResolvedCalls

Return the address correspondent to the public key.
Returns:
str: Address string
uThe private key elliptic curve (
m_priv_key

Construct class.
Args:
priv_key (Bip32PrivateKey object): Bip32PrivateKey object
coin_conf (BipCoinConf object)   : BipCoinConf object
Raises:
ValueError: If the key elliptic curve is different from the coin configuration one
aRaw
aBip44PublicKey
aPublicKey

Get the public key correspondent to the private one.
Returns:
Bip44PublicKey object: Bip44PublicKey object
aWifNetVersion
aWifEncoder
aEncode
aToBytes

Return key in WIF format.
Args:
pub_key_mode (WifPubKeyModes): Specify if the private key corresponds to a compressed public key
Returns:
str: Key in WIF format
uModule for BIP44 keys handling.
a__doc__
a__file__
origin
has_location
a__cached__
lru_cache
ubip_utils.addr
T aAdaShelleyAddrEncoder
aXmrAddrEncoder
ubip_utils.bip.bip32
T aBip32ChainCode
aBip32PrivateKey
aBip32PublicKey
aBip32ChainCode
aBip32PrivateKey
aBip32PublicKey
ubip_utils.bip.conf.common
T aBipCoinConf
aBipCoinConf
ubip_utils.utils.misc
T aDataBytes
aDataBytes
ubip_utils.wif
T aWifEncoder
aWifPubKeyModes
aWifPubKeyModes
