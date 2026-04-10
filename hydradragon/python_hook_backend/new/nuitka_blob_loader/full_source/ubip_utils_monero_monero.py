# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.monero


Monero class.
It allows to compute Monero keys and addresses/subaddresses.
aMonero
a__qualname__
a__annotations__
uOptional[MoneroPrivateKey]
aMONERO_MAINNET
D aseed_bytes
coin_type
return
bytes
aMoneroCoins
aMonero
aFromSeed
uMonero.FromSeed
D apriv_key
coin_type
return
uUnion[bytes, IPrivateKey]
aMoneroCoins
aMonero
aFromBip44PrivateKey
uMonero.FromBip44PrivateKey
D apriv_skey
coin_type
return
uUnion[bytes, IPrivateKey]
aMoneroCoins
aMonero
uMonero.FromPrivateSpendKey
D apriv_vkey
pub_skey
coin_type
return
uUnion[bytes, IPrivateKey]
uUnion[bytes, IPublicKey]
aMoneroCoins
aMonero
aFromWatchOnly
uMonero.FromWatchOnly
D apriv_key
pub_key
coin_type
return
uUnion[bytes, IPrivateKey]
uOptional[Union[bytes, IPublicKey]]
aMoneroCoins
aNone
a__init__
uMonero.__init__
D areturn
bool
uMonero.IsWatchOnly
D areturn
aMoneroCoinConf
aCoinConf
uMonero.CoinConf
D areturn
aMoneroPrivateKey
aPrivateSpendKey
uMonero.PrivateSpendKey
aPrivateViewKey
uMonero.PrivateViewKey
D areturn
aMoneroPublicKey
aPublicSpendKey
uMonero.PublicSpendKey
aPublicViewKey
uMonero.PublicViewKey
D apayment_id
return
bytes
str
aIntegratedAddress
uMonero.IntegratedAddress
D areturn
str
uMonero.PrimaryAddress
T l
D aminor_idx
major_idx
return
int
pastr
aSubaddress
uMonero.Subaddress
D apriv_skey
return
aMoneroPrivateKey
pa__ViewFromSpendKey
uMonero.__ViewFromSpendKey
ubip_utils\monero\monero.py
u<module bip_utils.monero.monero>
T aself
T acls
priv_key
coin_type
T acls
priv_skey
coin_type
T acls
seed_bytes
coin_type
priv_skey_bytes
T acls
priv_vkey
pub_skey
coin_type
T aself
payment_id
T a__class__
T aself
minor_idx
major_idx
T apriv_skey
priv_vkey_bytes
T aself
priv_key
pub_key
coin_type

a__spec__
.bip_utils.monero.monero_ex
uModule for Monero exceptions.
a__doc__
a__file__
origin
has_location
a__cached__
T EException
a__prepare__
aMoneroKeyError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
