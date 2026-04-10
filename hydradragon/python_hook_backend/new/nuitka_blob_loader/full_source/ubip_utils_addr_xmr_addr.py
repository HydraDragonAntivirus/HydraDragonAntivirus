# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.xmr_addr

uClass container for Monero address constants.
a__qualname__
a__annotations__
l l uClass container for Monero address utility functions.
D apayload_bytes
return
Obytes
pu_XmrAddrUtils.ComputeChecksum
T naaddr
net_ver_bytes
payment_id_bytes
return
u_XmrAddrUtils.DecodeAddr
pub_skey
u_XmrAddrUtils.EncodeKey
a__prepare__
aXmrAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Monero address decoder class.
It allows the Monero address decoding.
staticmethod
str
kwargs
bytes
uXmrAddrDecoder.DecodeAddr
a__orig_bases__
aXmrAddrEncoder

Monero address encoder class.
It allows the Monero address encoding.
pub_key
uXmrAddrEncoder.EncodeKey
aXmrIntegratedAddrDecoder

Monero integrated address decoder class.
It allows the Monero integrated address decoding.
uXmrIntegratedAddrDecoder.DecodeAddr
aXmrIntegratedAddrEncoder

Monero integrated address encoder class.
It allows the Monero integrated address encoding.
uXmrIntegratedAddrEncoder.EncodeKey
aXmrAddr
aXmrIntegratedAddr
ubip_utils\addr\xmr_addr.py
u<module bip_utils.addr.xmr_addr>
T apayload_bytes
T aaddr
kwargs
net_ver
T aaddr
kwargs
net_ver
payment_id
T
addr
net_ver_bytes
payment_id_bytes
addr_dec_bytes
payload_bytes
checksum_bytes
ex
payment_id_got_bytes
pub_spend_key_bytes
pub_view_key_bytes
T apub_key
kwargs
pub_vkey
net_ver
T apub_key
kwargs
pub_vkey
net_ver
payment_id
T apub_skey
pub_vkey
net_ver_bytes
payment_id_bytes
pub_spend_key_obj
pub_view_key_obj
payload_bytes
T a__class__
a__spec__
.bip_utils.addr.xrp_addr
B
aP2PKHAddrDecoder
aDecodeAddr
aCoinsConf
aRipple
aParamByKey
T ap2pkh_net_ver
aBase58Alphabets
aRIPPLE
T anet_ver
base58_alph

Decode a Ripple address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aP2PKHAddrEncoder
aEncodeKey

Encode a public key to Ripple address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Ripple address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.iaddr_decoder
T aIAddrDecoder
aIAddrDecoder
ubip_utils.addr.iaddr_encoder
T aIAddrEncoder
aIAddrEncoder
ubip_utils.addr.P2PKH_addr
T aP2PKHAddrDecoder
aP2PKHAddrEncoder
ubip_utils.base58
T aBase58Alphabets
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
a__prepare__
aXrpAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
