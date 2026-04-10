# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.P2PKH_addr

uEnumerative for P2PKH public key modes.
a__qualname__
aUNCOMPRESSED
a__orig_bases__
aP2PKHAddrDecoder

P2PKH address decoder class.
It allows the Pay-to-Public-Key-Hash address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uP2PKHAddrDecoder.DecodeAddr
aP2PKHAddrEncoder

P2PKH address encoder class.
It allows the Pay-to-Public-Key-Hash address encoding.
pub_key
aEncodeKey
uP2PKHAddrEncoder.EncodeKey
aBchP2PKHAddrDecoder

Bitcoin Cash P2PKH address decoder class.
It allows the Bitcoin Cash P2PKH decoding.
uBchP2PKHAddrDecoder.DecodeAddr
aBchP2PKHAddrEncoder

Bitcoin Cash P2PKH address encoder class.
It allows the Bitcoin Cash P2PKH encoding.
uBchP2PKHAddrEncoder.EncodeKey
aP2PKHAddr
aBchP2PKHAddr
ubip_utils\addr\P2PKH_addr.py
u<module bip_utils.addr.P2PKH_addr>
T a__class__
T aaddr
kwargs
hrp
net_ver_bytes
net_ver_bytes_got
addr_dec_bytes
ex
T aaddr
kwargs
net_ver_bytes
base58_alph
addr_dec_bytes
ex
T apub_key
kwargs
hrp
net_ver_bytes
pub_key_obj
T apub_key
kwargs
net_ver_bytes
base58_alph
pub_key_mode
pub_key_obj
pub_key_bytes
a__spec__
.bip_utils.addr.P2SH_addr
b
aHash160
aQuickDigest
aRawCompressed
aToBytes
aP2SHAddrConst
aSCRIPT_BYTES

Add script signature to public key and get address bytes.
Args:
pub_key (IPublicKey object): Public key object
Returns:
bytes: Address bytes
aP2PKHAddrDecoder
aDecodeAddr
net_ver
T anet_ver

Decode a P2SH address to bytes.
Args:
ddr (str): Address string
Other Parameters:
net_ver (bytes): Expected net address version
Returns:
bytes: Script signature hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aBase58Encoder
aCheckEncode
a_P2SHAddrUtils
aAddScriptSig

Encode a public key to P2SH address.
Args:
pub_key (bytes or IPublicKey) : Public key bytes or object
Other Parameters:
net_ver (bytes): Net address version
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
aBchP2PKHAddrDecoder
hrp
T ahrp
net_ver

Decode a Bitcoin Cash P2SH address to bytes.
Args:
ddr (str): Address string
Other Parameters:
hrp (str)      : Expected HRP
net_ver (bytes): Expected net address version
Returns:
bytes: Script signature hash bytes
Raises:
ValueError: If the address encoding is not valid
aBchBech32Encoder
aEncode

Encode a public key to Bitcoin Cash P2SH address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
hrp (str)      : HRP
net_ver (bytes): Net address version
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for P2SH address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.addr_key_validator
T aAddrKeyValidator
ubip_utils.addr.iaddr_decoder
T aIAddrDecoder
aIAddrDecoder
ubip_utils.addr.iaddr_encoder
T aIAddrEncoder
aIAddrEncoder
ubip_utils.addr.P2PKH_addr
T aBchP2PKHAddrDecoder
aP2PKHAddrDecoder
ubip_utils.base58
T aBase58Encoder
ubip_utils.bech32
T aBchBech32Encoder
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aHash160
