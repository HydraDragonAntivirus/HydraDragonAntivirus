# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.atom_addr


Atom address decoder class.
It allows the Atom address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uAtomAddrDecoder.DecodeAddr
a__orig_bases__
aAtomAddrEncoder

Atom address encoder class.
It allows the Atom address encoding.
pub_key
aEncodeKey
uAtomAddrEncoder.EncodeKey
aAtomAddr
ubip_utils\addr\atom_addr.py
u<module bip_utils.addr.atom_addr>
T a__class__
T aaddr
kwargs
hrp
addr_dec_bytes
ex
T apub_key
kwargs
hrp
pub_key_obj

a__spec__
.bip_utils.addr.avax_addr
C
S
aAddrDecUtils
aValidateAndRemovePrefix
aAtomAddrDecoder
aDecodeAddr
T ahrp

Decode an Avax address to bytes.
Args:
ddr (str)  : Address string
prefix (str): Address prefix
hrp (str)   : Address HRP
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
a_AvaxAddrUtils
aCoinsConf
aAvaxPChain
aParamByKey
T aaddr_prefix
T aaddr_hrp

Decode an Avax P-Chain address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAtomAddrEncoder
aEncodeKey

Encode a public key to Avax P-Chain address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
aAvaxXChain

Decode an Avax X-Chain address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid

Encode a public key to Avax X-Chain address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Avax address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.addr_dec_utils
T aAddrDecUtils
ubip_utils.addr.atom_addr
T aAtomAddrDecoder
aAtomAddrEncoder
ubip_utils.addr.iaddr_decoder
T aIAddrDecoder
aIAddrDecoder
ubip_utils.addr.iaddr_encoder
T aIAddrEncoder
aIAddrEncoder
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
