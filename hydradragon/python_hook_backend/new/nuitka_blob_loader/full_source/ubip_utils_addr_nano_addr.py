# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.nano_addr

uClass container for Nano address constants.
a__qualname__
a__annotations__
u13456789abcdefghijkmnopqrstuwxyz
b
u1111
uNano address utility class.
D apub_key_bytes
return
Obytes
pu_NanoAddrUtils.ComputeChecksum
a__prepare__
aNanoAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Nano address decoder class.
It allows the Nano address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uNanoAddrDecoder.DecodeAddr
a__orig_bases__
aNanoAddrEncoder

Nano address encoder class.
It allows the Nano address encoding.
pub_key
aEncodeKey
uNanoAddrEncoder.EncodeKey
aNanoAddr
ubip_utils\addr\nano_addr.py
u<module bip_utils.addr.nano_addr>
T apub_key_bytes
T aaddr
kwargs
addr_no_prefix
addr_dec_bytes
pub_key_bytes
checksum_bytes
T apub_key
kwargs
pub_key_obj
pub_key_bytes
checksum_bytes
payload_bytes
b32_enc
T a__class__

a__spec__
.bip_utils.addr.near_addr
E
aBytesUtils
aFromHexString
aAddrDecUtils
aValidateLength
aEd25519PublicKey
aCompressedLength
aValidatePubKey

Decode a Near Protocol address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetEd25519Key
aRawCompressed
aToHex
:l nnu
Encode a public key to Near Protocol address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519
uModule for Near Protocol address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.addr_dec_utils
T aAddrDecUtils
ubip_utils.addr.addr_key_validator
T aAddrKeyValidator
ubip_utils.addr.iaddr_decoder
T aIAddrDecoder
aIAddrDecoder
ubip_utils.addr.iaddr_encoder
T aIAddrEncoder
aIAddrEncoder
ubip_utils.ecc
T aEd25519PublicKey
aIPublicKey
aIPublicKey
ubip_utils.utils.misc
T aBytesUtils
a__prepare__
aNearAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
