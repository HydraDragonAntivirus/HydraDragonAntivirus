# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.sol_addr


Solana address decoder class.
It allows the Solana address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uSolAddrDecoder.DecodeAddr
a__orig_bases__
aSolAddrEncoder

Solana address encoder class.
It allows the Solana address encoding.
pub_key
aEncodeKey
uSolAddrEncoder.EncodeKey
aSolAddr
ubip_utils\addr\sol_addr.py
u<module bip_utils.addr.sol_addr>
T aaddr
kwargs
addr_dec_bytes
T apub_key
kwargs
pub_key_obj
T a__class__

a__spec__
.bip_utils.addr.substrate_addr
a
[
aSS58Decoder
aDecode
aSS58ChecksumError
uInvalid SS58 encoding
uInvalid SS58 format (expected

u, got
w)aAddrDecUtils
aValidatePubKey

Decode a Substrate address to bytes.
Args:
ddr (str)              : Address string
ss58_format (int)       : SS58 format
pub_key_cls (IPublicKey): Public key class type
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
a_SubstrateAddrUtils
aDecodeAddr
ss58_format
aEd25519PublicKey

Decode a Substrate address to bytes.
Args:
ddr (str): Address string
Other Parameters:
ss58_format (int): Expected SS58 format
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetEd25519Key
aSS58Encoder
aEncode
aRawCompressed
aToBytes
:l nnu
Encode a public key to Substrate address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
ss58_format (int): SS58 format
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
aSr25519PublicKey
aValidateAndGetSr25519Key
uModule for Substrate address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aType
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
aSr25519PublicKey
aIPublicKey
ubip_utils.ss58
T aSS58ChecksumError
aSS58Decoder
aSS58Encoder
