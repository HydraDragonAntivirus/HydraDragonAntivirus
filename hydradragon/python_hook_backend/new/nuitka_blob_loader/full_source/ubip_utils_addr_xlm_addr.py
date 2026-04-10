# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.xlm_addr

uEnumerative for Stellar address types.
a__qualname__
l0l  aPRIV_KEY
a__orig_bases__
uClass container for Stellar address constants.
a__annotations__
l uStellar address utility class.
D apayload_bytes
return
Obytes
pu_XlmAddrUtils.ComputeChecksum
aXlmAddrDecoder

Stellar address decoder class.
It allows the Stellar address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uXlmAddrDecoder.DecodeAddr
aXlmAddrEncoder

Stellar address encoder class.
It allows the Stellar address encoding.
pub_key
aEncodeKey
uXlmAddrEncoder.EncodeKey
aXlmAddr
ubip_utils\addr\xlm_addr.py
u<module bip_utils.addr.xlm_addr>
T apayload_bytes
T aaddr
kwargs
addr_type
addr_dec_bytes
payload_bytes
checksum_bytes
addr_type_got
pub_key_bytes
T apub_key
kwargs
addr_type
pub_key_obj
payload_bytes
checksum_bytes
T a__class__
a__spec__
.bip_utils.addr.xmr_addr
aKekkak256
aQuickDigest
aXmrAddrConst
aCHECKSUM_BYTE_LEN

Compute checksum in EOS format.
Args:
payload_bytes (bytes): Payload bytes
Returns:
bytes: Computed checksum
aBase58XmrDecoder
aDecode
aAddrDecUtils
aSplitPartsByChecksum
aValidateChecksum
a_XmrAddrUtils
aComputeChecksum
aValidateAndRemovePrefix
aValidateLength
aEd25519MoneroPublicKey
aCompressedLength
l aPAYMENT_ID_BYTE_LEN
uInvalid payment ID
uInvalid payment ID (expected
aBytesUtils
aToHexString

u, got
w)aValidatePubKey

Decode a Monero address to bytes.
Args:
ddr (str)                       : Address string
net_ver_bytes (bytes)            : Net version
payment_id_bytes (bytes, optional): Payment ID (only for integrated addresses)
Returns:
bytes: Public spend (first) and view (second) keys joined together
Raises:
ValueError: If the address encoding is not valid
uInvalid payment ID length
c
aAddrKeyValidator
aValidateAndGetEd25519MoneroKey
aRawCompressed
aToBytes
aBase58XmrEncoder
aEncode

Encode a public key to Monero address.
Args:
pub_skey (bytes or IPublicKey)    : Public spend key bytes or object
pub_vkey (bytes or IPublicKey)    : Public view key bytes or object
net_ver_bytes (bytes)             : Net version
payment_id_bytes (bytes, optional): Payment ID (only for integrated addresses)
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519-monero
net_ver
aDecodeAddr

Decode a Monero address to bytes.
Args:
ddr (str): Address string
Other Parameters:
net_ver (bytes): Expected net version
Returns:
bytes: Public spend (first) and view (second) keys joined together
Raises:
ValueError: If the address encoding is not valid
pub_vkey
aEncodeKey

Encode a public key to Monero format.
Args:
pub_key (bytes or IPublicKey): Public spend key bytes or object
Other Parameters:
pub_vkey (bytes or IPublicKey): Public view key bytes or object
net_ver (bytes)               : Net version
payment_id (bytes, optional)  : Payment ID (only for integrated addresses)
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519-monero
payment_id

Decode a Monero address to bytes.
Args:
ddr (str): Address string
Other Parameters:
net_ver (bytes)   : Expected net version
payment_id (bytes): Expected payment ID
Returns:
bytes: Public spend (first) and view (second) keys joined together
Raises:
ValueError: If the address encoding is not valid

Encode a public key to Monero integrated address.
Args:
pub_key (bytes or IPublicKey): Public spend key bytes or object
Other Parameters:
pub_vkey (bytes or IPublicKey): Public view key bytes or object
net_ver (bytes)               : Net version
payment_id (bytes)            : Payment ID
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519-monero
uModule for Monero address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aOptional
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
ubip_utils.base58
T aBase58XmrDecoder
aBase58XmrEncoder
ubip_utils.ecc
T aEd25519MoneroPublicKey
aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aKekkak256
ubip_utils.utils.misc
T aBytesUtils
