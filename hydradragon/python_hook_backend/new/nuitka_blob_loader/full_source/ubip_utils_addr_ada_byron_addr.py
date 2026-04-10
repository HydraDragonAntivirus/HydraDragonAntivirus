# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.ada_byron_addr

uEnumerative for Cardano Byron address types.
a__qualname__
aREDEMPTION
a__orig_bases__
uClass container for Cardano Byron address constants.
a__annotations__
bytes
cserokellfore
l aint
uCardano Byron address HD path class.
D ahd_path_enc_bytes
hd_path_key_bytes
return
bytes
paBip32Path
u_AdaByronAddrHdPath.Decrypt
D ahd_path
hd_path_key_bytes
return
aBip32Path
bytes
pu_AdaByronAddrHdPath.Encrypt
uUtility class for Cardano Byron address attributes.
uOptional[bytes]
uOptional[int]
classmethod
D aattrs_dict
return
uDict[int, bytes]
a_AdaByronAddrAttrs
u_AdaByronAddrAttrs.FromDict
D areturn
uDict[int, bytes]
u_AdaByronAddrAttrs.ToDict
uUtility class for Cardano Byron address spending data.
key_bytes
uUtility class for Cardano Byron address root.
D areturn
bytes
u_AdaByronAddrRoot.Hash
u_AdaByronAddrRoot.Serialize
uUtility class for Cardano Byron address payload.
D aser_payload_bytes
return
bytes
a_AdaByronAddrPayload
u_AdaByronAddrPayload.Deserialize
u_AdaByronAddrPayload.Serialize
uUtility class for Cardano Byron address.
D aaddr
return
str
a_AdaByronAddr
u_AdaByronAddr.Decode
D areturn
str
u_AdaByronAddr.Encode
D aser_addr_bytes
return
bytes
a_AdaByronAddr
u_AdaByronAddr.Deserialize
u_AdaByronAddr.Serialize
uCardano Byron address utility class.
T nD apub_key_bytes
chain_code_bytes
addr_type
hd_path_enc_bytes
return
bytes
paAdaByronAddrTypes
uOptional[bytes]
str
u_AdaByronAddrUtils.EncodeKey
aAdaByronAddrDecoder

Cardano Byron address decoder class.
It allows the Cardano Byron address decoding.
staticmethod
aDecryptHdPath
uAdaByronAddrDecoder.DecryptHdPath
D adec_bytes
return
bytes
uTuple[bytes, bytes]
aSplitDecodedBytes
uAdaByronAddrDecoder.SplitDecodedBytes
D aaddr
kwargs
return
str
aAny
bytes
aDecodeAddr
uAdaByronAddrDecoder.DecodeAddr
aAdaByronIcarusAddrEncoder

Cardano Byron Icarus address encoder class.
It allows the Cardano Byron Icarus address encoding (i.e. without the encrypted derivation path, format Ae2...).
D apub_key
kwargs
return
uUnion[bytes, IPublicKey]
aAny
str
uAdaByronIcarusAddrEncoder.EncodeKey
aAdaByronLegacyAddrEncoder

Cardano Byron legacy address encoder class.
It allows the Cardano Byron legacy address encoding (i.e. containing the encrypted derivation path, format Ddz...).
uAdaByronLegacyAddrEncoder.EncodeKey
aAdaByronIcarusAddr
aAdaByronLegacyAddr
ubip_utils\addr\ada_byron_addr.py
u<module bip_utils.addr.ada_byron_addr>
T a__class__
T acls
addr
T aaddr
kwargs
addr_type
dec_addr
ex
T ahd_path_enc_bytes
hd_path_key_bytes
plain_text_bytes
T ahd_path_enc_bytes
hd_path_key_bytes
T acls
ser_addr_bytes
addr_bytes
cbor_tag
crc32_got
T acls
ser_payload_bytes
addr_payload
T aself
T apub_key
kwargs
chain_code
chain_code_bytes
T apub_key
kwargs
hd_path
hd_path_key_bytes
chain_code
chain_code_bytes
T apub_key_bytes
chain_code_bytes
addr_type
hd_path_enc_bytes
addr_attrs
addr_root
addr_payload
T ahd_path
hd_path_key_bytes
cipher_text_bytes
tag_bytes
T acls
attrs_dict
T aself
ser_payload
T adec_bytes
T aself
attrs
a__spec__
.bip_utils.addr.ada_shelley_addr
aBlake2b224
aQuickDigest

Compute the key hash.
Args:
pub_key_bytes (bytes): Public key bytes
Returns:
bytes: Key hash bytes
aIntegerUtils
aToBytes
l u
Encode address prefix.
Args:
hdr_type (AdaShelleyAddrHeaderTypes): Header type
net_tag (AdaShelleyAddrNetworkTags) : Network tag
Returns:
bytes: Prefix byte
net_tag
aAdaShelleyAddrNetworkTags
aMAINNET
uAddress type is not an enumerative of AdaShelleyAddrNetworkTags
aBech32Decoder
aDecode
aAdaShelleyAddrConst
aNETWORK_TAG_TO_ADDR_HRP
aBech32ChecksumError
uInvalid bech32 checksum
aAddrDecUtils
aValidateLength
aDigestSize
l a_AdaShelleyAddrUtils
aEncodePrefix
aAdaShelleyAddrHeaderTypes
aPAYMENT
aValidateAndRemovePrefix

Decode a Cardano Shelley address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Other Parameters:
net_tag (AdaShelleyAddrNetworkTags): Expected network tag (default: main net)
Returns:
bytes: Public keys hash bytes (public key + public staking key)
Raises:
ValueError: If the address encoding is not valid
TypeError: If the network tag is not a AdaShelleyAddrNetworkTags enum
pub_skey
aAddrKeyValidator
aValidateAndGetEd25519Key
aKeyHash
aRawCompressed
:l nnaBech32Encoder
aEncode

Encode a public key to Cardano Shelley address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
pub_skey (bytes or IPublicKey)     : Public staking key bytes or object
net_tag (AdaShelleyAddrNetworkTags): Network tag (default: main net)
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519 or the network tag is not a AdaShelleyAddrNetworkTags enum
aNETWORK_TAG_TO_REWARD_ADDR_HRP
aREWARD

Decode a Cardano Shelley address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Other Parameters:
net_tag (AdaShelleyAddrNetworkTags): Network tag (default: main net)
Returns:
bytes: Public keys hash bytes (public key + public staking key)
Raises:
ValueError: If the address encoding is not valid
TypeError: If the network tag is not a AdaShelleyAddrNetworkTags enum

Encode a public key to Cardano Shelley staking address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
net_tag (AdaShelleyAddrNetworkTags): Network tag (default: main net)
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519 or the network tag is not a AdaShelleyAddrNetworkTags enum

Module for Cardano Shelley address encoding/decoding.
Reference: https://cips.cardano.org/cips/cip19
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aIntEnum
unique
aIntEnum
unique
aAny
aDict
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
ubip_utils.bech32
T aBech32ChecksumError
aBech32Decoder
aBech32Encoder
ubip_utils.coin_conf
T aCoinsConf
aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aBlake2b224
ubip_utils.utils.misc
T aIntegerUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
