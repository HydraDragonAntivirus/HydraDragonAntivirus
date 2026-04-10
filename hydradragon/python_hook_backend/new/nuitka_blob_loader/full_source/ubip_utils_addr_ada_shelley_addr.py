# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.ada_shelley_addr

uEnumerative for Cardano Shelley network tags.
a__qualname__
aTESTNET
a__orig_bases__
uEnumerative for Cardano Shelley header types.
l uClass container for Cardano Shelley address constants.
a__annotations__
aCardanoMainNet
aParamByKey
T aaddr_hrp
aCardanoTestNet
T astaking_addr_hrp
uCardano Shelley address utility class.
D apub_key_bytes
return
Obytes
pu_AdaShelleyAddrUtils.KeyHash
hdr_type
return
u_AdaShelleyAddrUtils.EncodePrefix
aAdaShelleyAddrDecoder

Cardano Shelley address decoder class.
It allows the Cardano Shelley address decoding.
staticmethod
addr
str
kwargs
bytes
aDecodeAddr
uAdaShelleyAddrDecoder.DecodeAddr
aAdaShelleyAddrEncoder

Cardano Shelley address encoder class.
It allows the Cardano Shelley address encoding.
pub_key
aEncodeKey
uAdaShelleyAddrEncoder.EncodeKey
aAdaShelleyStakingAddrDecoder

Cardano Shelley staking address decoder class.
It allows the Cardano Shelley staking address decoding.
uAdaShelleyStakingAddrDecoder.DecodeAddr
aAdaShelleyStakingAddrEncoder

Cardano Shelley staking address encoder class.
It allows the Cardano Shelley staking address encoding.
uAdaShelleyStakingAddrEncoder.EncodeKey
aAdaShelleyAddr
aAdaShelleyStakingAddr
aAdaShelleyRewardAddrDecoder
aAdaShelleyRewardAddrEncoder
aAdaShelleyRewardAddr
ubip_utils\addr\ada_shelley_addr.py
u<module bip_utils.addr.ada_shelley_addr>
T a__class__
T aaddr
kwargs
net_tag
addr_dec_bytes
ex
prefix_byte
T	apub_key
kwargs
pub_skey
net_tag
pub_key_obj
pub_skey_obj
pub_key_hash
pub_skey_hash
prefix_byte
T apub_key
kwargs
net_tag
pub_key_obj
pub_key_hash
first_byte
T ahdr_type
net_tag
T apub_key_bytes

a__spec__
.bip_utils.addr.addr_dec_utils
I
uInvalid prefix (expected

u, got
w)u
Validate and remove prefix from an address.
Args:
ddr (bytes or str)  : Address string or bytes
prefix (bytes or str): Address prefix
Returns:
bytes or str: Address string or bytes with prefix removed
Raises:
ValueError: If the prefix is not valid
uInvalid length (expected

Validate address length.
Args:
ddr (str)   : Address string or bytes
len_exp (int): Expected address length
Raises:
ValueError: If the length is not valid
aIsValidBytes
uInvalid
aCurveType
u public key
aBytesUtils
aToHexString

Validate address length.
Args:
pub_key_bytes (bytes)   : Public key bytes
pub_key_cls (IPublicKey): Public key class type
Raises:
ValueError: If the public key is not valid
uInvalid checksum (expected

Validate address checksum.
Args:
payload_bytes (bytes)     : Payload bytes
checksum_bytes_exp (bytes): Expected checksum bytes
checksum_fct (function)   : Function for computing checksum
Raises:
ValueError: If the computed checksum is not equal tot he specified one

Split address in two parts, considering the checksum at the end of it.
Args:
ddr_bytes (bytes): Address bytes
checksum_len (int): Checksum length
Returns:
tuple[bytes, bytes]: Payload bytes (index 0) and checksum bytes (index 1)
uModule with utility functions for address decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aCallable
aTuple
aType
aTypeVar
aUnion
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.misc
T aBytesUtils
T aBytesOrStr
Obytes
Ostr
aBytesOrStr
