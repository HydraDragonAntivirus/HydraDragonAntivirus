# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.avax_addr

uAvax address utility class.
a__qualname__
D aaddr
prefix
hrp
return
Ostr
ppObytes
u_AvaxAddrUtils.DecodeAddr
a__prepare__
aAvaxPChainAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Avax P-Chain address decoder class.
It allows the Avax P-Chain address decoding.
staticmethod
addr
str
kwargs
return
bytes
uAvaxPChainAddrDecoder.DecodeAddr
a__orig_bases__
aAvaxPChainAddrEncoder

Avax P-Chain address encoder class.
It allows the Avax P-Chain address encoding.
pub_key
uAvaxPChainAddrEncoder.EncodeKey
aAvaxXChainAddrDecoder

Avax X-Chain address decoder class.
It allows the Avax X-Chain address decoding.
uAvaxXChainAddrDecoder.DecodeAddr
aAvaxXChainAddrEncoder

Avax X-Chain address encoder class.
It allows the Avax X-Chain address encoding.
uAvaxXChainAddrEncoder.EncodeKey
aAvaxPChainAddr
aAvaxXChainAddr
ubip_utils\addr\avax_addr.py
u<module bip_utils.addr.avax_addr>
T a__class__
T aaddr
kwargs
T aaddr
prefix
hrp
addr_no_prefix
T apub_key
kwargs
prefix

a__spec__
.bip_utils.addr.bch_addr_converter
"
aBchBech32Decoder
aDecode
find
T w:aBchBech32Encoder
aEncode

Convert a Bitcoin Cash address by changing its HRP and net version.
Args:
ddress (str)            : Bitcoin Cash address
hrp (str)                : New HRP
net_ver (bytes, optional): New net version (if None, the old one will be used)
Returns:
str: Converted address string
Raises:
Bech32ChecksumError: If the address checksum is not valid
ValueError: If the address string is not valid
uModule for converting Bitcoin Cash addresses.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
ubip_utils.bech32
T aBchBech32Decoder
aBchBech32Encoder
