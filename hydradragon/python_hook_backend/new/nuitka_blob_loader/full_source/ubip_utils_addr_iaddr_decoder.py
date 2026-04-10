# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.iaddr_decoder

uAddress decoder interface.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes

Decode an address to bytes.
Depending on the coin, the result can be a public key or a public key hash bytes.
Args:
ddr (str): Address string
**kwargs  : Arbitrary arguments depending on the address type
Returns:
bytes: Public key bytes or public key hash
Raises:
ValueError: If the address encoding is not valid
aDecodeAddr
uIAddrDecoder.DecodeAddr
a__orig_bases__
ubip_utils\addr\iaddr_decoder.py
u<module bip_utils.addr.iaddr_decoder>
T aaddr
kwargs
T a__class__

a__spec__
.bip_utils.addr.iaddr_encoder
2
)
uModule with interface for address encoding classes.
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
aAny
aUnion
ubip_utils.ecc
T aIPublicKey
aIPublicKey
a__prepare__
aIAddrEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
