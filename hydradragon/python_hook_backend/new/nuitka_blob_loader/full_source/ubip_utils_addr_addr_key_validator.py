# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.addr_key_validator

uClass container for address utility functions.
a__qualname__
pub_key
return
aValidateAndGetEd25519Key
uAddrKeyValidator.ValidateAndGetEd25519Key
aValidateAndGetEd25519Blake2bKey
uAddrKeyValidator.ValidateAndGetEd25519Blake2bKey
aValidateAndGetEd25519MoneroKey
uAddrKeyValidator.ValidateAndGetEd25519MoneroKey
aValidateAndGetNist256p1Key
uAddrKeyValidator.ValidateAndGetNist256p1Key
aValidateAndGetSecp256k1Key
uAddrKeyValidator.ValidateAndGetSecp256k1Key
aValidateAndGetSr25519Key
uAddrKeyValidator.ValidateAndGetSr25519Key
pub_key_cls
a__ValidateAndGetGenericKey
uAddrKeyValidator.__ValidateAndGetGenericKey
ubip_utils\addr\addr_key_validator.py
u<module bip_utils.addr.addr_key_validator>
T a__class__
T apub_key
T apub_key
pub_key_cls
curve
a__spec__
.bip_utils.addr.algo_addr
Y
aSha512_256
aQuickDigest
aAlgoAddrConst
aCHECKSUM_BYTE_LEN

Compute checksum in Algorand format.
Args:
pub_key_bytes (bytes): Public key bytes
Returns:
bytes: Computed checksum
aBase32Decoder
aDecode
aAddrDecUtils
aValidateLength
aEd25519PublicKey
aCompressedLength
aSplitPartsByChecksum
aValidateChecksum
a_AlgoAddrUtils
aComputeChecksum
aValidatePubKey

Decode an Algorand address to bytes.
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
aToBytes
:l nnaBase32Encoder
aEncodeNoPadding

Encode a public key to Algorand address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519
uModule for Algorand address encoding/decoding.
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
ubip_utils.utils.crypto
T aSha512_256
ubip_utils.utils.misc
T aBase32Decoder
aBase32Encoder
