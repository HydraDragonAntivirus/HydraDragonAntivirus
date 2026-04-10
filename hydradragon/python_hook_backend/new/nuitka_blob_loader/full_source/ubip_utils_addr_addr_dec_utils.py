# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.addr_dec_utils

uClass container for address decoding utility functions.
aAddrDecUtils
a__qualname__
addr
prefix
return
aValidateAndRemovePrefix
uAddrDecUtils.ValidateAndRemovePrefix
T Obytes
Ostr
len_exp
aValidateLength
uAddrDecUtils.ValidateLength
pub_key_bytes
pub_key_cls
aValidatePubKey
uAddrDecUtils.ValidatePubKey
payload_bytes
checksum_bytes_exp
checksum_fct
T L Obytes
Obytes
aValidateChecksum
uAddrDecUtils.ValidateChecksum
addr_bytes
checksum_len
T Obytes
paSplitPartsByChecksum
uAddrDecUtils.SplitPartsByChecksum
ubip_utils\addr\addr_dec_utils.py
u<module bip_utils.addr.addr_dec_utils>
T a__class__
T aaddr_bytes
checksum_len
checksum_bytes
payload_bytes
T aaddr
prefix
prefix_got
T apayload_bytes
checksum_bytes_exp
checksum_fct
checksum_bytes_got
T aaddr
len_exp
T apub_key_bytes
pub_key_cls
a__spec__
.bip_utils.addr.addr_key_validator
>
aAddrKeyValidator
a_AddrKeyValidator__ValidateAndGetGenericKey
aEd25519PublicKey

Validate and get a ed25519 public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not ed25519
ValueError: If the public key is not valid
aEd25519Blake2bPublicKey

Validate and get a ed25519-blake2b public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not ed25519-blake2b
ValueError: If the public key is not valid
aEd25519MoneroPublicKey

Validate and get a ed25519-monero public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not ed25519-monero
ValueError: If the public key is not valid
aNist256p1PublicKey

Validate and get a nist256p1 public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not nist256p1
ValueError: If the public key is not valid
aSecp256k1PublicKey

Validate and get a secp256k1 public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not secp256k1
ValueError: If the public key is not valid
aSr25519PublicKey

Validate and get a sr25519 public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not sr25519
ValueError: If the public key is not valid
aFromBytes
aEllipticCurveGetter
aFromType
aCurveType
uA
aName

u public key is required(expected:
u, got:

Validate and get a generic public key.
Args:
pub_key (bytes or IPublicKey object): Public key bytes or object
pub_key_cls (IPublicKey)            : Public key class type
Returns:
IPublicKey object: IPublicKey object
Raises:
TypeError: If the public key is not of the correct class type
ValueError: If the public key is not valid
uModule with utility functions for validating address public keys.
a__doc__
a__file__
origin
has_location
a__cached__
aType
aUnion
ubip_utils.ecc
T aEd25519Blake2bPublicKey
aEd25519MoneroPublicKey
aEd25519PublicKey
aEllipticCurveGetter
aIPublicKey
aNist256p1PublicKey
aSecp256k1PublicKey
aSr25519PublicKey
aIPublicKey
