# Reconstructed from integrated Nuitka blob
# Module: ueth_keys.backends.native.main

a__qualname__
msg_hash
bytes
private_key
return
ecdsa_sign
uNativeECCBackend.ecdsa_sign
ecdsa_sign_non_recoverable
uNativeECCBackend.ecdsa_sign_non_recoverable
signature
public_key
bool
ecdsa_verify
uNativeECCBackend.ecdsa_verify
ecdsa_recover
uNativeECCBackend.ecdsa_recover
uNativeECCBackend.private_key_to_public_key
compressed_public_key_bytes
decompress_public_key_bytes
uNativeECCBackend.decompress_public_key_bytes
uncompressed_public_key_bytes
compress_public_key_bytes
uNativeECCBackend.compress_public_key_bytes
a__orig_bases__
ueth_keys\backends\native\main.py
u<module eth_keys.backends.native.main>
T a__class__
T aself
uncompressed_public_key_bytes
T aself
compressed_public_key_bytes
T aself
msg_hash
signature
public_key_bytes
public_key
T aself
msg_hash
private_key
signature_vrs
signature
T aself
msg_hash
private_key
w_asignature_r
signature_s
signature
T aself
msg_hash
signature
public_key
T aself
private_key
public_key_bytes
public_key

a__spec__
.eth_keys
<
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_eth_keys
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
version
a__version
main
T aKeyAPI
lazy_key_api
aKeyAPI
lazy_key_api
keys
u0.6.1
a__version__
ueth_keys\__init__.py
u<module eth_keys>

a__spec__
.eth_keys.constants
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aTuple
l l  g
l  aSECPK1_P
g	                                          aSECPK1_N
aSECPK1_A
l aSECPK1_B
g	y                                        aSECPK1_Gx
g	H                                        aSECPK1_Gy
aSECPK1_G
T Oint
pT T l
ppT l
pl aIDENTITY_POINTS
ueth_keys\constants.py
u<module eth_keys.constants>

a__spec__
.eth_keys.datatypes
ueth_keys.backends.base
T aBaseECCBackend
aBaseECCBackend
is_string
get_backend
uUnsupported format for ECC backend.  Must be an instance or subclass of `eth_keys.backends.BaseECCBackend` or a string of the dot-separated import path for the desired backend class
backend
a_backend
ueth_keys.backends
T aget_backend
u0x
codecs
decode
encode
a_raw_key
hex
ascii
big_endian_to_int
keccak
to_bytes
to_hex
is_bytes
w'u
a__int__
validate_uncompressed_public_key_bytes
a__class__
a__init__
T abackend
validate_compressed_public_key_bytes
decompress_public_key_bytes
private_key_to_public_key
recover_from_msg_hash
ecdsa_recover
verify_msg_hash
ecdsa_verify
compress_public_key_bytes
to_checksum_address
public_key_bytes_to_address
to_normalized_address
validate_private_key_bytes
public_key
sign_msg_hash
ecdsa_sign
sign_msg_hash_non_recoverable
ecdsa_sign_non_recoverable
validate_signature_r_or_s
aValidationError
aBadSignature
a_r
a_s
wrwsaencode_hex
uYou must provide one of `signature_bytes` or `vrs`
validate_recoverable_signature_bytes
:l
l n:l l@n:l@lAnuInvariant: unreachable code path
T ars
backend
wva_v
validate_signature_v
int_to_byte
pad32
int_to_big_endian
c
recover_public_key_from_msg_hash
aNonRecoverableSignature
rs
T ars
uYou must provide one of `signature_bytes` or `vr`
validate_non_recoverable_signature_bytes
u<genexpr>
uNonRecoverableSignature.to_bytes.<locals>.<genexpr>
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
collections
aTYPE_CHECKING
aAny
aTuple
aType
aUnion
eth_typing
T aChecksumAddress
aChecksumAddress
eth_utils
T	aValidationError
big_endian_to_int
encode_hex
int_to_big_endian
is_bytes
is_string
keccak
to_checksum_address
to_normalized_address
ueth_keys.exceptions
T aBadSignature
ueth_keys.utils.address
T apublic_key_bytes_to_address
ueth_keys.utils.numeric
T aint_to_byte
ueth_keys.utils.padding
T apad32
ueth_keys.validation
T avalidate_compressed_public_key_bytes
validate_non_recoverable_signature_bytes
validate_private_key_bytes
validate_recoverable_signature_bytes
validate_signature_r_or_s
validate_signature_v
validate_uncompressed_public_key_bytes
