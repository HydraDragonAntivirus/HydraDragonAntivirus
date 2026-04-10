# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.solana.spl_token

uClass container for SPL token constants.
a__qualname__
a__annotations__
aATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
aTokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
cProgramDerivedAddress
l  l u
SPL token class.
It provides methods for getting the account address associated to a SPL token.
aSplToken
D awallet_addr
token_mint_addr
return
Ostr
ppaGetAssociatedTokenAddress
uSplToken.GetAssociatedTokenAddress
D awallet_addr
token_mint_addr
token_program_id
return
Ostr
pppuSplToken.GetAssociatedTokenAddressWithProgramId
seeds
program_id
return
uSplToken.FindPda
seeds_with_bump
a__CreatePda
uSplToken.__CreatePda
ubip_utils\solana\spl_token.py
u<module bip_utils.solana.spl_token>
T acls
seeds
program_id
seed
program_id_bytes
bump_seed
w_aseeds_with_bump
T acls
wallet_addr
token_mint_addr
T acls
wallet_addr
token_mint_addr
token_program_id
seeds
T a__class__
T aseeds_with_bump
program_id_bytes
sha256
seed
elem
pda_bytes
a__spec__
.bip_utils.ss58
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ss58
T aNUITKA_PACKAGE_bip_utils_ss58
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.ss58.ss58
T aSS58Decoder
aSS58Encoder
aSS58Decoder
aSS58Encoder
ubip_utils.ss58.ss58_ex
T aSS58ChecksumError
aSS58ChecksumError
ubip_utils\ss58\__init__.py
u<module bip_utils.ss58>

a__spec__
.bip_utils.ss58.ss58
Q
aBlake2b512
aQuickDigest
aSS58Const
aCHECKSUM_PREFIX
aCHECKSUM_BYTE_LEN

Compute SS58 checksum.
Args:
data_bytes (bytes): Data bytes
Returns:
bytes: Computed checksum
aDATA_BYTE_LEN
uInvalid data length (

w)aFORMAT_MAX_VAL
uInvalid SS58 format (
aRESERVED_FORMATS
aSIMPLE_ACCOUNT_FORMAT_MAX_VAL
aIntegerUtils
aToBytes
l  l l@l l l a_SS58Utils
aComputeChecksum
aBase58Encoder
aEncode

Encode bytes into a SS58 string.
Args:
data_bytes (bytes): Data bytes (32-byte length)
ss58_format (int) : SS58 format
Returns:
str: SS58 encoded string
Raises:
ValueError: If parameters are not valid
aBase58Decoder
aDecode
l?aSS58ChecksumError
uInvalid checksum (expected
aBytesUtils
aToHexString
u, got

Decode bytes from a SS58 string.
Args:
data_str (string): Data string
Returns:
tuple[int, bytes]: SS58 format and data bytes
Raises:
SS58ChecksumError: If checksum is not valid
ValueError: If the string is not a valid SS58 format

Module for SS58 decoding/encoding.
Reference: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ubip_utils.base58
T aBase58Decoder
aBase58Encoder
ubip_utils.ss58.ss58_ex
T aSS58ChecksumError
ubip_utils.utils.crypto
T aBlake2b512
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
