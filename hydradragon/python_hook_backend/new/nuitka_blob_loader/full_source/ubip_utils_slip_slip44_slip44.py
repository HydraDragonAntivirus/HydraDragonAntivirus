# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.slip.slip44.slip44


SLIP-0044 class.
It defines the coin types in according to SLIP-0044.
aSlip44
a__qualname__
a__annotations__
aBITCOIN
aTESTNET
l aLITECOIN
l aDOGECOIN
l aDASH
l<aETHEREUM
l=aETHEREUM_CLASSIC
lJaICON
lMaVERGE
lvaATOM
l  aMONERO
l  aZCASH
l  aRIPPLE
l  aBITCOIN_CASH
l  aSTELLAR
l  aNANO
l  aEOS
l  aTRON
l  aBITCOIN_SV
l  aALGORAND
l  aZILLIQA
l  aTERRA
l  aPOLKADOT
l  aNEAR_PROTOCOL
l  aERGO
l  aKUSAMA
l  aKAVA
l  aFILECOIN
l  aBAND_PROTOCOL
l  aTHETA
l  aSOLANA
l  aELROND
l  aSECRET_NETWORK
l  aNINE_CHRONICLES
l  aAPTOS
l  aBINANCE_CHAIN
l  aSUI
l  aVECHAIN
l  aNEO
l  aOKEX_CHAIN
l  aHARMONY_ONE
l  aONTOLOGY
l aTEZOS
l  aCARDANO
l FaAVALANCHE
l   aCELO
l   aPI_NETWORK
ubip_utils\slip\slip44\slip44.py
u<module bip_utils.slip.slip44.slip44>
T a__class__

a__spec__
.bip_utils.solana
]
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
solana
T aNUITKA_PACKAGE_bip_utils_solana
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.solana.spl_token
T aSplToken
aSplToken
ubip_utils\solana\__init__.py
u<module bip_utils.solana>

a__spec__
.bip_utils.solana.spl_token
!
T
aGetAssociatedTokenAddressWithProgramId
aSplTokenConst
aDEF_TOKEN_PROGRAM_ID

Get the account address associated to the specified SPL token.
Args:
wallet_addr (str)    : Wallet address
token_mint_addr (str): Token mint address
Returns:
str: Associated account address
Raises:
ValueError: If the account address cannot be found or the specified addresses are not valid
aSolAddrDecoder
aDecodeAddr
aFindPda
aDEF_PROGRAM_ID

Get the account address associated to the specified SPL token and token program ID.
Args:
wallet_addr (str)     : Wallet address
token_mint_addr (str) : Token mint address
token_program_id (str): Token program ID
Returns:
str: Associated account address
Raises:
ValueError: If the account address cannot be found or the specified addresses or ID are not valid
aSEEDS_MAX_NUM
uSeeds length is not valid (

w)aEd25519PublicKey
aCompressedLength
uSeed length is not valid (
aSEED_BUMP_MAX_VAL
aIntegerUtils
aToBytes
bump_seed
cls
a_SplToken__CreatePda
program_id_bytes
uUnable to find a valid PDA

Find a valid PDA (Program Derived Address) and its corresponding bump seed.
Args:
seeds (list[bytes]): List of seeds bytes
program_id (str)   : Program ID
Returns:
str: Found PDA
Raises:
ValueError: If the PDA cannot be found or the specified seeds or program ID are not valid
aSha256
sha256
aUpdate
aPDA_MARKER
aDigest
aIsValidBytes
uInvalid created PDA
aBase58Encoder
aEncode

Create a PDA (Program Derived Address) for the specified seeds and program ID.
Args:
seeds_with_bump (list[bytes]): List of seeds bytes with bump
program_id_bytes (bytes)     : Program ID bytes
Returns:
str: Created PDA
Raises:
ValueError: If the created PDA is not valid
uModule for getting account addresses of SPL tokens.
a__doc__
a__file__
origin
has_location
a__cached__
aList
ubip_utils.addr
T aSolAddrDecoder
ubip_utils.base58
T aBase58Encoder
ubip_utils.ecc
T aEd25519PublicKey
ubip_utils.utils.crypto
T aSha256
ubip_utils.utils.misc
T aIntegerUtils
