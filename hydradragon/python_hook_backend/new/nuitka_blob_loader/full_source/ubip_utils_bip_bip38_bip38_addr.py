# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip38.bip38_addr

uClass container for BIP38 address constants.
a__qualname__
a__annotations__
l uClass for BIP38 address computation.
aBip38Addr
pub_key
pub_key_mode
return
aAddressHash
uBip38Addr.AddressHash
ubip_utils\bip\bip38\bip38_addr.py
u<module bip_utils.bip.bip38.bip38_addr>
T apub_key
pub_key_mode
address
T a__class__

a__spec__
.bip_utils.bip.bip38.bip38_ec
+%
aBip38EcConst
aLOT_NUM_MIN_VAL
aLOT_NUM_MAX_VAL
uInvalid lot number (

w)aSEQ_NUM_MIN_VAL
aSEQ_NUM_MAX_VAL
uInvalid sequence number (
urandom
aOWNER_SALT_WITH_LOT_SEQ_BYTE_LEN
aIntegerUtils
aToBytes
D abytes_num
l u
Compute the owner entropy as specified in BIP38 (with EC multiplication) with lot and sequence numbers.
Args:
lot_num (int)     : Lot number
sequence_num (int): Sequence number
Returns:
bytes: Owner entropy
Raises:
ValueError: If lot or sequence number is not valid
aOWNER_SALT_NO_LOT_SEQ_BYTE_LEN

Compute the owner entropy as specified in BIP38 (with EC multiplication) without lot and sequence numbers.
Returns:
bytes: Owner entropy

Get owner salt from owner entropy.
Args:
owner_entropy (bytes): Owner entropy
has_lot_seq (bool)   : True if lot and sequence numbers are present, false otherwise
Returns:
bytes: Owner salt
aScrypt
aDeriveKey
aStringUtils
aNormalizeNfc
a_Bip38EcUtils
aOwnerSaltFromEntropy
aSCRYPT_PREFACTOR_KEY_LEN
aSCRYPT_PREFACTOR_N
aSCRYPT_PREFACTOR_P
aSCRYPT_PREFACTOR_R
T akey_len
wnwrwpaDoubleSha256
aQuickDigest

Compute the passfactor as specified in BIP38 (with EC multiplication).
Args:
passphrase (str)     : Passphrase
owner_entropy (bytes): Owner entropy
has_lot_seq (bool)   : True if lot and sequence numbers are present, false otherwise
Returns:
bytes: Passfactor
aSecp256k1PublicKey
aFromPoint
aSecp256k1
aGenerator
aBytesUtils
aToInteger
aRawCompressed

Compute the passpoint as specified in BIP38 (with EC multiplication).
Args:
passfactor (bytes): Passfactor
Returns:
bytes: Passpoint bytes in compressed format
aSCRYPT_HALVES_KEY_LEN
aSCRYPT_HALVES_N
aSCRYPT_HALVES_R
aSCRYPT_HALVES_P
l u
Compute the scrypt as specified in BIP38 (without EC multiplication)and derive the two key halves.
Args:
passpoint (bytes)    : Passpoint
ddress_hash (bytes) : Address hash
owner_entropy (bytes): Owner entropy
Returns:
tuple[bytes, bytes]: Derived key halves
aOwnerEntropyWithLotSeq
aOwnerEntropyNoLotSeq
aPassFactor
aPassPoint
aINT_PASS_MAGIC_WITH_LOT_SEQ
aINT_PASS_MAGIC_NO_LOT_SEQ
aBase58Encoder
aCheckEncode

Generate an intermediate passphrase from the user passphrase as specified in BIP38.
Args:
passphrase (str)            : Passphrase
lot_num (int, optional)     : Lot number
sequence_num (int, optional): Sequence number
Returns:
str: Intermediate passphrase encoded in base58
aBase58Decoder
aCheckDecode
aINT_PASS_ENC_BYTE_LEN
uInvalid intermediate code length (
:nl n:l l naFromBytes
:l nnuInvalid magic (
aToHexString
aSEED_B_BYTE_LEN
aBip38Addr
aAddressHash
aPoint
aDeriveKeyHalves
aBip38EcKeysGenerator
a_Bip38EcKeysGenerator__EncryptSeedb
a_Bip38EcKeysGenerator__SetFlagbyteBits
aENC_KEY_PREFIX

Generate a random encrypted private key from the intermediate passphrase.
Args:
int_passphrase (str)           : Intermediate passphrase
pub_key_mode (Bip38PubKeyModes): Public key mode
Returns:
str: Encrypted private key
Raises:
Base58ChecksumError: If base58 checksum is not valid
ValueError: If the intermediate code is not valid
aAesEcbEncrypter
aAutoPad
T FaEncrypt
aXor
:nl n:l nnu
Encrypt seedb in two parts.
Args:
seedb (bytes)         : Seedb
derived_half_1 (bytes): First half of derived key
derived_half_2 (bytes): Second half of derived key
Returns:
tuple[bytes, bytes]: Two encrypted parts
aBip38PubKeyModes
aCOMPRESSED
aBitUtils
aSetBit
aFLAG_BIT_COMPRESSED
aFLAG_BIT_LOT_SEQ

Set flagbyte bits and return it.
Args:
magic (bytes)                  : Magic
pub_key_mode (Bip38PubKeyModes): Public key mode
Returns:
bytes: Flagbyte
aENC_BYTE_LEN
uInvalid encrypted length (
:nl n:l l n:l l n:l l n:l nnuInvalid prefix (
aBip38EcDecrypter
a_Bip38EcDecrypter__GetFlagbyteOptions
a_Bip38EcDecrypter__DecryptAndGetFactorb
a_Bip38EcDecrypter__ComputePrivateKey
aSecp256k1PrivateKey
aPublicKey
uInvalid address hash (expected:
u, got:

Decrypt the specified private key.
Args:
priv_key_enc (str): Encrypted private key bytes
passphrase (str)  : Passphrase
Returns:
tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)
Raises:
Base58ChecksumError: If base58 checksum is not valid
ValueError: If the encrypted key is not valid
aAesEcbDecrypter
aAutoUnPad
aDecrypt

Decrypt and get back factorb.
Args:
encrypted_part_1_lower (bytes): Lower part of first encrypted part
encrypted_part_2 (bytes)      : Second encrypted part
derived_half_1 (bytes)        : First half of derived key
derived_half_2 (bytes)        : Second half of derived key
Returns:
bytes: Factorb
aOrder
aLength
T abytes_num

Compute the private key from passfactor and factorb.
Args:
passfactor (bytes): Passfactor
factorb (bytes)   : Factorb
Returns:
bytes: Private key
aIsBitSet
aUNCOMPRESSED
aResetBit
uInvalid flagbyte (

Get the options from the flagbyte.
Args:
flagbyte (bytes): Flagbyte
Returns:
tuple[Bip38PubKeyModes, bool]: Public key mode (index 0), has lot/sequence numbers (index 1)

Module for BIP38 encryption/decryption.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
os
aOptional
aTuple
ubip_utils.base58
T aBase58Decoder
aBase58Encoder
ubip_utils.bip.bip38.bip38_addr
T aBip38Addr
aBip38PubKeyModes
ubip_utils.ecc
T aSecp256k1
aSecp256k1PrivateKey
aSecp256k1PublicKey
ubip_utils.utils.crypto
T aAesEcbDecrypter
aAesEcbEncrypter
aDoubleSha256
aScrypt
ubip_utils.utils.misc
T aBitUtils
aBytesUtils
aIntegerUtils
aStringUtils
