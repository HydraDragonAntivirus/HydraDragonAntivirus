# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip38.bip38_ec

uClass container for BIP38 EC constants.
a__qualname__
a__annotations__
l  ?l  l l l1c,    9 Q
c,    9 S
l l'c C
l l l   l@l  uClass container for BIP38 EC utility functions.
D alot_num
sequence_num
return
Oint
pObytes
u_Bip38EcUtils.OwnerEntropyWithLotSeq
D areturn
Obytes
u_Bip38EcUtils.OwnerEntropyNoLotSeq
D aowner_entropy
has_lot_seq
return
Obytes
Obool
Obytes
u_Bip38EcUtils.OwnerSaltFromEntropy
D apassphrase
owner_entropy
has_lot_seq
return
Ostr
Obytes
Obool
Obytes
u_Bip38EcUtils.PassFactor
D apassfactor
return
Obytes
pu_Bip38EcUtils.PassPoint
passpoint
address_hash
owner_entropy
return
T Obytes
pu_Bip38EcUtils.DeriveKeyHalves

BIP38 keys generator class.
It generates intermediate codes and private keys using the algorithm specified in BIP38 with EC multiplication.
T nnapassphrase
lot_num
sequence_num
aGenerateIntermediatePassphrase
uBip38EcKeysGenerator.GenerateIntermediatePassphrase
int_passphrase
pub_key_mode
aGeneratePrivateKey
uBip38EcKeysGenerator.GeneratePrivateKey
seedb
derived_half_1
derived_half_2
a__EncryptSeedb
uBip38EcKeysGenerator.__EncryptSeedb
magic
a__SetFlagbyteBits
uBip38EcKeysGenerator.__SetFlagbyteBits

BIP38 decrypter class.
It decrypts a private key using the algorithm specified in BIP38 with EC multiplication.
priv_key_enc
uBip38EcDecrypter.Decrypt
D aencrypted_part_1_lower
encrypted_part_2
derived_half_1
derived_half_2
return
Obytes
ppppa__DecryptAndGetFactorb
uBip38EcDecrypter.__DecryptAndGetFactorb
D apassfactor
factorb
return
Obytes
ppa__ComputePrivateKey
uBip38EcDecrypter.__ComputePrivateKey
flagbyte
a__GetFlagbyteOptions
uBip38EcDecrypter.__GetFlagbyteOptions
ubip_utils\bip\bip38\bip38_ec.py
u<module bip_utils.bip.bip38.bip38_ec>
T a__class__
T apriv_key_enc
passphrase
priv_key_enc_bytes
prefix
flagbyte
address_hash
owner_entropy
encrypted_part_1_lower
encrypted_part_2
pub_key_mode
has_lot_seq
passfactor
derived_half_1
derived_half_2
factorb
priv_key_bytes
address_hash_got
T apasspoint
address_hash
owner_entropy
key
derived_half_1
derived_half_2
T apassphrase
lot_num
sequence_num
has_lot_seq
owner_entropy
passfactor
passpoint
magic
T aint_passphrase
pub_key_mode
int_passphrase_bytes
magic
owner_entropy
passpoint
seedb
factorb
address_hash
derived_half_1
derived_half_2
encrypted_part_1
encrypted_part_2
flagbyte
enc_key_bytes
T aowner_salt
T alot_num
sequence_num
owner_salt
lot_sequence
T aowner_entropy
has_lot_seq
T apassphrase
owner_entropy
has_lot_seq
prefactor
passfactor
T apassfactor
passpoint
T apassfactor
factorb
priv_key_int
T
encrypted_part_1_lower
encrypted_part_2
derived_half_1
derived_half_2
aes_dec
decrypted_part_2
encrypted_part_1_higher
seedb_part_2
seedb_part_1
seedb
T aseedb
derived_half_1
derived_half_2
aes_enc
encrypted_part_1
encrypted_part_2
T aflagbyte
flagbyte_int
has_lot_seq
pub_key_mode
T amagic
pub_key_mode
flagbyte_int
a__spec__
.bip_utils.bip.bip38.bip38_no_ec
aBip38Addr
aAddressHash
aSecp256k1PrivateKey
aFromBytes
aPublicKey

Compute the address hash as specified in BIP38 (without EC multiplication).
Args:
priv_key_bytes (bytes)         : private key bytes
pub_key_mode (Bip38PubKeyModes): Public key mode
Returns:
bytes: Address hash
Raises:
ValueError: If the private key is not valid
aScrypt
aDeriveKey
aStringUtils
aNormalizeNfc
aBip38NoEcConst
aSCRYPT_KEY_LEN
aSCRYPT_N
aSCRYPT_R
aSCRYPT_P
T akey_len
wnwrwpl u
Compute the scrypt as specified in BIP38 (without EC multiplication) and derive the two key halves.
Args:
passphrase (str)    : Passphrase
ddress_hash (bytes): Address hash
Returns:
tuple[bytes, bytes]: Derived key halves
uA secp256k1 private key is required
aRaw
aToBytes
a_Bip38NoEcUtils
aDeriveKeyHalves
aBip38NoEcEncrypter
a_Bip38NoEcEncrypter__EncryptPrivateKey
aBip38PubKeyModes
aCOMPRESSED
aFLAGBYTE_COMPRESSED
aFLAGBYTE_UNCOMPRESSED
aENC_KEY_PREFIX
aBase58Encoder
aCheckEncode

Encrypt the specified private key.
Args:
priv_key (bytes or IPrivateKey): Private key bytes or object
passphrase (str)               : Passphrase
pub_key_mode (Bip38PubKeyModes): Public key mode
Returns:
str: Encrypted private key
Raises:
TypeError: If the private key is not a Secp256k1PrivateKey
ValueError: If the private key bytes are not valid
aAesEcbEncrypter
aAutoPad
T FaEncrypt
aBytesUtils
aXor
:nl n:l nnu
Encrypt private key in two halves.
Args:
priv_key_bytes (bytes): Private key
derived_half_1 (bytes): First half of derived key
derived_half_2 (bytes): Second half of derived key
Returns:
tuple[bytes, bytes]: Two encrypted halves
aBase58Decoder
aCheckDecode
aENC_KEY_BYTE_LEN
uInvalid encrypted key length (

w):nl naIntegerUtils
:l l n:l l n:l nnuInvalid prefix (
aToHexString
uInvalid flagbyte (
aBip38NoEcDecrypter
a_Bip38NoEcDecrypter__DecryptAndGetPrivKey
aUNCOMPRESSED
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

Decrypt and get back private key.
Args:
encrypted_half_1 (bytes): First encrypted half
encrypted_half_2 (bytes): Second encrypted half
derived_half_1 (bytes)  : First half of derived key
derived_half_2 (bytes)  : Second half of derived key
Returns:
bytes: Decrypted private key

Module for BIP38 encryption/decryption.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
aUnion
ubip_utils.base58
T aBase58Decoder
aBase58Encoder
ubip_utils.bip.bip38.bip38_addr
T aBip38Addr
aBip38PubKeyModes
ubip_utils.ecc
T aIPrivateKey
aSecp256k1PrivateKey
aIPrivateKey
ubip_utils.utils.crypto
T aAesEcbDecrypter
aAesEcbEncrypter
aScrypt
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
aStringUtils
