# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.slip10.bip32_slip10_key_derivator

uClass container for BIP32 SLIP-0010 derivator constants.
a__qualname__
a__annotations__
d
a__prepare__
aBip32Slip10EcdsaDerivator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

BIP32 SLIP-0010 ECDSA key derivator class.
It allows keys derivation for ECDSA curves in according to BIP32 SLIP-0010.
staticmethod
return
bool

Get if public derivation is supported.
Returns:
bool: True if supported, false otherwise.
aIsPublicDerivationSupported
uBip32Slip10EcdsaDerivator.IsPublicDerivationSupported
classmethod
priv_key
pub_key
index
bytes
aCkdPriv
uBip32Slip10EcdsaDerivator.CkdPriv
aCkdPub
uBip32Slip10EcdsaDerivator.CkdPub
a__orig_bases__
aBip32Slip10Ed25519Derivator

BIP32 SLIP-0010 ed25519 key derivator class.
It allows keys derivation for ed25519 curves in according to BIP32 SLIP-0010.
uBip32Slip10Ed25519Derivator.IsPublicDerivationSupported
uBip32Slip10Ed25519Derivator.CkdPriv
uBip32Slip10Ed25519Derivator.CkdPub
ubip_utils\bip\bip32\slip10\bip32_slip10_key_derivator.py
u<module bip_utils.bip.bip32.slip10.bip32_slip10_key_derivator>
T a__class__
T acls
priv_key
pub_key
index
curve
priv_key_bytes
data_bytes
il_bytes
ir_bytes
il_int
priv_key_int
new_priv_key_bytes
T acls
priv_key
pub_key
index
data_bytes
T acls
pub_key
index
data_bytes
il_bytes
ir_bytes
il_int
new_pub_key_point
T acls
pub_key
index

a__spec__
.bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator
o
R
aBip32Slip10MstKeyGeneratorConst
aSEED_MIN_BYTE_LEN
uInvalid seed length (

w)aHmacSha512
aDigestSize
l aEllipticCurveGetter
aFromType
aPrivateKeyClass
c
success
aQuickDigest
hmac_key_bytes
hmac_data
priv_key_cls
aIsValidBytes
hmac

Generate a master key from the specified seed and return a Bip32Base object.
Args:
seed_bytes (bytes)                      : Seed bytes
hmac_key_bytes (bytes)                  : HMAC key bytes
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the seed is not suitable for master key generation
ValueError: If seed length is not valid
a_Bip32Slip10MstKeyGenerator
aGenerateFromSeed
aHMAC_KEY_ED25519_BYTES
aEllipticCurveTypes
aED25519

Generate a master key from the specified seed.
Args:
seed_bytes (bytes): Seed bytes
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the seed is not suitable for master key generation
ValueError: If seed length is not valid
aHMAC_KEY_NIST256P1_BYTES
aNIST256P1
aHMAC_KEY_SECP256K1_BYTES
aSECP256K1

Module for BIP32 SLIP-0010 master key generation.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ubip_utils.bip.bip32.base
T aIBip32MstKeyGenerator
aIBip32MstKeyGenerator
ubip_utils.ecc
T aEllipticCurveGetter
aEllipticCurveTypes
ubip_utils.utils.crypto
T aHmacSha512
