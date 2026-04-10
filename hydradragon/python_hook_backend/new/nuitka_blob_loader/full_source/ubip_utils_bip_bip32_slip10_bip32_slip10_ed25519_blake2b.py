# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.slip10.bip32_slip10_ed25519_blake2b


BIP32 SLIP-0010 ed25519-blake2b class.
It allows master keys generation and keys derivation using ed25519-blake2b curve.
a__qualname__
staticmethod
return
aCurveType
uBip32Slip10Ed25519Blake2b.CurveType
a__orig_bases__
aBip32Ed25519Blake2bSlip
ubip_utils\bip\bip32\slip10\bip32_slip10_ed25519_blake2b.py
u<module bip_utils.bip.bip32.slip10.bip32_slip10_ed25519_blake2b>
T a__class__

a__spec__
.bip_utils.bip.bip32.slip10.bip32_slip10_key_derivator
^
aCurve
aRaw
aToBytes
aIsHardened
aBip32Slip10DerivatorConst
aPRIV_KEY_PREFIX
aRawCompressed
aHmacSha512
aQuickDigestHalves
aChainCode
aBytesUtils
aToInteger
aIntegerUtils
aOrder
aPrivateKeyClass
aLength
T abytes_num

Derive a child key with the specified index using private derivation.
Args:
priv_key (Bip32PrivateKey object): Bip32PrivateKey object
pub_key (Bip32PublicKey object)  : Bip32PublicKey object
index (Bip32KeyIndex object)     : Key index
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the index results in an invalid key
aPoint
aGenerator

Derive a child key with the specified index using public derivation.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
index (Bip32KeyIndex object)   : Key index
Returns:
tuple[bytes or IPoint, bytes]: Public key bytes or point (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the index results in an invalid key
aBip32KeyError
T uPrivate child derivation with not-hardened index is not supported
T uPublic child derivation is not supported

Module for BIP32 SLIP-0010 keys derivation.
References:
https://github.com/satoshilabs/slips/blob/master/slip-0010.md
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
aUnion
ubip_utils.bip.bip32.base
T aIBip32KeyDerivator
aIBip32KeyDerivator
ubip_utils.bip.bip32.bip32_ex
T aBip32KeyError
ubip_utils.bip.bip32.bip32_key_data
T aBip32KeyIndex
aBip32KeyIndex
ubip_utils.bip.bip32.bip32_keys
T aBip32PrivateKey
aBip32PublicKey
aBip32PrivateKey
aBip32PublicKey
ubip_utils.ecc
T aIPoint
aIPoint
ubip_utils.utils.crypto
T aHmacSha512
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
