# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.base.ibip32_key_derivator

uInterface for generic BIP32 key derivator.
a__qualname__
staticmethod
return
bool

Get if public derivation is supported.
Returns:
bool: True if supported, false otherwise.
aIsPublicDerivationSupported
uIBip32KeyDerivator.IsPublicDerivationSupported
classmethod
priv_key
pub_key
index
bytes

Derive a child key with the specified index using private derivation.
Args:
priv_key (Bip32PrivateKey object): Bip32PrivateKey object
pub_key (Bip32PublicKey object)  : Bip32PublicKey object
index (Bip32KeyIndex object)     : Key index
Returns:
tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the index results in an invalid key
aCkdPriv
uIBip32KeyDerivator.CkdPriv

Derive a child key with the specified index using public derivation.
Args:
pub_key (Bip32PublicKey object): Bip32PublicKey object
index (Bip32KeyIndex object)   : Key index
Returns:
tuple[bytes or IPoint, bytes]: Public key bytes or point (index 0) and chain code bytes (index 1)
Raises:
Bip32KeyError: If the index results in an invalid key
aCkdPub
uIBip32KeyDerivator.CkdPub
a__orig_bases__
ubip_utils\bip\bip32\base\ibip32_key_derivator.py
u<module bip_utils.bip.bip32.base.ibip32_key_derivator>
T acls
priv_key
pub_key
index
T acls
pub_key
index
T a__class__

a__spec__
.bip_utils.bip.bip32.base.ibip32_mst_key_generator
%
#
uModule for BIP32 SLIP-0010 keys derivation.
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
aTuple
a__prepare__
aIBip32MstKeyGenerator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
