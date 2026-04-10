# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.brainwallet.ibrainwallet_algo


Interface for an algorithm that computes a private key for a brainwallet.
It can be inherited to implement custom algorithms.
a__qualname__
staticmethod
passphrase
str
kwargs
return
bytes

Compute the private key from the specified passphrase.
Args:
passphrase (str): Passphrase
**kwargs        : Arbitrary arguments depending on the algorithm
Returns:
bytes: Private key bytes
aComputePrivateKey
uIBrainwalletAlgo.ComputePrivateKey
a__orig_bases__
ubip_utils\brainwallet\ibrainwallet_algo.py
u<module bip_utils.brainwallet.ibrainwallet_algo>
T apassphrase
kwargs
T a__class__

a__spec__
.bip_utils.cardano.bip32.cardano_byron_legacy_bip32
8
7
aEllipticCurveTypes
aED25519_KHOLAW

Return the elliptic curve type.
Returns:
EllipticCurveTypes: Curve type
aBip32Const
aKHOLAW_KEY_NET_VERSIONS

Return the default key net version.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
aCardanoByronLegacyKeyDerivator

Return the key derivator class.
Returns:
IBip32KeyDerivator class: Key derivator class
aCardanoByronLegacyMstKeyGenerator

Return the master key generator class.
Returns:
IBip32MstKeyGenerator class: Master key generator class
uModule for keys derivation based for Cardano Byron (legacy).
a__doc__
a__file__
origin
has_location
a__cached__
aType
ubip_utils.bip.bip32
T aBip32Base
aBip32Const
aBip32KeyNetVersions
aIBip32KeyDerivator
aIBip32MstKeyGenerator
aBip32Base
aBip32KeyNetVersions
aIBip32KeyDerivator
aIBip32MstKeyGenerator
ubip_utils.cardano.bip32.cardano_byron_legacy_key_derivator
T aCardanoByronLegacyKeyDerivator
ubip_utils.cardano.bip32.cardano_byron_legacy_mst_key_generator
T aCardanoByronLegacyMstKeyGenerator
ubip_utils.ecc
T aEllipticCurveTypes
a__prepare__
aCardanoByronLegacyBip32
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
