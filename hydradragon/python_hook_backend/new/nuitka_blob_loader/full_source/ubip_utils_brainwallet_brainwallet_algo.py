# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.brainwallet.brainwallet_algo

uEnum for brainwallet algorithms.
a__qualname__
aSHA256
aDOUBLE_SHA256
aPBKDF2_HMAC_SHA512
aSCRYPT
a__orig_bases__
uClass container for brainwallet algorithm constants.
a__annotations__
l l    l   l aBrainwalletAlgoSha256
uCompute the private key from passphrase using SHA256 algorithm.
staticmethod
passphrase
str
kwargs
return
bytes
aComputePrivateKey
uBrainwalletAlgoSha256.ComputePrivateKey
aBrainwalletAlgoDoubleSha256
uCompute the private key from passphrase using double SHA256 algorithm.
uBrainwalletAlgoDoubleSha256.ComputePrivateKey
aBrainwalletAlgoPbkdf2HmacSha512
uCompute the private key from passphrase using PBKDF2 HMAC-SHA512 algorithm.
uBrainwalletAlgoPbkdf2HmacSha512.ComputePrivateKey
aBrainwalletAlgoScrypt
uCompute the private key from passphrase using Scrypt algorithm.
uBrainwalletAlgoScrypt.ComputePrivateKey
ubip_utils\brainwallet\brainwallet_algo.py
u<module bip_utils.brainwallet.brainwallet_algo>
T a__class__
T apassphrase
kwargs
T apassphrase
kwargs
salt
itr_num
T apassphrase
kwargs
salt
wnwrwpa__spec__
.bip_utils.brainwallet.brainwallet_algo_getter
x
+
aBrainwalletAlgos
uAlgorithm type is not an enumerative of BrainwalletAlgos
aBrainwalletAlgoGetterConst
aENUM_TO_ALGO

Get algorithm class.
Args:
lgo_type (BrainwalletAlgos): Algorithm type
Returns:
IBrainwalletAlgo class: Algorithm class
Raises:
TypeError: If algorithm type is not of a BrainwalletAlgos enumerative
uModule for getting brainwallet algorithms.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aType
ubip_utils.brainwallet.brainwallet_algo
T aBrainwalletAlgoDoubleSha256
aBrainwalletAlgoPbkdf2HmacSha512
aBrainwalletAlgos
aBrainwalletAlgoScrypt
aBrainwalletAlgoSha256
aBrainwalletAlgoDoubleSha256
aBrainwalletAlgoPbkdf2HmacSha512
aBrainwalletAlgoScrypt
aBrainwalletAlgoSha256
ubip_utils.brainwallet.ibrainwallet_algo
T aIBrainwalletAlgo
aIBrainwalletAlgo
