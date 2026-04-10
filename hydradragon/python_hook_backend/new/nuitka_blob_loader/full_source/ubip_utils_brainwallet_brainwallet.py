# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.brainwallet.brainwallet


Brainwallet class.
It allows to generate a key pair from a passphrase chosen by the user
for different coins and with different algorithms.
aBrainwallet
a__qualname__
a__annotations__
D apasshrase
coin_type
algo_type
algo_params
return
str
aBrainwalletCoins
aBrainwalletAlgos
aAny
aBrainwallet
aGenerate
uBrainwallet.Generate
D apasshrase
coin_type
algo_cls
algo_params
return
str
aBrainwalletCoins
uType[IBrainwalletAlgo]
aAny
aBrainwallet
uBrainwallet.GenerateWithCustomAlgo
D abip44_obj
return
aBip44Base
aNone
a__init__
uBrainwallet.__init__
D areturn
aBip44PublicKey
uBrainwallet.PublicKey
D areturn
aBip44PrivateKey
uBrainwallet.PrivateKey
ubip_utils\brainwallet\brainwallet.py
u<module bip_utils.brainwallet.brainwallet>
T a__class__
T acls
passhrase
coin_type
algo_type
algo_params
T acls
passhrase
coin_type
algo_cls
algo_params
T aself
T aself
bip44_obj

a__spec__
.bip_utils.brainwallet.brainwallet_algo
v
X
aSha256
aQuickDigest

Compute the private key from the specified passphrase.
Args:
passphrase (str): Passphrase
**kwargs        : Not used
Returns:
bytes: Private key bytes
aDoubleSha256
salt

itr_num
aBrainwalletAlgoConst
aPBKDF2_HMAC_SHA512_DEF_ITR_NUM
aPbkdf2HmacSha512
aDeriveKey
aPBKDF2_HMAC_SHA512_KEY_LEN
T aitr_num
dklen

Compute the private key from the specified passphrase.
Args:
passphrase (str): Passphrase
Other Parameters:
salt (str)   : Salt for PBKDF2 algorithm (default: empty)
itr_num (int): Number of iteration for PBKDF2 algorithm (default: 2097152)
Returns:
bytes: Private key bytes
wnaSCRYPT_DEF_N
wraSCRYPT_DEF_R
wpaSCRYPT_DEF_P
aScrypt
aSCRYPT_KEY_LEN
T akey_len
wnwrwpu
Compute the private key from the specified passphrase.
Args:
passphrase (str): Passphrase
Other Parameters:
salt (str): Salt for Scrypt algorithm (default: empty)
n (int)   : CPU/Memory cost parameter for Scrypt algorithm (default: 131072)
r (int)   : Block size parameter for Scrypt algorithm (default: 8)
p (int)   : Parallelization parameter for Scrypt algorithm (default: 8)
Returns:
bytes: Private key bytes
uModule for implementing algorithms for brainwallet generation.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
auto
unique
aEnum
auto
unique
aAny
ubip_utils.brainwallet.ibrainwallet_algo
T aIBrainwalletAlgo
aIBrainwalletAlgo
ubip_utils.utils.crypto
T aDoubleSha256
aPbkdf2HmacSha512
aScrypt
aSha256
a__prepare__
aBrainwalletAlgos
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
