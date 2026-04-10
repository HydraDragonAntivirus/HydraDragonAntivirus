# Reconstructed from integrated Nuitka blob
# Module: uCrypto.SelfTest.Cipher.test_DES

u Ronald L. Rivest's DES test, see
http://people.csail.mit.edu/rivest/Destest.txt
ABSTRACT
--------
We present a simple way to test the correctness of a DES implementation:
Use the recurrence relation:
X0      =       9474B8E8C73BCA7D (hexadecimal)
X(i+1)  =       IF  (i is even)  THEN  E(Xi,Xi)  ELSE  D(Xi,Xi)
to compute a sequence of 64-bit values:  X0, X1, X2, ..., X16.  Here
E(X,K)  denotes the DES encryption of  X  using key  K, and  D(X,K)  denotes
the DES decryption of  X  using key  K.  If you obtain
X16     =       1B1A2DDB4C642438
your implementation does not have any of the 36,568 possible single-fault
errors described herein.
a__qualname__
runTest
uRonRivestTest.runTest
a__orig_bases__
uTestOutput.runTest
get_tests
uCrypto\SelfTest\Cipher\test_DES.py
u<module Crypto.SelfTest.Cipher.test_DES>
T a__class__
T aconfig
make_block_tests
tests
T aself
b2a_hex
wXwiwcT aself
cipher
pt
ct
output
res
shorter_output

a__spec__
.Crypto.SelfTest.Cipher.test_DES3
m
unhexlify
T aCABF326FA56734324FFCCABCDEFACABF
aDES3
adjust_key_parity
assertEqual
T aCBBF326EA46734324FFDCBBCDFFBCBBF
T aAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC
T aABABABABABABABABBABABABABABABABACDCDCDCDCDCDCDCD
bchr
T l l T l  aassertRaises
l l astrxor_c
new
aMODE_ECB
c44444444GGGGGGGGTTTTTTTT
encrypt
T c5555555555555555
B
T aoutput
decrypt
c5555555555555555
D aoutput
c0000000000000000
B
common
T amake_block_tests
make_block_tests
test_data
append
aDegenerateToDESTest
list_test_cases
aCheckParity
aTestOutput
uSelf-test suite for Crypto.Cipher.DES3
a__doc__
a__file__
origin
has_location
a__cached__
unittest
binascii
T ahexlify
unhexlify
hexlify
uCrypto.Cipher
T aDES3
uCrypto.Util.strxor
T astrxor_c
uCrypto.Util.py3compat
T abchr
tostr
tostr
uCrypto.SelfTest.loader
T aload_test_vectors
load_test_vectors
uCrypto.SelfTest.st_common
T alist_test_cases
T u54686520717566636b2062726f776e20666f78206a756d70
a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900
u0123456789abcdef23456789abcdef01456789abcdef0123
uNIST SP800-67 B.1
T u21e81b7ade88a259
u5c577d4d9b20c0f8
u9b397ebf81b1181e282f4bb8adbadc6b
uTwo-key 3DES
T uTECBMMT2.rsp
uTECBMMT3.rsp
nist_tdes_mmt_files
tdes_file
T aCipher
aTDES
uTDES ECB (%s)
count
u<lambda>
test_vectors
index
tv
key1
key2
key3
key
plaintext
ciphertext
u%s (%s)
test_data_item
aTestCase
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
