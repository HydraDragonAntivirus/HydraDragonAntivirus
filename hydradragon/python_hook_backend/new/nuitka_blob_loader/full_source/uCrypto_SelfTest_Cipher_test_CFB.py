# Reconstructed from integrated Nuitka blob
# Module: uCrypto.SelfTest.Cipher.test_CFB

a__qualname__
aes_mode
des3_mode
test_unaligned_data_128
uCfbTests.test_unaligned_data_128
test_unaligned_data_64
uCfbTests.test_unaligned_data_64
test_segment_size_128
uCfbTests.test_segment_size_128
test_segment_size_64
uCfbTests.test_segment_size_64
a__orig_bases__
aTestCase
uNistCfbVectors._do_kat_aes_test
uNistCfbVectors._do_mct_aes_test
uNistCfbVectors._do_tdes_test
T uCFB?GFSbox128.rsp
uCFB?GFSbox192.rsp
uCFB?GFSbox256.rsp
uCFB?KeySbox128.rsp
uCFB?KeySbox192.rsp
uCFB?KeySbox256.rsp
uCFB?VarKey128.rsp
uCFB?VarKey192.rsp
uCFB?VarKey256.rsp
uCFB?VarTxt128.rsp
uCFB?VarTxt192.rsp
uCFB?VarTxt256.rsp
uCFB?MMT128.rsp
uCFB?MMT192.rsp
uCFB?MMT256.rsp
nist_aes_kat_mmt_files
T uCFB?MCT128.rsp
uCFB?MCT192.rsp
uCFB?MCT256.rsp
nist_aes_mct_files
file_gen_name
T w8u128
bits
replace
w?afile_name
new_func
test_AES_
T uTCFB?MMT2.rsp
uTCFB?MMT3.rsp
uTCFB?invperm.rsp
uTCFB?permop.rsp
uTCFB?subtab.rsp
uTCFB?varkey.rsp
uTCFB?vartext.rsp
nist_tdes_files
T w8u64
test_TDES_
uClass exercising the CFB test vectors found in Section F.3
of NIST SP 800-3A
test_aes_128_cfb8
uSP800TestVectors.test_aes_128_cfb8
test_aes_192_cfb8
uSP800TestVectors.test_aes_192_cfb8
test_aes_256_cfb8
uSP800TestVectors.test_aes_256_cfb8
test_aes_128_cfb128
uSP800TestVectors.test_aes_128_cfb128
test_aes_192_cfb128
uSP800TestVectors.test_aes_192_cfb128
test_aes_256_cfb128
uSP800TestVectors.test_aes_256_cfb128
get_tests
uCrypto\SelfTest\Cipher\test_CFB.py
T wxu<module Crypto.SelfTest.Cipher.test_CFB>
T a__class__
T aself
file_name
segment_size
test_vectors
direction
tv
cipher
Taself
file_name
segment_size
test_vectors
direction
tv
cipher
get_input
cts
wjaplaintext
pts
ciphertext
T aself
file_name
segment_size
test_vectors
direction
tv
cipher
key
T ainput_text
output_seq
wjasegment_size
tv
T asegment_size
tv
T atag
length
T aconfig
tests
T aself
file_name
bits
T aself
plaintext
ciphertext
key
iv
cipher
T aself
bits
cipher
T aself
plaintexts
cipher
ciphertexts

a__spec__
.Crypto.SelfTest.Cipher.test_CTR
aSHAKE128
new
tobytes
T adata
read
aAES
key_128
aMODE_CTR
ctr_128
T acounter
get_tag_random
T aplaintext
l  aencrypt
decrypt
assertEqual
aDES3
key_192
ctr_64
T aplaintext
l  aassertRaises
nonce
nonce_32
nonce_64
aCounter
T l@T aprefix
suffix
assertFalse
T anonce
T aprefix
initial_value
T aplaintext
l   aassertNotEqual
l D anonce
c
c
d0l  T acounter
nonce
l   T anonce
initial_value
D ainitial_value
l   T acounter
initial_value
b
D ainitial_value
c55555555555555555
c555555555
D ainitial_value
c555555555555555
c5555555
T lxT l  ablock_size
c7777777
cipher
l T acounter
unknown
T acounter
use_aesni
T aencrypt
decrypt
self
T c
bchr
T l	l T l T aprefix
d9l  l  T c1111111111111111
B
B 1111111111111111cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
dBl  =aSHA256
hexdigest
u96204fc470476561a3a8f3b6fe6d24be85c87510b638142d1d0fb90989f8a6a6
c4444444444444444
T c55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
B
T aoutput
c55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
D aoutput
c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
B
u6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
u874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
u2b7e151628aed2a6abf7158809cf4f3c
l aunhexlify
T af0f1f2f3f4f5f6f7f8f9fafbfcfd
l   T anbits
prefix
initial_value
u1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050
u8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
u601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6
u603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
bindata
T l ahexlify
list_test_cases
aCtrTests
aSP800TestVectors
aRFC3686TestVectors
a__doc__
a__file__
origin
has_location
a__cached__
unittest
binascii
T ahexlify
unhexlify
uCrypto.SelfTest.st_common
T alist_test_cases
uCrypto.Util.py3compat
T atobytes
bchr
uCrypto.Cipher
T aAES
aDES3
uCrypto.Hash
T aSHAKE128
aSHA256
uCrypto.Util
T aCounter
aTestCase
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
