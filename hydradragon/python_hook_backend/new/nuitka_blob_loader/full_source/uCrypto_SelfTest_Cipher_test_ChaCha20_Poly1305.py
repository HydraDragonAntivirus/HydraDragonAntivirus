# Reconstructed from integrated Nuitka blob
# Module: uCrypto.SelfTest.Cipher.test_ChaCha20_Poly1305

a__qualname__
T akey_256
l T anonce_96
l T adata_128
l atest_loopback
uChaCha20Poly1305Tests.test_loopback
test_nonce
uChaCha20Poly1305Tests.test_nonce
test_nonce_must_be_bytes
uChaCha20Poly1305Tests.test_nonce_must_be_bytes
test_nonce_length
uChaCha20Poly1305Tests.test_nonce_length
test_block_size
uChaCha20Poly1305Tests.test_block_size
test_nonce_attribute
uChaCha20Poly1305Tests.test_nonce_attribute
test_unknown_parameters
uChaCha20Poly1305Tests.test_unknown_parameters
test_null_encryption_decryption
uChaCha20Poly1305Tests.test_null_encryption_decryption
test_either_encrypt_or_decrypt
uChaCha20Poly1305Tests.test_either_encrypt_or_decrypt
test_data_must_be_bytes
uChaCha20Poly1305Tests.test_data_must_be_bytes
test_mac_len
uChaCha20Poly1305Tests.test_mac_len
test_invalid_mac
uChaCha20Poly1305Tests.test_invalid_mac
test_hex_mac
uChaCha20Poly1305Tests.test_hex_mac
test_message_chunks
uChaCha20Poly1305Tests.test_message_chunks
test_bytearray
uChaCha20Poly1305Tests.test_bytearray
test_memoryview
uChaCha20Poly1305Tests.test_memoryview
a__orig_bases__
uXChaCha20Poly1305Tests.test_nonce
uXChaCha20Poly1305Tests.test_encrypt
test_valid_init_encrypt_decrypt_digest_verify
uChaCha20Poly1305FSMTests.test_valid_init_encrypt_decrypt_digest_verify
test_valid_init_update_digest_verify
uChaCha20Poly1305FSMTests.test_valid_init_update_digest_verify
test_valid_full_path
uChaCha20Poly1305FSMTests.test_valid_full_path
test_valid_init_digest
uChaCha20Poly1305FSMTests.test_valid_init_digest
test_valid_init_verify
uChaCha20Poly1305FSMTests.test_valid_init_verify
test_valid_multiple_encrypt_or_decrypt
uChaCha20Poly1305FSMTests.test_valid_multiple_encrypt_or_decrypt
test_valid_multiple_digest_or_verify
uChaCha20Poly1305FSMTests.test_valid_multiple_digest_or_verify
test_valid_encrypt_and_digest_decrypt_and_verify
uChaCha20Poly1305FSMTests.test_valid_encrypt_and_digest_decrypt_and_verify
test_invalid_mixing_encrypt_decrypt
uChaCha20Poly1305FSMTests.test_invalid_mixing_encrypt_decrypt
test_invalid_encrypt_or_update_after_digest
uChaCha20Poly1305FSMTests.test_invalid_encrypt_or_update_after_digest
test_invalid_decrypt_or_update_after_verify
uChaCha20Poly1305FSMTests.test_invalid_decrypt_or_update_after_verify
compact
uTest cases from RFC7539
T u50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7
u4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 7373 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 636f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 2074 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 7363 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 6974 2e
ud3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d63d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 3692 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b61 16
u1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91
u80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
u07 00 00 0040 41 42 43 44 45 46 47
T uf3 33 88 86 00 00 00 00 00 00 4e 91
u49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 2061 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 656e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 206d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 6520 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 6365 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 6420 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 656e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 7269 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 6572 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 7265 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 616c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 656d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 202f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 6772 65 73 73 2e 2f e2 80 9d
u64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b24c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 8114 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 5597 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 3836 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e990 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3eaf 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4ece bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 1049 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 3030 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29a6 ad 5c b4 02 2b 02 70 9b
uee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38
u1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f047 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
u00 00 00 00 01 02 03 04 05 06 07 08
test_vectors_hex
runTest
uTestVectorsRFC.runTest
uTestVectorsWycheproof.__init__
uTestVectorsWycheproof.load_tests
setUp
uTestVectorsWycheproof.setUp
shortDescription
uTestVectorsWycheproof.shortDescription
uTestVectorsWycheproof.warn
uTestVectorsWycheproof.test_encrypt
uTestVectorsWycheproof.test_decrypt
uTestVectorsWycheproof.test_corrupt_decrypt
uTestVectorsWycheproof.runTest
uTestOutput.runTest
get_tests
uCrypto\SelfTest\Cipher\test_ChaCha20_Poly1305.py
u<module Crypto.SelfTest.Cipher.test_ChaCha20_Poly1305>
T a__class__
T aself
wycheproof_warnings
T adata
chunk_length
T wxT aroot
T agroup
T atag
length
T aconfig
wycheproof_warnings
tests
T aself
filename
filter_tag
filter_algo
result
T	aself
key
nonce
cipher
pt
ct
output
res
shorter_output
T aself
assoc_data
pt
ct
mac
key
nonce
cipher
ct2
mac2
pt2
T aself
tv
T aself
T aself
cipher
T aself
key_ba
nonce_ba
header_ba
data_ba
cipher1
ct
tag
cipher2
ct_test
tag_test
ct_ba
tag_ba
cipher3
pt_test
T aself
tv
cipher
ct_corrupt
T aself
tv
cipher
weapt
T aself
tv
cipher
weact
tag
T
self
pt
aad
key
iv
ct
tag
cipher
ct_test
tag_test
T aself
cipher
mac_hex
T aself
cipher
ct
mac
method_name
T aself
method_name
cipher
T aself
strxor_c
cipher
ct
mac
invalid_mac
T aself
method1_name
method2_name
assoc_data_present
cipher
T aself
cipher
pt
ct
pt2
T aself
cipher
w_amac
T aself
key_mv
nonce_mv
header_mv
data_mv
cipher1
ct
tag
cipher2
ct_test
tag_test
ct_mv
tag_mv
cipher3
pt_test
T aself
auth_data
plaintext
cipher
ciphertext
ref_mac
break_up
chunk_length
chunk
pt2
ct2
T aself
cipher
nonce1
nonce2
ct
T aself
cipher
nonce1
nonce2
T aself
func
cipher
result
T aself
cipher
ct
mac
pt
T aself
cipher
ct
mac
T aself
cipher
mac
T aself
cipher
first_mac
wxT aself
method_name
auth_data
cipher
method
T aself
tv
warnings

a__spec__
.Crypto.SelfTest.Cipher.test_DES
k"
binascii
T ab2a_hex
b2a_hex
c t   ; }
:l
nn;l
l l aDES
new
wXaMODE_ECB
encrypt
decrypt
assertEqual
l T c  - Ld$8
c44444444
T c55555555
B
T aoutput
c55555555
assertRaises
D aoutput
c00000000
B
common
T amake_block_tests
make_block_tests
test_data
aRonRivestTest
aTestOutput
uSelf-test suite for Crypto.Cipher.DES
a__doc__
a__file__
origin
has_location
a__cached__
unittest
uCrypto.Cipher
T aDES
u0101010101010101
aSP800_17_B1_KEY
u0000000000000000
aSP800_17_B2_PT
T u0000000000000000
u82dcbafbdeab6602
u10316e028c8f3b4a
uNIST SP800-17 A
u8000000000000000
u95f8a5e5dd31d900
uNIST SP800-17 B.1 #0
u4000000000000000
dd7f121ca5015619
uNIST SP800-17 B.1 #1
u2000000000000000
u2e8653104f3834ea
uNIST SP800-17 B.1 #2
u1000000000000000
u4bd388ff6cd81d4f
uNIST SP800-17 B.1 #3
u0800000000000000
u20b9e767b2fb1456
uNIST SP800-17 B.1 #4
u0400000000000000
u55579380d77138ef
uNIST SP800-17 B.1 #5
u0200000000000000
u6cc5defaaf04512f
uNIST SP800-17 B.1 #6
u0100000000000000
u0d9f279ba5d87260
uNIST SP800-17 B.1 #7
u0080000000000000
d9031b0271bd5a0a
uNIST SP800-17 B.1 #8
u0040000000000000
u424250b37c3dd951
uNIST SP800-17 B.1 #9
u0020000000000000
b8061b7ecd9a21e5
uNIST SP800-17 B.1 #10
u0010000000000000
f15d0f286b65bd28
uNIST SP800-17 B.1 #11
u0008000000000000
add0cc8d6e5deba1
uNIST SP800-17 B.1 #12
u0004000000000000
e6d5f82752ad63d1
uNIST SP800-17 B.1 #13
u0002000000000000
ecbfe3bd3f591a5e
uNIST SP800-17 B.1 #14
u0001000000000000
f356834379d165cd
uNIST SP800-17 B.1 #15
u0000800000000000
u2b9f982f20037fa9
uNIST SP800-17 B.1 #16
u0000400000000000
u889de068a16f0be6
uNIST SP800-17 B.1 #17
u0000200000000000
e19e275d846a1298
uNIST SP800-17 B.1 #18
u0000100000000000
u329a8ed523d71aec
uNIST SP800-17 B.1 #19
u0000080000000000
e7fce22557d23c97
uNIST SP800-17 B.1 #20
u0000040000000000
u12a9f5817ff2d65d
uNIST SP800-17 B.1 #21
u0000020000000000
a484c3ad38dc9c19
uNIST SP800-17 B.1 #22
u0000010000000000
fbe00a8a1ef8ad72
uNIST SP800-17 B.1 #23
u0000008000000000
u750d079407521363
uNIST SP800-17 B.1 #24
u0000004000000000
u64feed9c724c2faf
uNIST SP800-17 B.1 #25
u0000002000000000
f02b263b328e2b60
uNIST SP800-17 B.1 #26
u0000001000000000
u9d64555a9a10b852
uNIST SP800-17 B.1 #27
u0000000800000000
d106ff0bed5255d7
uNIST SP800-17 B.1 #28
u0000000400000000
e1652c6b138c64a5
uNIST SP800-17 B.1 #29
u0000000200000000
e428581186ec8f46
uNIST SP800-17 B.1 #30
u0000000100000000
aeb5f5ede22d1a36
uNIST SP800-17 B.1 #31
u0000000080000000
e943d7568aec0c5c
uNIST SP800-17 B.1 #32
u0000000040000000
df98c8276f54b04b
uNIST SP800-17 B.1 #33
u0000000020000000
b160e4680f6c696f
uNIST SP800-17 B.1 #34
u0000000010000000
fa0752b07d9c4ab8
uNIST SP800-17 B.1 #35
u0000000008000000
ca3a2b036dbc8502
uNIST SP800-17 B.1 #36
u0000000004000000
u5e0905517bb59bcf
uNIST SP800-17 B.1 #37
u0000000002000000
u814eeb3b91d90726
uNIST SP800-17 B.1 #38
u0000000001000000
u4d49db1532919c9f
uNIST SP800-17 B.1 #39
u0000000000800000
u25eb5fc3f8cf0621
uNIST SP800-17 B.1 #40
u0000000000400000
ab6a20c0620d1c6f
uNIST SP800-17 B.1 #41
u0000000000200000
u79e90dbc98f92cca
uNIST SP800-17 B.1 #42
u0000000000100000
u866ecedd8072bb0e
uNIST SP800-17 B.1 #43
u0000000000080000
u8b54536f2f3e64a8
uNIST SP800-17 B.1 #44
u0000000000040000
ea51d3975595b86b
uNIST SP800-17 B.1 #45
u0000000000020000
caffc6ac4542de31
uNIST SP800-17 B.1 #46
u0000000000010000
u8dd45a2ddf90796c
uNIST SP800-17 B.1 #47
u0000000000008000
u1029d55e880ec2d0
uNIST SP800-17 B.1 #48
u0000000000004000
u5d86cb23639dbea9
uNIST SP800-17 B.1 #49
u0000000000002000
u1d1ca853ae7c0c5f
uNIST SP800-17 B.1 #50
u0000000000001000
ce332329248f3228
uNIST SP800-17 B.1 #51
u0000000000000800
u8405d1abe24fb942
uNIST SP800-17 B.1 #52
u0000000000000400
e643d78090ca4207
uNIST SP800-17 B.1 #53
u0000000000000200
u48221b9937748a23
uNIST SP800-17 B.1 #54
u0000000000000100
dd7c0bbd61fafd54
uNIST SP800-17 B.1 #55
u0000000000000080
u2fbc291a570db5c4
uNIST SP800-17 B.1 #56
u0000000000000040
e07c30d7e4e26e12
uNIST SP800-17 B.1 #57
u0000000000000020
u0953e2258e8e90a1
uNIST SP800-17 B.1 #58
u0000000000000010
u5b711bc4ceebf2ee
uNIST SP800-17 B.1 #59
u0000000000000008
cc083f1e6d9e85f6
uNIST SP800-17 B.1 #60
u0000000000000004
d2fd8867d50d2dfe
uNIST SP800-17 B.1 #61
u0000000000000002
u06e7ea22ce92708f
uNIST SP800-17 B.1 #62
u0000000000000001
u166b40b44aba4bd6
uNIST SP800-17 B.1 #63
u95a8d72813daa94d
u8001010101010101
uNIST SP800-17 B.2 #0
u0eec1487dd8c26d5
u4001010101010101
uNIST SP800-17 B.2 #1
u7ad16ffb79c45926
u2001010101010101
uNIST SP800-17 B.2 #2
d3746294ca6a6cf3
u1001010101010101
uNIST SP800-17 B.2 #3
u809f5f873c1fd761
u0801010101010101
uNIST SP800-17 B.2 #4
c02faffec989d1fc
u0401010101010101
uNIST SP800-17 B.2 #5
u4615aa1d33e72f10
u0201010101010101
uNIST SP800-17 B.2 #6
u2055123350c00858
u0180010101010101
uNIST SP800-17 B.2 #7
df3b99d6577397c8
u0140010101010101
uNIST SP800-17 B.2 #8
u31fe17369b5288c9
u0120010101010101
uNIST SP800-17 B.2 #9
dfdd3cc64dae1642
u0110010101010101
uNIST SP800-17 B.2 #10
u178c83ce2b399d94
u0108010101010101
uNIST SP800-17 B.2 #11
u50f636324a9b7f80
u0104010101010101
uNIST SP800-17 B.2 #12
a8468ee3bc18f06d
u0102010101010101
uNIST SP800-17 B.2 #13
a2dc9e92fd3cde92
u0101800101010101
uNIST SP800-17 B.2 #14
cac09f797d031287
u0101400101010101
uNIST SP800-17 B.2 #15
u90ba680b22aeb525
u0101200101010101
uNIST SP800-17 B.2 #16
ce7a24f350e280b6
u0101100101010101
uNIST SP800-17 B.2 #17
u882bff0aa01a0b87
u0101080101010101
uNIST SP800-17 B.2 #18
u25610288924511c2
u0101040101010101
uNIST SP800-17 B.2 #19
c71516c29c75d170
u0101020101010101
uNIST SP800-17 B.2 #20
u5199c29a52c9f059
u0101018001010101
uNIST SP800-17 B.2 #21
c22f0a294a71f29f
u0101014001010101
uNIST SP800-17 B.2 #22
ee371483714c02ea
u0101012001010101
uNIST SP800-17 B.2 #23
a81fbd448f9e522f
u0101011001010101
uNIST SP800-17 B.2 #24
u4f644c92e192dfed
u0101010801010101
uNIST SP800-17 B.2 #25
u1afa9a66a6df92ae
u0101010401010101
uNIST SP800-17 B.2 #26
b3c1cc715cb879d8
u0101010201010101
uNIST SP800-17 B.2 #27
u19d032e64ab0bd8b
u0101010180010101
uNIST SP800-17 B.2 #28
u3cfaa7a7dc8720dc
u0101010140010101
uNIST SP800-17 B.2 #29
b7265f7f447ac6f3
u0101010120010101
uNIST SP800-17 B.2 #30
u9db73b3c0d163f54
u0101010110010101
uNIST SP800-17 B.2 #31
u8181b65babf4a975
u0101010108010101
uNIST SP800-17 B.2 #32
u93c9b64042eaa240
u0101010104010101
uNIST SP800-17 B.2 #33
u5570530829705592
u0101010102010101
uNIST SP800-17 B.2 #34
u8638809e878787a0
u0101010101800101
uNIST SP800-17 B.2 #35
u41b9a79af79ac208
u0101010101400101
uNIST SP800-17 B.2 #36
u7a9be42f2009a892
u0101010101200101
uNIST SP800-17 B.2 #37
u29038d56ba6d2745
u0101010101100101
uNIST SP800-17 B.2 #38
u5495c6abf1e5df51
u0101010101080101
uNIST SP800-17 B.2 #39
ae13dbd561488933
u0101010101040101
uNIST SP800-17 B.2 #40
u024d1ffa8904e389
u0101010101020101
uNIST SP800-17 B.2 #41
d1399712f99bf02e
u0101010101018001
uNIST SP800-17 B.2 #42
u14c1d7c1cffec79e
u0101010101014001
uNIST SP800-17 B.2 #43
u1de5279dae3bed6f
u0101010101012001
uNIST SP800-17 B.2 #44
e941a33f85501303
u0101010101011001
uNIST SP800-17 B.2 #45
da99dbbc9a03f379
u0101010101010801
uNIST SP800-17 B.2 #46
b7fc92f91d8e92e9
u0101010101010401
uNIST SP800-17 B.2 #47
ae8e5caa3ca04e85
u0101010101010201
uNIST SP800-17 B.2 #48
u9cc62df43b6eed74
u0101010101010180
uNIST SP800-17 B.2 #49
d863dbb5c59a91a0
u0101010101010140
uNIST SP800-17 B.2 #50
a1ab2190545b91d7
u0101010101010120
uNIST SP800-17 B.2 #51
u0875041e64c570f7
u0101010101010110
uNIST SP800-17 B.2 #52
u5a594528bebef1cc
u0101010101010108
uNIST SP800-17 B.2 #53
fcdb3291de21f0c0
u0101010101010104
uNIST SP800-17 B.2 #54
u869efd7f9f265a09
u0101010101010102
uNIST SP800-17 B.2 #55
aTestCase
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
