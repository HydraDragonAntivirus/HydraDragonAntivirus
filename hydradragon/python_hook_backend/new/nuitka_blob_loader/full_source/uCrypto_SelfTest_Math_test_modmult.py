# Reconstructed from integrated Nuitka blob
# Module: uCrypto.SelfTest.Math.test_modmult

a__qualname__
a__orig_bases__
gC                  e                                                              ;                                                                                                 -                                      b       %             `                                                                                aTestCase
test_small
uTestModMultiply.test_small
test_large
uTestModMultiply.test_large
test_zero_term
uTestModMultiply.test_zero_term
test_larger_term
uTestModMultiply.test_larger_term
get_tests
uCrypto\SelfTest\Math\test_modmult.py
u<module Crypto.SelfTest.Math.test_modmult>
T a__class__
T aconfig
tests
T	aterm1
term2
modulus
modulus_b
numbers_len
term1_b
term2_b
out
error
T aself
numbers_len
t1
t2
expect
T aself
t1
expect_int
res
T aself
T aself
numbers_len
expect

a__spec__
.Crypto.SelfTest.Protocol
$
uCrypto.SelfTest.Protocol
T atest_rfc1751
test_rfc1751
get_tests
T aconfig
T atest_KDF
test_KDF
T atest_ecdh
test_ecdh
T atest_SecretSharing
test_SecretSharing
uSelf-test for Crypto.Protocol
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
uSelfTest\Protocol
T aNUITKA_PACKAGE_Crypto_SelfTest
u\not_existing
aProtocol
T aNUITKA_PACKAGE_Crypto_SelfTest_Protocol
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
u$Id$
a__revision__
uCrypto\SelfTest\Protocol\__init__.py
u<module Crypto.SelfTest.Protocol>
T aconfig
tests
test_rfc1751
test_KDF
test_ecdh
test_SecretSharing

a__spec__
.Crypto.SelfTest.Protocol.test_KDF
*I
replace
T w u
T w

unhexlify
wba_testData
aPBKDF1
t2b
l l aSHA1
assertEqual
l aprf_SHA1
uPBKDF2_Tests.test1.<locals>.prf_SHA1
prf_SHA256
uPBKDF2_Tests.test1.<locals>.prf_SHA256
self
l aPBKDF2
aHMAC
new
digest
aSHA256
uPBKDF2_Tests.test2.<locals>.prf_SHA1
assertRaises
T axxx
T ayyy
l ldT aprf
hmac_hash_module
aMD5
aSHA224
aSHA384
aSHA512
password
salt
u<lambda>
uPBKDF2_Tests.test3.<locals>.<lambda>
T aprf
T ahmac_hash_module
hashmod
xxx
l
yyy
a_S2V
s2v
update
derive
uVerify correctness of test vector
bchr
T l
l T l  aAES
aDES3
key
block_size
T aXX
T aYY
uVerify that no more than 127(AES) and 63(TDES)
components are accepted.
a_test_vector
T l l l l T l l
aHKDF
T aXXXXXX
l T aYYYY
l :nl n:l nn:nl n:l l n:l nnadata
aTestVector
wPwSwNwrwpaoutput
dkLen
new_test_vectors
scrypt
u 2
l  @awarnings
warn
uNot enough memory to unit test scrypt() with N=1048576
aRuntimeWarning
T apassword
T asalt
bcrypt
c1111111111111111111111111111111111111111111111111111111111111111111111111
c1111111111
l D asalt
c
D asalt
d1D asalt
c11111111111111111
b 1
1
1
1
1
1
1
1
1
1
T apwd
l abcrypt_check
pwd
:nq ndx:l nnL T c
l czVHmKQtGGQob.b/Nc7l9NO
c$2a$04$zVHmKQtGGQob.b/Nc7l9NO8UlrYcW05FiuCj/SxsFO/ZtiN9.mNzy
T c
l czVHmKQtGGQob.b/Nc7l9NO
c$2a$05$zVHmKQtGGQob.b/Nc7l9NOWES.1hkVBgy5IWImh9DOjKNU8atY4Iy
T c
l czVHmKQtGGQob.b/Nc7l9NO
c$2a$06$zVHmKQtGGQob.b/Nc7l9NOjOl7l4oz3WSh5fJ6414Uw8IXRAUoiaO
T c
l czVHmKQtGGQob.b/Nc7l9NO
c$2a$07$zVHmKQtGGQob.b/Nc7l9NOBsj1dQpBA1HYNGpIETIByoNX9jc.hOi
T c
l czVHmKQtGGQob.b/Nc7l9NO
c$2a$08$zVHmKQtGGQob.b/Nc7l9NOiLTUh/9MDpX86/DLyEzyiFjqjBFePgO
a_bcrypt_decode
L T c<.S.2K(Zq'
l cVYAclAMpaXY/oqAo9yUpku
c$2a$04$VYAclAMpaXY/oqAo9yUpkuWmoYywaPzyhu56HxXpVltnBIfmO9tgu
T c5.rApO%5jA
l ckVNDrnYKvbNr5AIcxNzeIu
c$2a$05$kVNDrnYKvbNr5AIcxNzeIuRcyIF5cZk6UrwHGxENbxP5dVv.WQM/G
T coW++kSrQW^
l cQLKkRMH9Am6irtPeSKN5sO
c$2a$06$QLKkRMH9Am6irtPeSKN5sObJGr3j47cO6Pdf5JZ0AsJXuze0IbsNm
T cggJ\KbTnDG
l c4H896R09bzjhapgCPS/LYu
c$2a$07$4H896R09bzjhapgCPS/LYuMzAQluVgR5iu/ALF8L8Aln6lzzYXwbq
T c49b0:;VkH/
l chfvO2retKrSrx5f2RXikWe
c$2a$08$hfvO2retKrSrx5f2RXikWeFWdtSesPlbj08t/uXxCeZoHRWDz/xFe
T c>9N^5jc##'
l	cXZLvl7rMB3EvM0c1.JHivu
c$2a$09$XZLvl7rMB3EvM0c1.JHivuIDPJWeNJPTVrpjZIEVRYYB/mF6cYgJK
T c\$ch)s4WXp
l
caIjpMOLK5qiS9zjhcHR5TO
c$2a$10$aIjpMOLK5qiS9zjhcHR5TOU7v2NFDmcsBmSFDt5EHOgp/jeTF3O/q
T cRYoj\_>2P7
l cesIAHiQAJNNBrsr5V13l7.
c$2a$12$esIAHiQAJNNBrsr5V13l7.RFWWJI2BZFtQlkFyiWXjou05GyuREZa
L T c^Q&"]A`%/A(BVGt>QaX0M-#<Q148&f
l cvrRP5vQxyD4LrqiLd/oWRO
c$2a$04$vrRP5vQxyD4LrqiLd/oWROgrrGINsw3gb4Ga5x2sn01jNmiLVECl6
T cnZa!rRf\U;OL;R?>1ghq_+":Y0CRmY
l cYuQvhokOGVnevctykUYpKu
c$2a$05$YuQvhokOGVnevctykUYpKutZD2pWeGGYn3auyLOasguMY3/0BbIyq
T cF%uN/j>[GuB7-jB'_Yj!Tnb7Y!u^6)
l c5L3vpQ0tG9O7k5gQ8nAHAe
c$2a$06$5L3vpQ0tG9O7k5gQ8nAHAe9xxQiOcOLh8LGcI0PLWhIznsDt.S.C6
T cZ>BobP32ub"Cfe*Q<<WUq3rc=[GJr-
l chp8IdLueqE6qFh1zYycUZ.
c$2a$07$hp8IdLueqE6qFh1zYycUZ.twmUH8eSTPQAEpdNXKMlwms9XfKqfea
T cIk&8N['7*[1aCc1lOm8\jWeD*H$eZM
l c2ANDTYCB9m7vf0Prh7rSru
c$2a$08$2ANDTYCB9m7vf0Prh7rSrupqpO3jJOkIz2oW/QHB4lCmK7qMytGV6
T cO)=%3[E$*q+>-q-=tRSjOBh8\mLNW.
l	cnArqOfdCsD9kIbVnAixnwe
c$2a$09$nArqOfdCsD9kIbVnAixnwe6s8QvyPYWtQBpEXKir2OJF9/oNBsEFe
T c/MH51`!BP&0tj3%YCA;Xk%e3S`o\EI
l
cePiAc.s.yoBi3B6p1iQUCe
c$2a$10$ePiAc.s.yoBi3B6p1iQUCezn3mraLwpVJ5XGelVyYFKyp5FZn/y.u
T cptAP"mcg6oH.";c0U2_oll.OKi<!ku
l caroG/pwwPj1tU5fl9a9pkO
c$2a$12$aroG/pwwPj1tU5fl9a9pkO4rydAmkXRj/LqfHZOSnR6LGAZ.z.jwa
T cQ/A:k3DP;X@=<0"hg&9c
l cwbgDTvLMtyjQlNK7fjqwyO
c$2a$04$wbgDTvLMtyjQlNK7fjqwyOakBoACQuYh11.VsKNarF4xUIOBWgD6S
T cQ/A:k3DP;X@=<0"hg&9c
l czbAaOmloOhxiKItjznRqru
c$2a$05$zbAaOmloOhxiKItjznRqrunRqHlu3MAa7pMGv26Rr3WwyfGcwoRm6
T cQ/A:k3DP;X@=<0"hg&9c
l caOK0bWUvLI0qLkc3ti5jyu
c$2a$06$aOK0bWUvLI0qLkc3ti5jyuAIQoqRzuqoK09kQqQ6Ou/YKDhW50/qa
L T co<&+X'F4AQ8H,LU,N`&r
l cBK5u.QHk1Driey7bvnFTH.
c$2a$04$BK5u.QHk1Driey7bvnFTH.3smGwxd91PtoK2GxH5nZ7pcBsYX4lMq
T co<&+X'F4AQ8H,LU,N`&r
l cBK5u.QHk1Driey7bvnFTH.
c$2a$05$BK5u.QHk1Driey7bvnFTH.t5P.jZvFBMzDB1IY4PwkkRPOyVbEtFG
T co<&+X'F4AQ8H,LU,N`&r
l cBK5u.QHk1Driey7bvnFTH.
c$2a$06$BK5u.QHk1Driey7bvnFTH.6Ea1Z5db2p25CPXZbxb/3OyKQagg3pa
T co<&+X'F4AQ8H,LU,N`&r
l cBK5u.QHk1Driey7bvnFTH.
c$2a$07$BK5u.QHk1Driey7bvnFTH.sruuQi8Lhv/0LWKDvNp3AGFk7ltdkm6
T co<&+X'F4AQ8H,LU,N`&r
l cBK5u.QHk1Driey7bvnFTH.
c$2a$08$BK5u.QHk1Driey7bvnFTH.IE7KsaUzc4m7gzAMlyUPUeiYyACWe0q
T co<&+X'F4AQ8H,LU,N`&r
l	cBK5u.QHk1Driey7bvnFTH.
c$2a$09$BK5u.QHk1Driey7bvnFTH.1v4Xj1dwkp44QNg0cVAoQt4FQMMrvnS
T co<&+X'F4AQ8H,LU,N`&r
l
cBK5u.QHk1Driey7bvnFTH.
c$2a$10$BK5u.QHk1Driey7bvnFTH.ESINe9YntUMcVgFDfkC.Vbhc9vMhNX2
T co<&+X'F4AQ8H,LU,N`&r
l cBK5u.QHk1Driey7bvnFTH.
c$2a$12$BK5u.QHk1Driey7bvnFTH.QM1/nnGe/f5cTzb6XTTi/vMzcAnycqG
T cg*3Q45="8NNgpT&mbMJ$Omfr.#ZeW?FP=CE$#roHd?97uL0F-]`?u73c"\[."*)qU34@VG
l cT2XJ5MOWvHQZRijl8LIKkO
c$2a$04$T2XJ5MOWvHQZRijl8LIKkOQKIyX75KBfuLsuRYOJz5OjwBNF2lM8a
T c\M+*8;&QE=Ll[>5?Ui"^ai#iQH7ZFtNMfs3AROnIncE9"BNNoEgO[[*Yk8;RQ(#S,;I+aT
l cwgkOlGNXIVE2fWkT3gyRoO
c$2a$05$wgkOlGNXIVE2fWkT3gyRoOqWi4gbi1Wv2Q2Jx3xVs3apl1w.Wtj8C
T cM.E1=dt<.L0Q&p;94NfGm_Oo23+Kpl@M5?WIAL.[@/:'S)W96G8N^AWb7_smmC]>7#fGoB
l cW9zTCl35nEvUukhhFzkKMe
c$2a$06$W9zTCl35nEvUukhhFzkKMekjT9/pj7M0lihRVEZrX3m8/SBNZRX7i
L T dal c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.l4WvgHIVg17ZawDIrDM2IjlE64GDNQS
T caa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.AyUxBk.ThHlsLvRTH7IqcG7yVHJ3SXq
T caaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.BxOVac5xPB6XFdRc/ZrzM9FgZkqmvbW
T caaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.Qbr209bpCtfl5hN7UQlG/L4xiD3AKau
T caaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.oWszihPjDZI0ypReKsaDOW1jBl7oOii
T caaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ./k.Xxn9YiqtV/sxh3EHbnOHd0Qsq27K
T caaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.PYJqRFQbgRbIjMd5VNKmdKS4sBVOyDe
T caaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ..VMYfzaw1wP/SGxowpLeGf13fxCCt.q
T caaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.5B0p054nO5WgAD1n04XslDY/bqY9RJi
T caaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.INBTgqm7sdlBJDg.J5mLMSRK25ri04y
T caaaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.s3y7CdFD0OR5p6rsZw/eZ.Dla40KLfm
T caaaaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.Jx742Djra6Q7PqJWnTAS.85c28g.Siq
T caaaaaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.oKMXW3EZcPHcUV0ib5vDBnh9HojXnLu
T caaaaaaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.w6nIjWpDPNSH5pZUvLjC1q25ONEQpeS
T caaaaaaaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.k1b2/r9A/hxdwKEKurg6OCn4MwMdiGq
T caaaaaaaaaaaaaaaa
l c5DCebwootqWMCp59ISrMJ.
c$2a$04$5DCebwootqWMCp59ISrMJ.3prCNHVX1Ws.7Hm2bJxFUnQOX9f7DFa
L T u
l cD3qS2aoTVyqM7z8v8crLm.
c$2a$04$D3qS2aoTVyqM7z8v8crLm.3nKt4CzBZJbyFB.ZebmfCvRw7BGs.Xm
T u
l cVA1FujiOCMPkUHQ8kF7IaO
c$2a$05$VA1FujiOCMPkUHQ8kF7IaOg7NGaNvpxwWzSluQutxEVmbZItRTsAa
T u
l cTXiaNrPeBSz5ugiQlehRt.
c$2a$06$TXiaNrPeBSz5ugiQlehRt.gwpeDQnXWteQL4z2FulouBr6G7D9KUi
T u
l cYTn1Qlvps8e1odqMn6G5x.
c$2a$04$YTn1Qlvps8e1odqMn6G5x.85pqKql6w773EZJAExk7/BatYAI4tyO
T u
l cC.8k5vJKD2NtfrRI9o17DO
c$2a$05$C.8k5vJKD2NtfrRI9o17DOfIW0XnwItA529vJnh2jzYTb1QdoY0py
T u
l cxqfRPj3RYAgwurrhcA6uRO
c$2a$06$xqfRPj3RYAgwurrhcA6uROtGlXDp/U6/gkoDYHwlubtcVcNft5.vW
T u
l cy8vGgMmr9EdyxP9rmMKjH.
c$2a$04$y8vGgMmr9EdyxP9rmMKjH.wv2y3r7yRD79gykQtmb3N3zrwjKsyay
T u
l ciYH4XIKAOOm/xPQs7xKP1u
c$2a$05$iYH4XIKAOOm/xPQs7xKP1upD0cWyMn3Jf0ZWiizXbEkVpS41K1dcO
T u
l cwCOob.D0VV8twafNDB2ape
c$2a$06$wCOob.D0VV8twafNDB2apegiGD5nqF6Y1e6K95q6Y.R8C4QGd265q
T u
l cE5SQtS6P4568MDXW7cyUp.
c$2a$04$E5SQtS6P4568MDXW7cyUp.18wfDisKZBxifnPZjAI1d/KTYMfHPYO
T u
l c03e26gQFHhQwRNf81/ww9.
c$2a$04$03e26gQFHhQwRNf81/ww9.p1UbrNwxpzWjLuT.zpTLH4t/w5WhAhC
T u
l cPHNoJwpXCfe32nUtLv2Upu
c$2a$04$PHNoJwpXCfe32nUtLv2UpuhJXOzd4k7IdFwnEpYwfJVCZ/f/.8Pje
T u
l cwU4/0i1TmNl2u.1jIwBX.u
c$2a$04$wU4/0i1TmNl2u.1jIwBX.uZUaOL3Rc5ID7nlQRloQh6q5wwhV/zLW
T u
l cP4kreGLhCd26d4WIy7DJXu
c$2a$04$P4kreGLhCd26d4WIy7DJXusPkhxLvBouzV6OXkL5EB0jux0osjsry
L T u-O_=*N!2JP
l c......................
c$2a$04$......................JjuKLOX9OOwo5PceZZXSkaLDvdmgb82
T u7B[$Q<4b>U
l c......................
c$2a$05$......................DRiedDQZRL3xq5A5FL8y7/6NM8a2Y5W
T u>d5-I_8^.h
l c......................
c$2a$06$......................5Mq1Ng8jgDY.uHNU4h5p/x6BedzNH2W
T u)V`/UM/]1t
l c.OC/.OC/.OC/.OC/.OC/.O
c$2a$04$.OC/.OC/.OC/.OC/.OC/.OQIvKRDAam.Hm5/IaV/.hc7P8gwwIbmi
T u:@t2.bWuH]
l c.OC/.OC/.OC/.OC/.OC/.O
c$2a$05$.OC/.OC/.OC/.OC/.OC/.ONDbUvdOchUiKmQORX6BlkPofa/QxW9e
T ub(#KljF5s"
l c.OC/.OC/.OC/.OC/.OC/.O
c$2a$06$.OC/.OC/.OC/.OC/.OC/.OHfTd9e7svOu34vi1PCvOcAEq07ST7.K
T u@3YaJ^Xs]*
l ceGA.eGA.eGA.eGA.eGA.e.
c$2a$04$eGA.eGA.eGA.eGA.eGA.e.stcmvh.R70m.0jbfSFVxlONdj1iws0C
T u'"5\!k*C(p
l ceGA.eGA.eGA.eGA.eGA.e.
c$2a$05$eGA.eGA.eGA.eGA.eGA.e.vR37mVSbfdHwu.F0sNMvgn8oruQRghy
T uedEu7C?$'W
l ceGA.eGA.eGA.eGA.eGA.e.
c$2a$06$eGA.eGA.eGA.eGA.eGA.e.tSq0FN8MWHQXJXNFnHTPQKtA.n2a..G
T uN7dHmg\PI^
l c999999999999999999999u
c$2a$04$999999999999999999999uCZfA/pLrlyngNDMq89r1uUk.bQ9icOu
T u"eJuHh!)7*
l c999999999999999999999u
c$2a$05$999999999999999999999uj8Pfx.ufrJFAoWFLjapYBS5vVEQQ/hK
T uZeDRJ:_tu:
l c999999999999999999999u
c$2a$06$999999999999999999999u6RB0P9UmbdbQgjoQFEJsrvrKe.BoU6q
aTestCase
a__init__
a_wycheproof_warnings
aNone
a_id
filter_algo
uTestVectorsHKDFWycheproof.add_tests.<locals>.filter_algo
filter_size
uTestVectorsHKDFWycheproof.add_tests.<locals>.filter_size
load_test_vectors_wycheproof
T aProtocol
wycheproof
uWycheproof HMAC (%s)
hash_module
size
T aroot_tag
unit_tag
algorithm
uHKDF-SHA-1
uHKDF-SHA-256
uHKDF-SHA-384
uHKDF-SHA-512
uUnknown algorithm
tv
add_tests
T uhkdf_sha1_test.json
T uhkdf_sha256_test.json
T uhkdf_sha384_test.json
T uhkdf_sha512_test.json
warning
uWycheproof warning: %s (%s)
comment
uWycheproof HKDF Test #%d (%s, %s)
id
filename
ikm
info
valid
okm
test_verify
uCrypto.Hash.
hash_name
prf
uSP800_180_Counter_Tests.test_negative_zeroes.<locals>.prf
aSP800_108_Counter
c0000000000000000
D alabel
b A
Bafail
T uSP800_108_Counter failed with zero in label
D acontext
b A
BuSP800_180_Counter_Tests.test_multiple_keys.<locals>.prf
l  T l l l l c
expected
load_test_vectors
T aProtocol
uKDF_SP800_108_COUNTER.txt
uNIST SP 800 108 KDF Counter Mode
count
uadd_tests_sp800_108_counter.<locals>.<lambda>
re
match
u\[HMAC-(SHA-[0-9]+)\]
group
T l T w-u
load_hash_by_name
hmac
u\[CMAC-AES-128\]
cmac
mac_type
uadd_tests_sp800_108_counter.<locals>.prf
kin
label
context
kout
kdf_test
uadd_tests_sp800_108_counter.<locals>.kdf_test
utest_kdf_sp800_108_counter_%d
aCMAC
get
T awycheproof_warnings
T aslow_tests
aPBKDF2_Tests
:nl nascrypt_Tests
list_test_cases
aPBKDF1_Tests
aS2V_Tests
aHKDF_Tests
aTestVectorsHKDFWycheproof
bcrypt_Tests
aSP800_180_Counter_Tests
a__doc__
a__file__
origin
has_location
a__cached__
unittest
binascii
T aunhexlify
uCrypto.Util.py3compat
T wbabchr
uCrypto.SelfTest.st_common
T alist_test_cases
uCrypto.SelfTest.loader
T aload_test_vectors
load_test_vectors_wycheproof
uCrypto.Hash
T aSHA1
aHMAC
aSHA256
aMD5
aSHA224
aSHA384
aSHA512
uCrypto.Cipher
T aAES
aDES3
uCrypto.Protocol.KDF
T aPBKDF1
aPBKDF2
a_S2V
aHKDF
scrypt
bcrypt
bcrypt_check
aSP800_108_Counter
T a_bcrypt_decode
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
