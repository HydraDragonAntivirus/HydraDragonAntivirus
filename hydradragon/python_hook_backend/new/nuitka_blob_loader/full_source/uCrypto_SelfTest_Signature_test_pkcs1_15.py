# Reconstructed from integrated Nuitka blob
# Module: uCrypto.SelfTest.Signature.test_pkcs1_15

a__qualname__
uFIPS PKCS1 Tests (Verify)
shortDescription
uFIPS_PKCS1_Verify_Tests.shortDescription
test_can_sign
uFIPS_PKCS1_Verify_Tests.test_can_sign
a__orig_bases__
T aSignature
uPKCS1-v1.5
uSigVer15_186-3.rsp
uSignature Verification 186-3
shaalg
u<lambda>
wdaresult
test_vectors_verify
count
wnamodulus
upper
hash_obj
construct
weaverifier
wsapositive_test
negative_test
wfutest_negative_%d
utest_positive_%d
uFIPS PKCS1 Tests (Sign)
uFIPS_PKCS1_Sign_Tests.shortDescription
uFIPS_PKCS1_Sign_Tests.test_can_sign
uSigGen15_186-2.txt
uSignature Generation 186-2
test_vectors_sign
uSigGen15_186-3.txt
uSignature Generation 186-3
private_key
new_test
utest_%d
uVerify that PKCS#1 v1.5 signatures pass even without NULL parameters in
the algorithm identifier (PyCrypto/LP bug #1119552).
u-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAL8eJ5AKoIsjURpcEoGubZMxLD7+kT+TLr7UkvEtFrRhDDKMtuII
q19FrL4pUIMymPMSLBn3hJLe30Dw48GQM4UCAwEAAQJACUSDEp8RTe32ftq8IwG8
Wojl5mAd1wFiIOrZ/Uv8b963WJOJiuQcVN29vxU5+My9GPZ7RA3hrDBEAoHUDPrI
OQIhAPIPLz4dphiD9imAkivY31Rc5AfHJiQRA7XixTcjEkojAiEAyh/pJHks/Mlr
+rdPNEpotBjfV4M4BkgGAA/ipcmaAjcCIQCHvhwwKVBLzzTscT2HeUdEeBMoiXXK
JACAr3sJQJGxIQIgarRp+m1WSKV1MciwMaTOnbU7wxFs9DP1pva76lYBzgUCIQC9
n0CnZCJ6IZYqSt0H5N7+Q+2Ro64nuwV/OSQfM6sBwQ==
-----END RSA PRIVATE KEY-----
cThis is a test
a287a13517f716e72fb14eea8e33a8db4a4643314607e7ca3e3e281893db74013dda8b855fd99f6fecedcb25fcb7a434f35cd0a101f8b19348e0bd7b6f152dfc
sig_str
runTest
uPKCS1_15_NoParams.runTest
uVerify that the legacy module Crypto.Signature.PKCS1_v1_5
behaves as expected. The only difference is that the verify()
method returns True/False and does not raise exceptions.
uTest legacy Crypto.Signature.PKCS1_v1_5
uPKCS1_Legacy_Module_Tests.shortDescription
uPKCS1_Legacy_Module_Tests.runTest
uTest PKCS#1v1.5 signature in combination with all hashes
uPKCS1_All_Hashes_Tests.shortDescription
uPKCS1_All_Hashes_Tests.runTest
uTestVectorsWycheproof.__init__
setUp
uTestVectorsWycheproof.setUp
uTestVectorsWycheproof.add_tests
uTestVectorsWycheproof.shortDescription
uTestVectorsWycheproof.warn
uTestVectorsWycheproof.test_verify
uTestVectorsWycheproof.runTest
get_tests
uCrypto\SelfTest\Signature\test_pkcs1_15.py
T wxu<module Crypto.SelfTest.Signature.test_pkcs1_15>
T a__class__
T aself
wycheproof_warnings
T aself
filename
filter_rsa
filter_sha
filter_type
result
T agroup
T agroup
hash_name
T agroup
type_name
T aconfig
wycheproof_warnings
tests
T ahash_name
T aself
hash_obj
verifier
signature
T aself
hash_obj
signer
result
signature
T aself
verifier
hashed
T aself
key
signer
hash_names
name
hashed
aBLAKE2b
aBLAKE2s
hash_size
hashed_b
hashed_s
T aself
key
hashed
good_signature
verifier
bad_signature
T aself
tv
T aself
T aself
test_private_key
signer
T aself
test_public_key
verifier
T aself
tv
hashed_msg
signer
signature
weT aself
tv
warnings

a__spec__
.Crypto.SelfTest.Signature.test_pss
uCrypto.Hash.
hash_name
new
stream
idx
aRSA
import_key
rsa_key
aSHA256
msg
pss
verify
tag
dAaassertRaises
D asalt_bytes
l  aPRNG
T asalt_bytes
rand_func
generate
T l  apublic_key
assertEqual
can_sign
sign
aSHA1
wbT aTest
aPKCS1_PSS
strxor
bchr
T l T l
TaMD2
aMD4
aMD5
aRIPEMD160
aSHA1
aSHA224
aSHA256
aSHA384
aSHA512
aSHA3_224
aSHA3_256
aSHA3_384
aSHA3_512
load_hash_by_name
signer
uCrypto.Hash
T aBLAKE2b
aBLAKE2s
aBLAKE2b
aBLAKE2s
T l l l0l@T adigest_bytes
data
T l l l l uSHA-512
aSHA512
uSHA-512/224
T u224
T atruncate
uSHA-512/256
T u256
uSHA-384
aSHA384
uSHA-256
uSHA-224
aSHA224
uSHA-1
uUnknown hash algorithm:
aTestCase
a__init__
a_wycheproof_warnings
aNone
a_id
filter_rsa
uTestVectorsPSSWycheproof.add_tests.<locals>.filter_rsa
filter_sha
uTestVectorsPSSWycheproof.add_tests.<locals>.filter_sha
filter_type
uTestVectorsPSSWycheproof.add_tests.<locals>.filter_type
filter_slen
uTestVectorsPSSWycheproof.add_tests.<locals>.filter_slen
filter_mgf
uTestVectorsPSSWycheproof.add_tests.<locals>.filter_mgf
load_test_vectors_wycheproof
T aSignature
wycheproof
uWycheproof PSS signature (%s)
key
hash_module
sLen
mgf
type
T agroup_tag
keyPem
get_hash_module
sha
T aRsassaPssVerify
uUnknown type name
T aMGF1
uUnknown MGF
mgfSha
uTestVectorsPSSWycheproof.add_tests.<locals>.filter_mgf.<locals>.mgf
aMGF1
tv
add_tests
T ursa_pss_2048_sha1_mgf1_20_test.json
T ursa_pss_2048_sha256_mgf1_0_test.json
T ursa_pss_2048_sha256_mgf1_32_test.json
T ursa_pss_2048_sha512_256_mgf1_28_test.json
T ursa_pss_2048_sha512_256_mgf1_32_test.json
T ursa_pss_3072_sha256_mgf1_32_test.json
T ursa_pss_4096_sha256_mgf1_32_test.json
T ursa_pss_4096_sha512_mgf1_32_test.json
T ursa_pss_misc_test.json
warning
warnings
warn
uWycheproof warning: %s (%s)
comment
uWycheproof RSA PSS Test #%d (%s)
id
T amask_func
salt_bytes
sig
valid
self
test_verify
get
T awycheproof_warnings
list_test_cases
aPSS_Tests
aFIPS_PKCS1_Verify_Tests
aFIPS_PKCS1_Sign_Tests
aPKCS1_Legacy_Module_Tests
aPKCS1_All_Hashes_Tests
T aslow_tests
aFIPS_PKCS1_Verify_Tests_KAT
aFIPS_PKCS1_Sign_Tests_KAT
aTestVectorsPSSWycheproof
a__doc__
a__file__
origin
has_location
a__cached__
unittest
uCrypto.Util.py3compat
T wbabchr
uCrypto.Util.number
T abytes_to_long
bytes_to_long
uCrypto.Util.strxor
T astrxor
uCrypto.SelfTest.st_common
T alist_test_cases
uCrypto.SelfTest.loader
T aload_test_vectors
load_test_vectors_wycheproof
load_test_vectors
T aSHA1
aSHA224
aSHA256
aSHA384
aSHA512
uCrypto.PublicKey
T aRSA
uCrypto.Signature
T apss
T aPKCS1_PSS
uCrypto.Signature.pss
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
