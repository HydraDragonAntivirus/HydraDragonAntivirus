# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.serialization.pkcs7

a__qualname__
uAdd text/plain MIME type
uDon't translate input data into canonical MIME format
uDon't embed data in the PKCS7 structure
uDon't embed SMIME capabilities
uDon't embed authenticatedAttributes
uDon't embed signer certificate
aNoCerts
a__orig_bases__
a__init__
uPKCS7SignatureBuilder.__init__
set_data
uPKCS7SignatureBuilder.set_data
D arsa_padding
naadd_signer
uPKCS7SignatureBuilder.add_signer
add_certificate
uPKCS7SignatureBuilder.add_certificate
T nasign
uPKCS7SignatureBuilder.sign
D a_data
a_recipients
a_content_encryption_algorithm
nnnuPKCS7EnvelopeBuilder.__init__
uPKCS7EnvelopeBuilder.set_data
add_recipient
uPKCS7EnvelopeBuilder.add_recipient
set_content_encryption_algorithm
uPKCS7EnvelopeBuilder.set_content_encryption_algorithm
encrypt
uPKCS7EnvelopeBuilder.encrypt
decrypt_der
pkcs7_decrypt_der
decrypt_pem
pkcs7_decrypt_pem
decrypt_smime
pkcs7_decrypt_smime
a_smime_signed_encode
a_smime_enveloped_encode
a_smime_enveloped_decode
a_smime_remove_text_headers
uOpenSSLMimePart._write_headers
ucryptography\hazmat\primitives\serialization\pkcs7.py
T a.0
opt
T a.0
wxu<module cryptography.hazmat.primitives.serialization.pkcs7>
T a__class__
T aself
a_data
a_recipients
a_content_encryption_algorithm
ossl
T aself
data
signers
additional_certs
T adata
wmT adata
wmacontent_type
T	adata
signature
micalg
text_mode
wmamsg_part
sig_part
fp
wgT aself
generator
T aself
certificate
T aself
certificate
private_key
hash_algorithm
rsa_padding
T aself
encoding
options
content_encryption_algorithm
T aself
content_encryption_algorithm
T aself
data
T aself
encoding
options
backend
.cryptography.hazmat.primitives.serialization.ssh
3
E aUnsupportedAlgorithm
T uNeed bcrypt module
ec
aEllipticCurvePrivateKey
a_ecdsa_key_type
public_key
aEllipticCurvePublicKey
rsa
aRSAPrivateKey
aRSAPublicKey
a_SSH_RSA
dsa
aDSAPrivateKey
aDSAPublicKey
a_SSH_DSA
ed25519
aEd25519PrivateKey
aEd25519PublicKey
a_SSH_ED25519
uUnsupported key type
curve
name
a_ECDSA_KEY_TYPE
uUnsupported curve for ssh private key:

c
a_base64_encode
l
uCorrupt data: missing padding
uCorrupt data: unparsed data
uKey is password-protected, but password was not provided.
a_SSH_CIPHERS
a_bcrypt_kdf
key_len
iv_len
aCipher
alg
mode
uInvalid data
from_bytes
:nl nD abyteorder
big
:l nn:nl n:l nna_get_u32
utoo many values to unpack (expected 2)
a_get_sshstr
l abig
unegative mpint not allowed
bit_length
l autils
int_to_bytes
flist
extend
append
to_bytes
T l abig
T alength
byteorder
T l abig
T Obytes
Omemoryview
Obytearray
put_u32
size
put_sshstr
a_to_mpint
len
pos
dstbuf
render
tobytes
a_get_mpint
get_public
aRSAPublicNumbers
uCorrupt data: rsa field mismatch
rsa_crt_dmp1
rsa_crt_dmq1
aRSAPrivateNumbers
private_key
T aunsafe_skip_rsa_key_validation
public_numbers
put_mpint
wewnaprivate_numbers
wdaiqmp
wpwqutoo many values to unpack (expected 4)
aDSAParameterNumbers
aDSAPublicNumbers
a_validate
uCorrupt data: dsa field mismatch
aDSAPrivateNumbers
parameter_numbers
wgwyaencode_public
wxl  uSSH supports only 1024 bit DSA keys
ssh_curve_name
uCurve name mismatch
l uNeed uncompressed point
from_encoded_point
uCorrupt data: ecdsa field mismatch
derive_private_key
public_bytes
aEncoding
aX962
aPublicFormat
aUncompressedPoint
private_value
utoo many values to unpack (expected 1)
from_public_bytes
:nl n:l nnuCorrupt data: ed25519 field mismatch
from_private_bytes
aRaw
private_bytes
aPrivateFormat
aNoEncryption
a_FragList
startswith
T cssh:
uU2F application string does not start with b'ssh:' (
w)a_lookup_kformat
load_public
load_application
T usk-ssh-ed25519 private keys cannot be loaded
a_ECDSA_NISTP256
T usk-ecdsa-sha2-nistp256 private keys cannot be loaded
a_KEY_FORMATS
uUnsupported key type:
a_check_byteslike
data
a_check_bytes
password
a_PEM_RC
search
uNot OpenSSH private key format
start
T l aend
binascii
a2b_base64
a_SK_MAGIC
l uOnly one key supported
a_check_empty
a_NONE
uUnsupported cipher:
a_BCRYPT
uUnsupported KDF:
block_len
tag_len
is_aead
uCorrupt data: invalid tag length for cipher
a_check_block_size
a_init_cipher
decryptor
update
finalize_with_tag
tag
finalize
uPassword was given but private key is not encrypted.
edata
uCorrupt data: broken checksum
uCorrupt data: key type mismatch
load_private
a_PADDING
uCorrupt data: invalid padding
warnings
warn
uSSH DSA keys are deprecated and will be removed in a future release.
aDeprecatedIn40
D astacklevel
l uSSH DSA key support is deprecated and will be removed in a future release
D astacklevel
l a_get_ssh_key_type
a_DEFAULT_CIPHER
a_DEFAULT_ROUNDS
a_KeySerializationEncryption
a_kdf_rounds
urandom
T l T l aencode_private
T c
put_raw
ciphername
encryptor
update_into
a_ssh_pem_encode
a_nonce
a_public_key
a_serial
aSSHCertificateType
a_type
uInvalid certificate type
a_key_id
a_valid_principals
a_valid_after
a_valid_before
a_critical_options
a_extensions
a_sig_type
a_sig_key
a_inner_sig_type
a_signature
a_cert_key_type
a_cert_body
a_tbs_cert_body
cast
aSSHCertPublicKeyTypes
d ab2a_base64
D anewline
Fasignature_key
verify
asym_utils
encode_dss_signature
a_get_ec_hash_alg
aECDSA
hashes
aSHA1
a_SSH_RSA_SHA256
aSHA256
aSHA512
padding
aPKCS1v15
aSECP256R1
aSECP384R1
aSHA384
a_SSH_PUBKEY_RC
match
uInvalid line format
group
T l aendswith
a_CERT_SUFFIX
key_type
T uDSA keys aren't supported in SSH certificates
aError
uInvalid format
uInvalid key format
a_get_u64
principals
valid_principals
a_parse_exts_opts
T uDSA signatures aren't supported in SSH certificates
cert_body
a_SSH_RSA_SHA512
uSignature key type does not match
aSSHCertificate
nonce
a_load_ssh_public_identity
exts_opts
result
uDuplicate name
last_name
uFields not lexically sorted
uUnexpected extra data after value
value
aMD5
uhash_algorithm must be either MD5 or SHA256
aHash
D a_legacy_dsa_allowed
tastrip
a_valid_for_all_principals
upublic_key already set
aSSHCertificateBuilder
T
a_public_key
a_serial
a_type
a_key_id
a_valid_principals
a_valid_for_all_principals
a_valid_before
a_valid_after
a_critical_options
a_extensions
userial must be an integer
g
userial must be between 0 and 2**64
userial already set
utype must be an SSHCertificateType
utype already set
ukey_id must be bytes
ukey_id already set
uPrincipals can't be set because the cert is valid for all principals
uprincipals must be a list of bytes and can't be empty
uvalid_principals already set
a_SSHKEY_CERT_MAX_PRINCIPALS
uReached or exceeded the maximum number of valid_principals
u<genexpr>
uSSHCertificateBuilder.valid_principals.<locals>.<genexpr>
uvalid_principals already set, can't set valid_for_all_principals
uvalid_for_all_principals already set
T Oint
Ofloat
uvalid_before must be an int or float
uvalid_before must [0, 2**64)
uvalid_before already set
uvalid_after must be an int or float
uvalid_after must [0, 2**64)
uvalid_after already set
uname and value must be bytes
uDuplicate critical option name
uDuplicate extension name
uUnsupported private key type
upublic_key must be set
utype must be set
uvalid_principals must be set if valid_for_all_principals is False
uvalid_before must be set
uvalid_after must be set
uvalid_after must be earlier than valid_before
sort
u<lambda>
uSSHCertificateBuilder.sign.<locals>.<lambda>
T akey
T l aput_u64
fprincipals
fcrit
fext
sign
decode_dss_signature
load_ssh_public_identity
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
enum
os
re
typing
base64
T aencodebytes
encodebytes
dataclasses
T adataclass
dataclass
cryptography
T autils
ucryptography.exceptions
T aUnsupportedAlgorithm
ucryptography.hazmat.primitives
T ahashes
ucryptography.hazmat.primitives.asymmetric
T adsa
ec
ed25519
padding
rsa
ucryptography.hazmat.primitives.ciphers
T aAEADDecryptionContext
aCipher
algorithms
modes
aAEADDecryptionContext
algorithms
modes
ucryptography.hazmat.primitives.serialization
T aEncoding
aKeySerializationEncryption
aNoEncryption
aPrivateFormat
aPublicFormat
a_KeySerializationEncryption
aKeySerializationEncryption
bcrypt
T akdf
kdf
a_bcrypt_supported
T Fcssh-ed25519
cssh-rsa
cssh-dss
cecdsa-sha2-nistp256
cecdsa-sha2-nistp384
a_ECDSA_NISTP384
cecdsa-sha2-nistp521
a_ECDSA_NISTP521
c-cert-v01@openssh.com
csk-ssh-ed25519@openssh.com
a_SK_SSH_ED25519
csk-ecdsa-sha2-nistp256@openssh.com
a_SK_SSH_ECDSA_NISTP256
crsa-sha2-256
crsa-sha2-512
compile
T c\A(\S+)[ \t]+(\S+)
b openssh-key-v1
c-----BEGIN OPENSSH PRIVATE KEY-----
a_SK_START
c-----END OPENSSH PRIVATE KEY-----
a_SK_END
cbcrypt
cnone
caes256-ctr
l c(.*?)
aDOTALL
B
