# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.hashes

aHashAlgorithm
a__qualname__
property
abstractmethod
D areturn
str

A string naming this algorithm (e.g. "sha256", "md5").
name
uHashAlgorithm.name
D areturn
int

The size of the resulting digest in bytes.
digest_size
uHashAlgorithm.digest_size
D areturn
uint | None

The internal block size of the hash function, or None if the hash
function does not use blocks internally (e.g. SHA3).
block_size
uHashAlgorithm.block_size
T aHashContext
T
aHashContext
D areturn
aHashAlgorithm

A HashAlgorithm that will be used by this context.
algorithm
uHashContext.algorithm
D adata
return
bytes
aNone

Processes the provided bytes through the hash.
update
uHashContext.update
D areturn
bytes

Finalizes the hash context and returns the hash digest as bytes.
finalize
uHashContext.finalize
D areturn
aHashContext

Return a HashContext that is a copy of the current context.
copy
uHashContext.copy
hashes
aHash
register
T aExtendableOutputFunction
T

An interface for extendable output functions.
aExtendableOutputFunction
aSHA1
sha1
l a__orig_bases__
aSHA512_224
usha512-224
l l  aSHA512_256
usha512-256
aSHA224
sha224
aSHA256
sha256
aSHA384
sha384
l0aSHA512
sha512
aSHA3_224
usha3-224
aSHA3_256
usha3-256
aSHA3_384
usha3-384
aSHA3_512
usha3-512
aSHAKE128
shake128
D adigest_size
int
a__init__
uSHAKE128.__init__
uSHAKE128.digest_size
aSHAKE256
shake256
uSHAKE256.__init__
uSHAKE256.digest_size
aMD5
md5
l aBLAKE2b
blake2b
a_max_digest_size
a_min_digest_size
uBLAKE2b.__init__
uBLAKE2b.digest_size
aBLAKE2s
blake2s
uBLAKE2s.__init__
uBLAKE2s.digest_size
aSM3
sm3
ucryptography\hazmat\primitives\hashes.py
u<module cryptography.hazmat.primitives.hashes>
T a__class__
T aself
digest_size
T aself
T aself
data

a__spec__
.cryptography.hazmat.primitives.serialization.base
a__doc__
a__file__
origin
has_location
a__cached__
ucryptography.hazmat.bindings._rust
T aopenssl
openssl
rust_openssl
keys
load_pem_private_key
load_der_private_key
load_pem_public_key
load_der_public_key
dh
from_pem_parameters
load_pem_parameters
from_der_parameters
load_der_parameters
ucryptography\hazmat\primitives\serialization\base.py
u<module cryptography.hazmat.primitives.serialization.base>

a__spec__
.cryptography.hazmat.primitives.serialization
8
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_cryptography
u\not_existing
uhazmat\primitives\serialization
T aNUITKA_PACKAGE_cryptography_hazmat
u\not_existing
uprimitives\serialization
T aNUITKA_PACKAGE_cryptography_hazmat_primitives
u\not_existing
serialization
T aNUITKA_PACKAGE_cryptography_hazmat_primitives_serialization
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
annotations
ucryptography.hazmat.primitives._serialization
T aBestAvailableEncryption
aEncoding
aKeySerializationEncryption
aNoEncryption
aParameterFormat
aPrivateFormat
aPublicFormat
a_KeySerializationEncryption
aBestAvailableEncryption
aEncoding
aKeySerializationEncryption
aNoEncryption
aParameterFormat
aPrivateFormat
aPublicFormat
a_KeySerializationEncryption
ucryptography.hazmat.primitives.serialization.base
T aload_der_parameters
load_der_private_key
load_der_public_key
load_pem_parameters
load_pem_private_key
load_pem_public_key
load_der_parameters
load_der_private_key
load_der_public_key
load_pem_parameters
load_pem_private_key
load_pem_public_key
ucryptography.hazmat.primitives.serialization.ssh
T
aSSHCertificate
aSSHCertificateBuilder
aSSHCertificateType
aSSHCertPrivateKeyTypes
aSSHCertPublicKeyTypes
aSSHPrivateKeyTypes
aSSHPublicKeyTypes
load_ssh_private_key
load_ssh_public_identity
load_ssh_public_key
aSSHCertificate
aSSHCertificateBuilder
aSSHCertificateType
aSSHCertPrivateKeyTypes
aSSHCertPublicKeyTypes
aSSHPrivateKeyTypes
aSSHPublicKeyTypes
load_ssh_private_key
load_ssh_public_identity
load_ssh_public_key
L aBestAvailableEncryption
aEncoding
aKeySerializationEncryption
aNoEncryption
aParameterFormat
aPrivateFormat
aPublicFormat
aSSHCertPrivateKeyTypes
aSSHCertPublicKeyTypes
aSSHCertificate
aSSHCertificateBuilder
aSSHCertificateType
aSSHPrivateKeyTypes
aSSHPublicKeyTypes
a_KeySerializationEncryption
load_der_parameters
load_der_private_key
load_der_public_key
load_pem_parameters
load_pem_private_key
load_pem_public_key
load_ssh_private_key
load_ssh_public_identity
load_ssh_public_key
a__all__
ucryptography\hazmat\primitives\serialization\__init__.py
u<module cryptography.hazmat.primitives.serialization>

a__spec__
.cryptography.hazmat.primitives.serialization.ssh
ZJ
aUnsupportedAlgorithm
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

uReturn SSH key_type and curve_name for private key.
c
a_base64_encode
uCorrupt data: missing padding
uRequire data to be full blocks
uCorrupt data: unparsed data
uAll data should have been parsed.
uKey is password-protected.
a_SSH_CIPHERS
a_bcrypt_kdf
key_len
iv_len
aCipher
alg
mode
uGenerate key + iv and return cipher.
uInvalid data
from_bytes
:nl nD abyteorder
big
:l nnaUint32
:nl n:l nnaUint64
a_get_u32
uBytes with u32 length prefix
a_get_sshstr
l abig
uBig integer.
unegative mpint not allowed
bit_length
l autils
int_to_bytes
uStorage format for signed bigint.
flist
extend
append
uAdd plain bytes
to_bytes
T l abig
T alength
byteorder
uBig-endian uint32
T l abig
uBig-endian uint64
T Obytes
Omemoryview
Obytearray
put_u32
size
uBytes prefixed with u32 length
put_sshstr
a_to_mpint
uBig-endian bigint prefixed with u32 length
len
uCurrent number of bytes
pos
dstbuf
uWrite into bytearray
render
tobytes
uReturn as bytes
a_get_mpint
uRSA public fields
get_public
aRSAPublicNumbers
uMake RSA public key from data.
uCorrupt data: rsa field mismatch
rsa_crt_dmp1
rsa_crt_dmq1
aRSAPrivateNumbers
private_key
uMake RSA private key from data.
public_numbers
put_mpint
wewnuWrite RSA public key
private_numbers
wdaiqmp
wpwquWrite RSA private key
uDSA public fields
aDSAParameterNumbers
aDSAPublicNumbers
a_validate
uMake DSA public key from data.
uCorrupt data: dsa field mismatch
aDSAPrivateNumbers
uMake DSA private key from data.
parameter_numbers
wgwyuWrite DSA public key
encode_public
wxuWrite DSA private key
l  uSSH supports only 1024 bit DSA keys
ssh_curve_name
uCurve name mismatch
l uNeed uncompressed point
uECDSA public fields
from_encoded_point
uMake ECDSA public key from data.
uCorrupt data: ecdsa field mismatch
derive_private_key
uMake ECDSA private key from data.
public_bytes
aEncoding
aX962
aPublicFormat
aUncompressedPoint
uWrite ECDSA public key
private_value
uWrite ECDSA private key
uEd25519 public fields
from_public_bytes
uMake Ed25519 public key from data.
:nl n:l nnuCorrupt data: ed25519 field mismatch
from_private_bytes
uMake Ed25519 private key from data.
aRaw
uWrite Ed25519 public key
private_bytes
aPrivateFormat
aNoEncryption
a_FragList
uWrite Ed25519 private key
startswith
T cssh:
uU2F application string does not start with b'ssh:' (
w)u
U2F application strings
a_lookup_kformat
load_public
load_application
a_ECDSA_NISTP256
a_KEY_FORMATS
uUnsupported key type:
uReturn valid format or throw error
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
uOnly one key supported
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
aAEADDecryptionContext
finalize_with_tag
tag
finalize
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
l uLoad private key from OpenSSH custom encoding.
uSSH DSA key support is deprecated and will be removed in a future release
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
uSerialize private key with OpenSSH custom encoding.
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
a_SSH_RSA_SHA512
aSHA512
padding
aPKCS1v15
aSECP256R1
aSECP384R1
aSHA384
aSECP521R1
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
D a_legacy_dsa_allowed
tastrip
uOne-line public key format for OpenSSH
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
origin
has_location
a__cached__
a__annotations__
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
T FD apassword
salt
desired_key_bytes
rounds
ignore_few_rounds
return
bytes
paint
pabool
bytes
cssh-ed25519
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
