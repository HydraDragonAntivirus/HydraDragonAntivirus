# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.serialization.ssh

a_SSHCipher
a__qualname__
utype[algorithms.AES]
int
utype[modes.CTR] | type[modes.CBC] | type[modes.GCM]
uint | None
bool
aAES
l aCTR
T aalg
key_len
mode
block_len
iv_len
tag_len
is_aead
caes256-cbc
aCBC
caes256-gcm@openssh.com
aGCM
l udict[bytes, _SSHCipher]
secp256r1
secp384r1
secp521r1
D akey
return
uSSHPrivateKeyTypes | SSHPublicKeyTypes
bytes
D apublic_key
return
uec.EllipticCurvePublicKey
bytes
d
D adata
prefix
suffix
return
bytes
pppD adata
block_len
return
bytes
int
aNone
D adata
return
bytes
aNone
D aciphername
password
salt
rounds
return
bytes
ubytes | None
bytes
int
uCipher[modes.CBC | modes.CTR | modes.GCM]
D adata
return
memoryview
utuple[int, memoryview]
D adata
return
memoryview
utuple[memoryview, memoryview]
D aval
return
int
bytes
uBuild recursive structure without data copy.
ulist[bytes]
T nD ainit
return
ulist[bytes] | None
aNone
a__init__
u_FragList.__init__
D aval
return
bytes
aNone
u_FragList.put_raw
D aval
return
int
aNone
u_FragList.put_u32
u_FragList.put_u64
D aval
return
ubytes | _FragList
aNone
u_FragList.put_sshstr
u_FragList.put_mpint
D areturn
int
u_FragList.size
T l
D adstbuf
pos
return
memoryview
int
pu_FragList.render
D areturn
bytes
u_FragList.tobytes
uFormat for RSA keys.
Public:
mpint e, n
Private:
mpint n, e, d, iqmp, p, q
a_SSHFormatRSA
D adata
return
memoryview
utuple[tuple[int, int], memoryview]
u_SSHFormatRSA.get_public
D adata
return
memoryview
utuple[rsa.RSAPublicKey, memoryview]
u_SSHFormatRSA.load_public
D adata
return
memoryview
utuple[rsa.RSAPrivateKey, memoryview]
u_SSHFormatRSA.load_private
D apublic_key
f_pub
return
ursa.RSAPublicKey
a_FragList
aNone
u_SSHFormatRSA.encode_public
D aprivate_key
f_priv
return
ursa.RSAPrivateKey
a_FragList
aNone
u_SSHFormatRSA.encode_private
uFormat for DSA keys.
Public:
mpint p, q, g, y
Private:
mpint p, q, g, y, x
a_SSHFormatDSA
D adata
return
memoryview
utuple[tuple, memoryview]
u_SSHFormatDSA.get_public
D adata
return
memoryview
utuple[dsa.DSAPublicKey, memoryview]
u_SSHFormatDSA.load_public
D adata
return
memoryview
utuple[dsa.DSAPrivateKey, memoryview]
u_SSHFormatDSA.load_private
D apublic_key
f_pub
return
udsa.DSAPublicKey
a_FragList
aNone
u_SSHFormatDSA.encode_public
D aprivate_key
f_priv
return
udsa.DSAPrivateKey
a_FragList
aNone
u_SSHFormatDSA.encode_private
D apublic_numbers
return
udsa.DSAPublicNumbers
aNone
u_SSHFormatDSA._validate
uFormat for ECDSA keys.
Public:
str curve
bytes point
Private:
str curve
bytes point
mpint secret
a_SSHFormatECDSA
D assh_curve_name
curve
bytes
uec.EllipticCurve
u_SSHFormatECDSA.__init__
D adata
return
memoryview
utuple[tuple[memoryview, memoryview], memoryview]
u_SSHFormatECDSA.get_public
D adata
return
memoryview
utuple[ec.EllipticCurvePublicKey, memoryview]
u_SSHFormatECDSA.load_public
D adata
return
memoryview
utuple[ec.EllipticCurvePrivateKey, memoryview]
u_SSHFormatECDSA.load_private
D apublic_key
f_pub
return
uec.EllipticCurvePublicKey
a_FragList
aNone
u_SSHFormatECDSA.encode_public
D aprivate_key
f_priv
return
uec.EllipticCurvePrivateKey
a_FragList
aNone
u_SSHFormatECDSA.encode_private
uFormat for Ed25519 keys.
Public:
bytes point
Private:
bytes point
bytes secret_and_point
a_SSHFormatEd25519
D adata
return
memoryview
utuple[tuple[memoryview], memoryview]
u_SSHFormatEd25519.get_public
D adata
return
memoryview
utuple[ed25519.Ed25519PublicKey, memoryview]
u_SSHFormatEd25519.load_public
D adata
return
memoryview
utuple[ed25519.Ed25519PrivateKey, memoryview]
u_SSHFormatEd25519.load_private
D apublic_key
f_pub
return
ued25519.Ed25519PublicKey
a_FragList
aNone
u_SSHFormatEd25519.encode_public
D aprivate_key
f_priv
return
ued25519.Ed25519PrivateKey
a_FragList
aNone
u_SSHFormatEd25519.encode_private
D areturn
utuple[memoryview, memoryview]

The format of a sk-ssh-ed25519@openssh.com public key is:
string		"sk-ssh-ed25519@openssh.com"
string		public key
string		application (user-specified, but typically "ssh:")
a_SSHFormatSKEd25519
u_SSHFormatSKEd25519.load_public

The format of a sk-ecdsa-sha2-nistp256@openssh.com public key is:
string		"sk-ecdsa-sha2-nistp256@openssh.com"
string		curve name
ec_point	Q
string		application (user-specified, but typically "ssh:")
a_SSHFormatSKECDSA
u_SSHFormatSKECDSA.load_public
cnistp256
cnistp384
cnistp521
D akey_type
bytes
aUnion
aSSHPrivateKeyTypes
D adata
password
backend
return
bytes
ubytes | None
utyping.Any
aSSHPrivateKeyTypes
load_ssh_private_key
D aprivate_key
password
encryption_algorithm
return
aSSHPrivateKeyTypes
bytes
aKeySerializationEncryption
bytes
a_serialize_ssh_private_key
aSSHPublicKeyTypes
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
aUSER
l aHOST
a__orig_bases__
D a_nonce
a_public_key
a_serial
a_cctype
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
a_tbs_cert_body
a_cert_key_type
a_cert_body
memoryview
aSSHPublicKeyTypes
int
pamemoryview
ulist[bytes]
int
pudict[bytes, bytes]
udict[bytes, bytes]
memoryview
ppppabytes
memoryview
uSSHCertificate.__init__
uSSHCertificate.nonce
D areturn
aSSHCertPublicKeyTypes
uSSHCertificate.public_key
serial
uSSHCertificate.serial
D areturn
aSSHCertificateType
type
uSSHCertificate.type
key_id
uSSHCertificate.key_id
D areturn
ulist[bytes]
uSSHCertificate.valid_principals
valid_before
uSSHCertificate.valid_before
valid_after
uSSHCertificate.valid_after
D areturn
udict[bytes, bytes]
critical_options
uSSHCertificate.critical_options
extensions
uSSHCertificate.extensions
uSSHCertificate.signature_key
uSSHCertificate.public_bytes
D areturn
aNone
verify_cert_signature
uSSHCertificate.verify_cert_signature
D acurve
return
uec.EllipticCurve
uhashes.HashAlgorithm
D adata
return
bytes
uSSHCertificate | SSHPublicKeyTypes
D aexts_opts
return
memoryview
udict[bytes, bytes]
D adata
backend
return
bytes
utyping.Any
aSSHPublicKeyTypes
load_ssh_public_key
D apublic_key
return
aSSHPublicKeyTypes
bytes
serialize_ssh_public_key
aSSHCertPrivateKeyTypes
l  D
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
uSSHCertPublicKeyTypes | None
uint | None
uSSHCertificateType | None
ubytes | None
ulist[bytes]
bool
uint | None
uint | None
ulist[tuple[bytes, bytes]]
ulist[tuple[bytes, bytes]]
uSSHCertificateBuilder.__init__
D apublic_key
return
aSSHCertPublicKeyTypes
aSSHCertificateBuilder
uSSHCertificateBuilder.public_key
D aserial
return
int
aSSHCertificateBuilder
uSSHCertificateBuilder.serial
D atype
return
aSSHCertificateType
aSSHCertificateBuilder
uSSHCertificateBuilder.type
D akey_id
return
bytes
aSSHCertificateBuilder
uSSHCertificateBuilder.key_id
D avalid_principals
return
ulist[bytes]
aSSHCertificateBuilder
uSSHCertificateBuilder.valid_principals
valid_for_all_principals
uSSHCertificateBuilder.valid_for_all_principals
D avalid_before
return
uint | float
aSSHCertificateBuilder
uSSHCertificateBuilder.valid_before
D avalid_after
return
uint | float
aSSHCertificateBuilder
uSSHCertificateBuilder.valid_after
D aname
value
return
bytes
paSSHCertificateBuilder
add_critical_option
uSSHCertificateBuilder.add_critical_option
add_extension
uSSHCertificateBuilder.add_extension
D aprivate_key
return
aSSHCertPrivateKeyTypes
aSSHCertificate
uSSHCertificateBuilder.sign
ucryptography\hazmat\primitives\serialization\ssh.py
T a.0
wxT wxu<module cryptography.hazmat.primitives.serialization.ssh>
T a__class__
T aself
a_nonce
a_public_key
a_serial
a_cctype
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
a_tbs_cert_body
a_cert_key_type
a_cert_body
T aself
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
T aself
init
T aself
ssh_curve_name
curve
T apassword
salt
desired_key_bytes
rounds
ignore_few_rounds
T adata
block_len
T adata
T apublic_key
curve
T acurve
T adata
val
T akey
key_type
T adata
wnT aciphername
password
salt
rounds
ciph
seed
T"adata
a_legacy_dsa_allowed
wmakey_type
orig_key_type
key_body
with_cert
kformat
rest
cert_body
inner_key_type
nonce
public_key
serial
cctype
key_id
principals
valid_principals
principal
valid_after
valid_before
crit_options
critical_options
exts
extensions
w_asig_key_raw
sig_type
sig_key
tbs_cert_body
signature_raw
inner_sig_type
sig_rest
signature
T akey_type
T aexts_opts
result
bname
last_name
name
value
extra
T aprivate_key
password
encryption_algorithm
key_type
kformat
f_kdfoptions
ciphername
blklen
kdfname
rounds
salt
ciph
nkeys
checkval
comment
f_public_key
f_secrets
f_main
slen
mlen
buf
ofs
T adata
prefix
suffix
T aval
nbytes
T aself
public_numbers
parameter_numbers
T aself
name
value
T aself
T aself
private_key
f_priv
T aself
private_key
f_priv
public_key
private_numbers
T aself
private_key
f_priv
public_key
raw_private_key
raw_public_key
f_keypair
T aself
private_key
f_priv
private_numbers
public_numbers
T aself
public_key
f_pub
public_numbers
parameter_numbers
T aself
public_key
f_pub
point
T aself
public_key
f_pub
raw_public_key
T aself
public_key
f_pub
pubn
T aself
data
wpwqwgwyT aself
data
curve
point
T aself
data
point
T aself
data
wewnT aself
key_id
T adata
application
T aself
data
pubfields
wpwqwgwywxaparameter_numbers
public_numbers
private_numbers
private_key
T aself
data
pubfields
curve_name
point
secret
private_key
T aself
data
pubfields
point
keypair
secret
point2
private_key
T aself
data
pubfields
wnwewdaiqmp
wpwqadmp1
dmq1
public_numbers
private_numbers
private_key
T	aself
data
wpwqwgwyaparameter_numbers
public_numbers
public_key
T aself
data
w_apoint
public_key
T aself
data
point
public_key
T aself
data
wewnapublic_numbers
public_key
T aself
data
public_key
w_T adata
password
backend
wmap1
p2
ciphername
kdfname
kdfoptions
nkeys
pubdata
pub_key_type
kformat
pubfields
ciphername_bytes
blklen
tag_len
edata
tag
salt
kbuf
rounds
ciph
dec
ck1
ck2
key_type
private_key
w_T adata
backend
public_key
cert_or_key
T aself
public_key
T aself
val
T aself
dstbuf
pos
frag
flen
start
T aself
serial
T apublic_key
key_type
kformat
f_pub
pub
T aself
private_key
serial
key_id
key_type
cert_prefix
nonce
kformat
wfafprincipals
wpafcrit
name
value
foptval
fext
fextval
ca_type
caformat
caf
signature
fsig
hash_alg
wrwsafsigblob
cert_data
T aself
sigformat
signature_key
sigkey_rest
T aself
buf
T aself
type
T aself
valid_after
T aself
valid_before
T aself
valid_principals
T aself
signature_key
wradata
wsacomputed_sig
hash_alg
a__spec__
.cryptography.utils
(
q

u must be bytes
u must be bytes-like
ulength argument can't be 0
to_bytes
bit_length
l l abig
value
message
warning_class
a__class__
a__init__
a__name__
a_module
a_DeprecatedValue
warnings
warn
D astacklevel
l adelattr
T a_module
modules
a_ModuleWithDeprecations
a_cached_
D ainstance
object
inner
ucached_property.<locals>.inner
cached_name
sentinel
func
w<w.a_name_
u:
a_value_
w>a__doc__
a__file__
origin
has_location
a__cached__
annotations
enum
sys
types
typing
aUserWarning
a__prepare__
aCryptographyDeprecationWarning
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
