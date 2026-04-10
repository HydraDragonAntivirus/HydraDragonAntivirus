# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.serialization.pkcs12

a__qualname__
a__init__
uPKCS12KeyAndCertificates.__init__
uPKCS12KeyAndCertificates.key
uPKCS12KeyAndCertificates.cert
uPKCS12KeyAndCertificates.additional_certs
a__eq__
uPKCS12KeyAndCertificates.__eq__
a__hash__
uPKCS12KeyAndCertificates.__hash__
a__repr__
uPKCS12KeyAndCertificates.__repr__
load_key_and_certificates
load_pkcs12
aCertificate
a_PKCS12CATypes
ucryptography\hazmat\primitives\serialization\pkcs12.py
T a.0
add_cert
u<module cryptography.hazmat.primitives.serialization.pkcs12>
T a__class__
T aself
other
T aself
T aself
key
cert
additional_certs
T aself
fmt
T acerts
encryption_algorithm
T aname
key
cert
cas
encryption_algorithm

.cryptography.hazmat.primitives.serialization.pkcs7
a_data
a_signers
a_additional_certs
a_check_byteslike
data
udata may only be set once
aPKCS7SignatureBuilder
hashes
aSHA224
aSHA256
aSHA384
aSHA512
uhash_algorithm must be one of hashes.SHA224, SHA256, SHA384, or SHA512
x509
aCertificate
ucertificate must be a x509.Certificate
rsa
aRSAPrivateKey
ec
aEllipticCurvePrivateKey
uOnly RSA & EC keys are supported at this time.
padding
aPSS
aPKCS1v15
uPadding must be PSS or PKCS1v15
uPadding is only supported for RSA keys
uMust have at least one signer
uYou must add data to sign
uoptions must be from the PKCS7Options enum
serialization
aEncoding
aPEM
aDER
aSMIME
uMust be PEM, DER, or SMIME from the Encoding enum
aPKCS7Options
aText
aDetachedSignature
uWhen passing the Text option you must also pass DetachedSignature
uThe Text option is only available for SMIME serialization
aNoAttributes
aNoCapabilities
uNoAttributes is a superset of NoCapabilities. Do not pass both values.
rust_pkcs7
sign_and_serialize
u<genexpr>
uPKCS7SignatureBuilder.sign.<locals>.<genexpr>
ucryptography.hazmat.backends.openssl.backend
T abackend
l
backend
rsa_encryption_supported
T apadding
aUnsupportedAlgorithm
uRSA with PKCS1 v1.5 padding is not supported by this version of OpenSSL.
a_Reasons
aUNSUPPORTED_PADDING
a_recipients
a_content_encryption_algorithm
aPKCS7EnvelopeBuilder
T a_data
a_recipients
a_content_encryption_algorithm
public_key
aRSAPublicKey
uOnly RSA keys are supported at this time.
uContent encryption algo may only be set once
algorithms
aAES128
aAES256
uOnly AES128 and AES256 are supported
uMust have at least one recipient
uYou must add data to encrypt
uOnly the following options are supported for encryption: Text, Binary
aBinary
uCannot use Binary and Text options at the same time
encrypt_and_serialize
uPKCS7EnvelopeBuilder.encrypt.<locals>.<genexpr>
email
message
aMessage
add_header
T uMIME-Version
u1.0
uapplication/x-pkcs7-signature
T uContent-Type
umultipart/signed
T aprotocol
micalg
uThis is an S/MIME signed message
preamble
aOpenSSLMimePart
set_payload
T uContent-Type
utext/plain
attach
aMIMEPart
T uContent-Type
uapplication/x-pkcs7-signature
usmime.p7s
T aname
T uContent-Transfer-Encoding
base64
T uContent-Disposition
attachment
usmime.p7s
T afilename
base64mime
body_encode
D amaxlinelen
lAuMIME-Version
aBytesIO
generator
aBytesGenerator
policy
clone
T u
T alinesep
T amaxheaderlen
mangle_from_
policy
flatten
getvalue
T uContent-Disposition
attachment
usmime.p7m
T uContent-Type
uapplication/pkcs7-mime
uenveloped-data
usmime.p7m
T asmime_type
name
as_bytes
T w
l
T alinesep
max_line_length
T apolicy
message_from_bytes
get_content_type
P uapplication/pkcs7-mime
uapplication/x-pkcs7-mime
uNot an S/MIME enveloped message
get_payload
T tT adecode
get
T ucontent-type
uDecrypted MIME data has no 'Content-Type' header. Please remove the 'Text' option to parse it manually.
utext/plain
uDecrypted MIME data content type is '

u', not 'text/plain'. Remove the 'Text' option to parse it manually.
raw_items
a_write_headers
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
uemail.base64mime
uemail.generator
uemail.message
uemail.policy
io
typing
ucollections.abc
T aIterable
aIterable
cryptography
T autils
x509
utils
ucryptography.exceptions
T aUnsupportedAlgorithm
a_Reasons
ucryptography.hazmat.bindings._rust
T apkcs7
pkcs7
ucryptography.hazmat.primitives
T ahashes
serialization
ucryptography.hazmat.primitives.asymmetric
T aec
padding
rsa
ucryptography.hazmat.primitives.ciphers
T aalgorithms
ucryptography.utils
T a_check_byteslike
load_pem_pkcs7_certificates
load_der_pkcs7_certificates
serialize_certificates
aUnion
aPKCS7HashTypes
aPKCS7PrivateKeyTypes
aType
aContentEncryptionAlgorithm
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
