# Reconstructed from integrated Nuitka blob
# Module: ucryptography.x509.base

a__qualname__
D amsg
oid
return
str
aObjectIdentifier
aNone
uAttributeNotFound.__init__
a__orig_bases__
D aextension
extensions
return
uExtension[ExtensionType]
ulist[Extension[ExtensionType]]
aNone
D aoid
attributes
return
aObjectIdentifier
ulist[tuple[ObjectIdentifier, bytes, int | None]]
aNone
D atime
return
udatetime.datetime
udatetime.datetime
aUTF8String
D aoid
value
a_type
return
aObjectIdentifier
bytes
int
aNone
uAttribute.__init__
D areturn
aObjectIdentifier
uAttribute.oid
D areturn
bytes
uAttribute.value
D areturn
str
a__repr__
uAttribute.__repr__
D aother
return
object
bool
a__eq__
uAttribute.__eq__
D areturn
int
a__hash__
uAttribute.__hash__
aAttributes
D aattributes
return
utyping.Iterable[Attribute]
aNone
uAttributes.__init__
T a_attributes
a__len__
a__iter__
uAttributes.__repr__
D aoid
return
aObjectIdentifier
aAttribute
get_attribute_for_oid
uAttributes.get_attribute_for_oid
aEnum
v1
l aInvalidVersion
D amsg
parsed_version
return
str
int
aNone
uInvalidVersion.__init__
aCertificate
metaclass
aABCMeta
T aRevokedCertificate
T
property
abstractmethod

Returns the serial number of the revoked certificate.
serial_number
uRevokedCertificate.serial_number
D areturn
udatetime.datetime

Returns the date of when this certificate was revoked.
revocation_date
uRevokedCertificate.revocation_date

Returns the date of when this certificate was revoked as a non-naive
UTC datetime.
revocation_date_utc
uRevokedCertificate.revocation_date_utc
D areturn
aExtensions

Returns an Extensions object containing a list of Revoked extensions.
extensions
uRevokedCertificate.extensions
register
D aserial_number
revocation_date
extensions
int
udatetime.datetime
aExtensions
u_RawRevokedCertificate.__init__
u_RawRevokedCertificate.serial_number
u_RawRevokedCertificate.revocation_date
u_RawRevokedCertificate.revocation_date_utc
u_RawRevokedCertificate.extensions
aCertificateRevocationList
aCertificateSigningRequest
load_pem_x509_certificate
load_der_x509_certificate
load_pem_x509_certificates
load_pem_x509_csr
load_der_x509_csr
load_pem_x509_crl
load_der_x509_crl
D asubject_name
extensions
attributes
uName | None
ulist[Extension[ExtensionType]]
ulist[tuple[ObjectIdentifier, bytes, int | None]]
uCertificateSigningRequestBuilder.__init__
D aname
return
aName
aCertificateSigningRequestBuilder
subject_name
uCertificateSigningRequestBuilder.subject_name
D aextval
critical
return
aExtensionType
bool
aCertificateSigningRequestBuilder
add_extension
uCertificateSigningRequestBuilder.add_extension
D a_tag
nD aoid
value
a_tag
return
aObjectIdentifier
bytes
u_ASN1Type | None
aCertificateSigningRequestBuilder
add_attribute
uCertificateSigningRequestBuilder.add_attribute
D arsa_padding
nD aprivate_key
algorithm
backend
rsa_padding
return
aCertificateIssuerPrivateKeyTypes
u_AllowedHashTypes | None
utyping.Any
upadding.PSS | padding.PKCS1v15 | None
aCertificateSigningRequest
sign
uCertificateSigningRequestBuilder.sign
a__annotations__
ulist[Extension[ExtensionType]]
D aissuer_name
subject_name
public_key
serial_number
not_valid_before
not_valid_after
extensions
return
uName | None
uName | None
uCertificatePublicKeyTypes | None
uint | None
udatetime.datetime | None
udatetime.datetime | None
ulist[Extension[ExtensionType]]
aNone
uCertificateBuilder.__init__
D aname
return
aName
aCertificateBuilder
issuer_name
uCertificateBuilder.issuer_name
uCertificateBuilder.subject_name
D akey
return
aCertificatePublicKeyTypes
aCertificateBuilder
public_key
uCertificateBuilder.public_key
D anumber
return
int
aCertificateBuilder
uCertificateBuilder.serial_number
D atime
return
udatetime.datetime
aCertificateBuilder
not_valid_before
uCertificateBuilder.not_valid_before
not_valid_after
uCertificateBuilder.not_valid_after
D aextval
critical
return
aExtensionType
bool
aCertificateBuilder
uCertificateBuilder.add_extension
D aprivate_key
algorithm
backend
rsa_padding
return
aCertificateIssuerPrivateKeyTypes
u_AllowedHashTypes | None
utyping.Any
upadding.PSS | padding.PKCS1v15 | None
aCertificate
uCertificateBuilder.sign
ulist[RevokedCertificate]
D aissuer_name
last_update
next_update
extensions
revoked_certificates
uName | None
udatetime.datetime | None
udatetime.datetime | None
ulist[Extension[ExtensionType]]
ulist[RevokedCertificate]
uCertificateRevocationListBuilder.__init__
D aissuer_name
return
aName
aCertificateRevocationListBuilder
uCertificateRevocationListBuilder.issuer_name
D alast_update
return
udatetime.datetime
aCertificateRevocationListBuilder
last_update
uCertificateRevocationListBuilder.last_update
D anext_update
return
udatetime.datetime
aCertificateRevocationListBuilder
next_update
uCertificateRevocationListBuilder.next_update
D aextval
critical
return
aExtensionType
bool
aCertificateRevocationListBuilder
uCertificateRevocationListBuilder.add_extension
D arevoked_certificate
return
aRevokedCertificate
aCertificateRevocationListBuilder
add_revoked_certificate
uCertificateRevocationListBuilder.add_revoked_certificate
D aprivate_key
algorithm
backend
rsa_padding
return
aCertificateIssuerPrivateKeyTypes
u_AllowedHashTypes | None
utyping.Any
upadding.PSS | padding.PKCS1v15 | None
aCertificateRevocationList
uCertificateRevocationListBuilder.sign
D aserial_number
revocation_date
extensions
uint | None
udatetime.datetime | None
ulist[Extension[ExtensionType]]
uRevokedCertificateBuilder.__init__
D anumber
return
int
aRevokedCertificateBuilder
uRevokedCertificateBuilder.serial_number
D atime
return
udatetime.datetime
aRevokedCertificateBuilder
uRevokedCertificateBuilder.revocation_date
D aextval
critical
return
aExtensionType
bool
aRevokedCertificateBuilder
uRevokedCertificateBuilder.add_extension
D abackend
return
utyping.Any
aRevokedCertificate
build
uRevokedCertificateBuilder.build
random_serial_number
ucryptography\x509\base.py
u<module cryptography.x509.base>
T a__class__
T aself
other
T aself
T aself
oid
value
a_type
T aself
msg
oid
a__class__
T aself
attributes
T aself
issuer_name
subject_name
public_key
serial_number
not_valid_before
not_valid_after
extensions
T aself
issuer_name
last_update
next_update
extensions
revoked_certificates
T aself
subject_name
extensions
attributes
T aself
msg
parsed_version
a__class__
T aself
serial_number
revocation_date
extensions
T atime
offset
T aoid
attributes
attr_oid
w_T aextension
extensions
weT aself
oid
value
a_tag
tag
T aself
extval
critical
extension
T aself
revoked_certificate
T aself
backend
T aself
oid
attr
T aself
name
T aself
issuer_name
T aself
last_update
T aself
next_update
T aself
time
T aself
key
T aself
number
T aself
private_key
algorithm
backend
rsa_padding
a__spec__
.cryptography.x509.certificate_transparency
?
+
a__doc__
a__file__
origin
has_location
a__cached__
annotations
cryptography
T autils
utils
ucryptography.hazmat.bindings._rust
T ax509
x509
rust_x509
aEnum
a__prepare__
aLogEntryType
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
