# Reconstructed from integrated Nuitka blob
# Module: ucryptography.utils

a__qualname__
a__orig_bases__
aDeprecatedIn36
aDeprecatedIn37
aDeprecatedIn40
aDeprecatedIn41
aDeprecatedIn42
aDeprecatedIn43
D aname
value
return
str
bytes
aNone
a_check_bytes
a_check_byteslike
T nD ainteger
length
return
int
uint | None
bytes
int_to_bytes
T EException
aInterfaceNotImplemented
D avalue
message
object
str
u_DeprecatedValue.__init__
aModuleType
D amodule
utypes.ModuleType
u_ModuleWithDeprecations.__init__
D aattr
return
str
object
a__getattr__
u_ModuleWithDeprecations.__getattr__
D aattr
value
return
str
object
aNone
a__setattr__
u_ModuleWithDeprecations.__setattr__
D aattr
return
str
aNone
a__delattr__
u_ModuleWithDeprecations.__delattr__
D areturn
utyping.Sequence[str]
a__dir__
u_ModuleWithDeprecations.__dir__
D avalue
module_name
message
warning_class
name
return
object
str
putype[Warning]
ustr | None
a_DeprecatedValue
deprecated
D afunc
return
utyping.Callable
property
cached_property
aEnum
D areturn
str
a__repr__
uEnum.__repr__
a__str__
uEnum.__str__
ucryptography\utils.py
u<module cryptography.utils>
T a__class__
T aself
attr
obj
T aself
T aself
value
message
warning_class
T aself
module
a__class__
T aself
attr
value
T aname
value
T afunc
cached_name
sentinel
inner
T avalue
module_name
message
warning_class
name
module
dv
T ainstance
cache
result
cached_name
sentinel
func
T acached_name
func
sentinel
T ainteger
length
a__spec__
.cryptography.x509.base
/
v a__class__
a__init__
oid
extension
uThis extension has already been set.
uThis attribute has already been set.
tzinfo
utcoffset
datetime
timedelta
replace
T nT atzinfo
uNormalizes a datetime to a naive datetime in UTC.
time -- datetime to normalize. Assumed to be in UTC if not timezone
ware.
a_oid
a_value
a_type
u<Attribute(oid=

u, value=
value
u)>
aAttribute
a_attributes
u<Attributes(
aAttributeNotFound
uNo
u attribute was found
parsed_version
a_serial_number
a_revocation_date
a_extensions
warnings
warn
uProperties that return a na  ve datetime object have been deprecated. Please switch to revocation_date_utc.
utils
aDeprecatedIn42
D astacklevel
l atimezone
utc
a_subject_name

Creates an empty X.509 certificate request (v1).
aName
uExpecting x509.Name object.
uThe subject name may only be set once.
aCertificateSigningRequestBuilder

Sets the certificate requestor's distinguished name.
aExtensionType
uextension must be an ExtensionType
aExtension
a_reject_duplicate_extension

Adds an X.509 extension to the certificate request.
aObjectIdentifier
uoid must be an ObjectIdentifier
uvalue must be bytes
a_ASN1Type
utag must be _ASN1Type
a_reject_duplicate_attribute

Adds an X.509 attribute with an OID and associated value.
uA CertificateSigningRequest must have a subject
padding
aPSS
aPKCS1v15
uPadding must be PSS or PKCS1v15
rsa
aRSAPrivateKey
uPadding is only supported for RSA keys
rust_x509
create_x509_csr

Signs the request using the requestor's private key.
aVersion
v3
a_version
a_issuer_name
a_public_key
a_not_valid_before
a_not_valid_after
uThe issuer name may only be set once.
aCertificateBuilder

Sets the CA's distinguished name.

Sets the requestor's distinguished name.
dsa
aDSAPublicKey
aRSAPublicKey
ec
aEllipticCurvePublicKey
ed25519
aEd25519PublicKey
ed448
aEd448PublicKey
x25519
aX25519PublicKey
x448
aX448PublicKey
uExpecting one of DSAPublicKey, RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey, X25519PublicKey, or X448PublicKey.
uThe public key may only be set once.

Sets the requestor's public key (as found in the signing request).
uSerial number must be of integral type.
uThe serial number may only be set once.
uThe serial number should be positive.
bit_length
l  uThe serial number should not be more than 159 bits.

Sets the certificate serial number.
uExpecting datetime object.
uThe not valid before may only be set once.
a_convert_to_naive_utc_time
a_EARLIEST_UTC_TIME
uThe not valid before date must be on or after 1950 January 1).
uThe not valid before date must be before the not valid after date.

Sets the certificate activation time.
uThe not valid after may only be set once.
uThe not valid after date must be on or after 1950 January 1.
uThe not valid after date must be after the not valid before date.

Sets the certificate expiration time.

Adds an X.509 extension to the certificate.
uA certificate must have a subject name
uA certificate must have an issuer name
uA certificate must have a serial number
uA certificate must have a not valid before time
uA certificate must have a not valid after time
uA certificate must have a public key
create_x509_certificate

Signs the certificate using the CA's private key.
a_last_update
a_next_update
a_revoked_certificates
aCertificateRevocationListBuilder
uLast update may only be set once.
uThe last update date must be on or after 1950 January 1.
uThe last update date must be before the next update date.
uThe next update date must be after the last update date.

Adds an X.509 extension to the certificate revocation list.
aRevokedCertificate
uMust be an instance of RevokedCertificate

Adds a revoked certificate to the CRL.
uA CRL must have an issuer name
uA CRL must have a last update time
uA CRL must have a next update time
create_x509_crl
uThe serial number should be positive
aRevokedCertificateBuilder
uThe revocation date may only be set once.
uThe revocation date must be on or after 1950 January 1.
uA revoked certificate must have a serial number
uA revoked certificate must have a revocation date
a_RawRevokedCertificate
aExtensions
from_bytes
urandom
T l abig
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
os
typing
cryptography
T autils
ucryptography.hazmat.bindings._rust
T ax509
x509
ucryptography.hazmat.primitives
T ahashes
hashes
ucryptography.hazmat.primitives.asymmetric
T adsa
ec
ed448
ed25519
padding
rsa
x448
x25519
ucryptography.hazmat.primitives.asymmetric.types
T aCertificateIssuerPrivateKeyTypes
aCertificatePublicKeyTypes
aCertificateIssuerPrivateKeyTypes
aCertificatePublicKeyTypes
ucryptography.x509.extensions
T aExtension
aExtensions
aExtensionType
a_make_sequence_methods
a_make_sequence_methods
ucryptography.x509.name
T aName
a_ASN1Type
ucryptography.x509.oid
T aObjectIdentifier
T l  l paUnion
aSHA224
aSHA256
aSHA384
aSHA512
aSHA3_224
aSHA3_256
aSHA3_384
aSHA3_512
a_AllowedHashTypes
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
