# Reconstructed from integrated Nuitka blob
# Module: ucryptography.x509.name

a__qualname__
l l aOctetString
l l aNumericString
l aPrintableString
l aT61String
l aIA5String
l aUTCTime
l aGeneralizedTime
l aVisibleString
l aUniversalString
l aBMPString
a__orig_bases__
a_ASN1_TYPE_TO_ENUM
aCOUNTRY_NAME
aJURISDICTION_COUNTRY_NAME
aSERIAL_NUMBER
aDN_QUALIFIER
aEMAIL_ADDRESS
aDOMAIN_COMPONENT
aMapping
a_OidNameMap
a_NameOidMap
aCOMMON_NAME
aCN
aLOCALITY_NAME
wLaSTATE_OR_PROVINCE_NAME
aST
aORGANIZATION_NAME
wOaORGANIZATIONAL_UNIT_NAME
aOU
wCaSTREET_ADDRESS
aSTREET
aDC
aUSER_ID
aUID
T l pT l l@aTypeVar
aNameAttributeValueType
aUnion
T Ostr
Obytes
D acovariant
taGeneric
T nD a_validate
ta__init__
uNameAttribute.__init__
property
uNameAttribute.oid
uNameAttribute.value
uNameAttribute.rfc4514_attribute_name
uNameAttribute.rfc4514_string
a__eq__
uNameAttribute.__eq__
a__hash__
uNameAttribute.__hash__
a__repr__
uNameAttribute.__repr__
uRelativeDistinguishedName.__init__
get_attributes_for_oid
uRelativeDistinguishedName.get_attributes_for_oid
uRelativeDistinguishedName.rfc4514_string
uRelativeDistinguishedName.__eq__
uRelativeDistinguishedName.__hash__
uRelativeDistinguishedName.__iter__
a__len__
uRelativeDistinguishedName.__len__
uRelativeDistinguishedName.__repr__
overload
uName.__init__
from_rfc4514_string
uName.from_rfc4514_string
uName.rfc4514_string
uName.get_attributes_for_oid
uName.rdns
public_bytes
uName.public_bytes
uName.__eq__
uName.__hash__
uName.__len__
uName.__repr__
compile
T u(0|([1-9]\d*))(\.(0|([1-9]\d*)))+
T u[a-zA-Z][a-zA-Z\d-]*
u\\([\\ #=\"\+,;<>]|[\da-zA-Z]{2})
a_PAIR
u[\x01-\x1f\x21\x24-\x2A\x2D-\x3A\x3D\x3F-\x5B\x5D-\x7F]
a_LUTF1
u[\x01-\x21\x23-\x2A\x2D-\x3A\x3D\x3F-\x5B\x5D-\x7F]
a_SUTF1
u[\x01-\x1F\x21\x23-\x2A\x2D-\x3A\x3D\x3F-\x5B\x5D-\x7F]
a_TUTF1
u[\x80-
maxunicode
w]a_UTFMB
w|a_LEADCHAR
a_STRINGCHAR
a_TRAILCHAR

(
(
u)
(
(
u)*
(
u)
)?
)?
aVERBOSE
T u#([\da-zA-Z]{2})+
u_RFC4514NameParser.__init__
u_RFC4514NameParser._has_data
u_RFC4514NameParser._peek
u_RFC4514NameParser._read_char
u_RFC4514NameParser._read_re
u_RFC4514NameParser.parse
u_RFC4514NameParser._parse_rdn
u_RFC4514NameParser._parse_na
ucryptography\x509\name.py
T a.0
wxT a.0
rdn
T a.0
attr
T a.0
attr
attr_name_overrides
u<module cryptography.x509.name>
T a__class__
T aself
other
T aself
T aself
attributes
T
self
oid
value
a_type
a_validate
length_limits
min_length
max_length
c_len
msg
T aself
data
attr_name_overrides
T aself
rdn
T aself
rdns
T aval
T aself
oid_value
name
oid
value
raw_value
T aself
nas
T aself
ch
T aself
pat
match
val
T aval
sub
T acls
data
attr_name_overrides
T aself
oid
T aself
backend
T aself
attr_name_overrides
T aself
attr_name_overrides
attr_name
T wmaval
.cryptography.x509.ocsp
:
a_ALLOWED_HASHES
uAlgorithm must be SHA1, SHA224, SHA256, SHA384, or SHA512
a_verify_algorithm
datetime
uthis_update must be a datetime object
unext_update must be a datetime object or None
a_resp
a_resp_hash
a_algorithm
a_this_update
a_next_update
aOCSPCertStatus
ucert_status must be an item from the OCSPCertStatus enum
aREVOKED
urevocation_time can only be provided if the certificate is revoked
urevocation_reason can only be provided if the certificate is revoked
urevocation_time must be a datetime object
x509
aReasonFlags
urevocation_reason must be an item from the ReasonFlags enum or None
a_cert_status
a_revocation_time
a_revocation_reason
a_request
a_request_hash
a_extensions
uOnly one certificate can be added to a request
aCertificate
ucert and issuer must be a Certificate
aOCSPRequestBuilder
userial_number must be an integer
utils
a_check_bytes
issuer_name_hash
issuer_key_hash
digest_size
uissuer_name_hash and issuer_key_hash must be the same length as the digest size of the algorithm
aExtensionType
uextension must be an ExtensionType
aExtension
oid
a_reject_duplicate_extension
uYou must add a certificate before building
ocsp
create_ocsp_request
a_response
a_responder_id
a_certs
uOnly one response per OCSPResponse.
a_SingleResponse
aOCSPResponseBuilder
uresponder_id can only be set once
uresponder_cert must be a Certificate
aOCSPResponderEncoding
uencoding must be an element from OCSPResponderEncoding
ucertificates may only be set once
ucerts must not be an empty list
ucerts must be a list of Certificates
u<genexpr>
uOCSPResponseBuilder.certificates.<locals>.<genexpr>
uYou must add a response before signing
uYou must add a responder_id before signing
create_ocsp_response
aOCSPResponseStatus
aSUCCESSFUL
uresponse_status must be an item from OCSPResponseStatus
uresponse_status cannot be SUCCESSFUL
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
l
ucollections.abc
T aIterable
aIterable
cryptography
T autils
x509
ucryptography.hazmat.bindings._rust
T aocsp
ucryptography.hazmat.primitives
T ahashes
hashes
ucryptography.hazmat.primitives.asymmetric.types
T aCertificateIssuerPrivateKeyTypes
aCertificateIssuerPrivateKeyTypes
ucryptography.x509.base
T a_reject_duplicate_extension
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
