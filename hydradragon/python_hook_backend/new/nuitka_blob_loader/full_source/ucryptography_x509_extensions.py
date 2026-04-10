# Reconstructed from integrated Nuitka blob
# Module: ucryptography.x509.extensions

a__qualname__
D amsg
oid
return
str
aObjectIdentifier
aNone
uDuplicateExtension.__init__
a__orig_bases__
uExtensionNotFound.__init__
metaclass
aABCMeta
T aExtensionType
T
aExtensionType
a__annotations__
utyping.ClassVar[ObjectIdentifier]
D areturn
bytes
uExtensionType.public_bytes
aExtensions
D aextensions
return
utyping.Iterable[Extension[ExtensionType]]
aNone
uExtensions.__init__
D aoid
return
aObjectIdentifier
uExtension[ExtensionType]
get_extension_for_oid
uExtensions.get_extension_for_oid
D aextclass
return
utype[ExtensionTypeVar]
uExtension[ExtensionTypeVar]
get_extension_for_class
uExtensions.get_extension_for_class
T a_extensions
a__len__
a__iter__
D areturn
str
a__repr__
uExtensions.__repr__
aCRL_NUMBER
D acrl_number
return
int
aNone
uCRLNumber.__init__
D aother
return
object
bool
a__eq__
uCRLNumber.__eq__
a__hash__
uCRLNumber.__hash__
uCRLNumber.__repr__
property
uCRLNumber.crl_number
uCRLNumber.public_bytes
aAUTHORITY_KEY_IDENTIFIER
D akey_identifier
authority_cert_issuer
authority_cert_serial_number
return
ubytes | None
utyping.Iterable[GeneralName] | None
uint | None
aNone
uAuthorityKeyIdentifier.__init__
classmethod
D apublic_key
return
aCertificateIssuerPublicKeyTypes
aAuthorityKeyIdentifier
from_issuer_public_key
uAuthorityKeyIdentifier.from_issuer_public_key
D aski
return
aSubjectKeyIdentifier
aAuthorityKeyIdentifier
from_issuer_subject_key_identifier
uAuthorityKeyIdentifier.from_issuer_subject_key_identifier
uAuthorityKeyIdentifier.__repr__
uAuthorityKeyIdentifier.__eq__
uAuthorityKeyIdentifier.__hash__
D areturn
ubytes | None
uAuthorityKeyIdentifier.key_identifier
D areturn
ulist[GeneralName] | None
uAuthorityKeyIdentifier.authority_cert_issuer
D areturn
uint | None
uAuthorityKeyIdentifier.authority_cert_serial_number
uAuthorityKeyIdentifier.public_bytes
aSUBJECT_KEY_IDENTIFIER
D adigest
return
bytes
aNone
uSubjectKeyIdentifier.__init__
D apublic_key
return
aCertificatePublicKeyTypes
aSubjectKeyIdentifier
from_public_key
uSubjectKeyIdentifier.from_public_key
uSubjectKeyIdentifier.digest
uSubjectKeyIdentifier.key_identifier
uSubjectKeyIdentifier.__repr__
uSubjectKeyIdentifier.__eq__
uSubjectKeyIdentifier.__hash__
uSubjectKeyIdentifier.public_bytes
aAUTHORITY_INFORMATION_ACCESS
D adescriptions
return
utyping.Iterable[AccessDescription]
aNone
uAuthorityInformationAccess.__init__
T a_descriptions
uAuthorityInformationAccess.__repr__
uAuthorityInformationAccess.__eq__
uAuthorityInformationAccess.__hash__
uAuthorityInformationAccess.public_bytes
aSUBJECT_INFORMATION_ACCESS
uSubjectInformationAccess.__init__
uSubjectInformationAccess.__repr__
uSubjectInformationAccess.__eq__
uSubjectInformationAccess.__hash__
uSubjectInformationAccess.public_bytes
D aaccess_method
access_location
return
aObjectIdentifier
aGeneralName
aNone
uAccessDescription.__init__
uAccessDescription.__repr__
uAccessDescription.__eq__
uAccessDescription.__hash__
D areturn
aObjectIdentifier
uAccessDescription.access_method
D areturn
aGeneralName
uAccessDescription.access_location
aBASIC_CONSTRAINTS
D aca
path_length
return
bool
uint | None
aNone
uBasicConstraints.__init__
D areturn
bool
uBasicConstraints.ca
uBasicConstraints.path_length
uBasicConstraints.__repr__
uBasicConstraints.__eq__
uBasicConstraints.__hash__
uBasicConstraints.public_bytes
aDELTA_CRL_INDICATOR
uDeltaCRLIndicator.__init__
uDeltaCRLIndicator.crl_number
uDeltaCRLIndicator.__eq__
uDeltaCRLIndicator.__hash__
uDeltaCRLIndicator.__repr__
uDeltaCRLIndicator.public_bytes
aCRL_DISTRIBUTION_POINTS
D adistribution_points
return
utyping.Iterable[DistributionPoint]
aNone
uCRLDistributionPoints.__init__
T a_distribution_points
uCRLDistributionPoints.__repr__
uCRLDistributionPoints.__eq__
uCRLDistributionPoints.__hash__
uCRLDistributionPoints.public_bytes
aFRESHEST_CRL
uFreshestCRL.__init__
uFreshestCRL.__repr__
uFreshestCRL.__eq__
uFreshestCRL.__hash__
uFreshestCRL.public_bytes
D afull_name
relative_name
reasons
crl_issuer
return
utyping.Iterable[GeneralName] | None
uRelativeDistinguishedName | None
ufrozenset[ReasonFlags] | None
utyping.Iterable[GeneralName] | None
aNone
uDistributionPoint.__init__
uDistributionPoint.__repr__
uDistributionPoint.__eq__
uDistributionPoint.__hash__
uDistributionPoint.full_name
D areturn
uRelativeDistinguishedName | None
uDistributionPoint.relative_name
D areturn
ufrozenset[ReasonFlags] | None
uDistributionPoint.reasons
uDistributionPoint.crl_issuer
aEnum
keyCompromise
key_compromise
cACompromise
ca_compromise
affiliationChanged
affiliation_changed
superseded
cessationOfOperation
cessation_of_operation
certificateHold
certificate_hold
privilegeWithdrawn
privilege_withdrawn
aACompromise
aa_compromise
removeFromCRL
l l l l l l l a_REASON_BIT_MAPPING
a_CRLREASONFLAGS
l	l
a_CRL_ENTRY_REASON_ENUM_TO_CODE
aPOLICY_CONSTRAINTS
D arequire_explicit_policy
inhibit_policy_mapping
return
uint | None
uint | None
aNone
uPolicyConstraints.__init__
uPolicyConstraints.__repr__
uPolicyConstraints.__eq__
uPolicyConstraints.__hash__
uPolicyConstraints.require_explicit_policy
uPolicyConstraints.inhibit_policy_mapping
uPolicyConstraints.public_bytes
aCERTIFICATE_POLICIES
D apolicies
return
utyping.Iterable[PolicyInformation]
aNone
uCertificatePolicies.__init__
T a_policies
uCertificatePolicies.__repr__
uCertificatePolicies.__eq__
uCertificatePolicies.__hash__
uCertificatePolicies.public_bytes
D apolicy_identifier
policy_qualifiers
return
aObjectIdentifier
utyping.Iterable[str | UserNotice] | None
aNone
uPolicyInformation.__init__
uPolicyInformation.__repr__
uPolicyInformation.__eq__
uPolicyInformation.__hash__
uPolicyInformation.policy_identifier
D areturn
ulist[str | UserNotice] | None
uPolicyInformation.policy_qualifiers
D anotice_reference
explicit_text
return
uNoticeReference | None
ustr | None
aNone
uUserNotice.__init__
uUserNotice.__repr__
uUserNotice.__eq__
uUserNotice.__hash__
D areturn
uNoticeReference | None
uUserNotice.notice_reference
D areturn
ustr | None
uUserNotice.explicit_text
D aorganization
notice_numbers
return
ustr | None
utyping.Iterable[int]
aNone
uNoticeReference.__init__
uNoticeReference.__repr__
uNoticeReference.__eq__
uNoticeReference.__hash__
uNoticeReference.organization
D areturn
ulist[int]
uNoticeReference.notice_numbers
aEXTENDED_KEY_USAGE
D ausages
return
utyping.Iterable[ObjectIdentifier]
aNone
uExtendedKeyUsage.__init__
T a_usages
uExtendedKeyUsage.__repr__
uExtendedKeyUsage.__eq__
uExtendedKeyUsage.__hash__
uExtendedKeyUsage.public_bytes
aOCSP_NO_CHECK
uOCSPNoCheck.__eq__
uOCSPNoCheck.__hash__
u<OCSPNoCheck()>
uOCSPNoCheck.__repr__
uOCSPNoCheck.public_bytes
aPRECERT_POISON
uPrecertPoison.__eq__
uPrecertPoison.__hash__
u<PrecertPoison()>
uPrecertPoison.__repr__
uPrecertPoison.public_bytes
aTLS_FEATURE
D afeatures
return
utyping.Iterable[TLSFeatureType]
aNone
uTLSFeature.__init__
T a_features
uTLSFeature.__repr__
uTLSFeature.__eq__
uTLSFeature.__hash__
uTLSFeature.public_bytes
status_request
l astatus_request_v2
a_TLS_FEATURE_TYPE_TO_ENUM
aINHIBIT_ANY_POLICY
D askip_certs
return
int
aNone
uInhibitAnyPolicy.__init__
uInhibitAnyPolicy.__repr__
uInhibitAnyPolicy.__eq__
uInhibitAnyPolicy.__hash__
uInhibitAnyPolicy.skip_certs
uInhibitAnyPolicy.public_bytes
aKEY_USAGE
D
digital_signature
content_commitment
key_encipherment
data_encipherment
key_agreement
key_cert_sign
crl_sign
encipher_only
decipher_only
return
bool
ppppppppaNone
uKeyUsage.__init__
uKeyUsage.digital_signature
uKeyUsage.content_commitment
uKeyUsage.key_encipherment
uKeyUsage.data_encipherment
uKeyUsage.key_agreement
uKeyUsage.key_cert_sign
uKeyUsage.crl_sign
uKeyUsage.encipher_only
uKeyUsage.decipher_only
uKeyUsage.__repr__
uKeyUsage.__eq__
uKeyUsage.__hash__
uKeyUsage.public_bytes
aNAME_CONSTRAINTS
D apermitted_subtrees
excluded_subtrees
return
utyping.Iterable[GeneralName] | None
utyping.Iterable[GeneralName] | None
aNone
uNameConstraints.__init__
uNameConstraints.__eq__
D atree
return
utyping.Iterable[GeneralName]
aNone
uNameConstraints._validate_tree
uNameConstraints._validate_ip_name
uNameConstraints._validate_dns_name
uNameConstraints.__repr__
uNameConstraints.__hash__
uNameConstraints.permitted_subtrees
uNameConstraints.excluded_subtrees
uNameConstraints.public_bytes
aGeneric
D aoid
critical
value
return
aObjectIdentifier
bool
aExtensionTypeVar
aNone
uExtension.__init__
uExtension.oid
uExtension.critical
D areturn
aExtensionTypeVar
uExtension.value
uExtension.__repr__
uExtension.__eq__
uExtension.__hash__
D ageneral_names
return
utyping.Iterable[GeneralName]
aNone
uGeneralNames.__init__
T a_general_names
overload
D atype
return
utype[DNSName] | type[UniformResourceIdentifier] | type[RFC822Name]
ulist[str]
uGeneralNames.get_values_for_type
D atype
return
utype[DirectoryName]
ulist[Name]
D atype
return
utype[RegisteredID]
ulist[ObjectIdentifier]
D atype
return
utype[IPAddress]
ulist[_IPAddressTypes]
D atype
return
utype[OtherName]
ulist[OtherName]
D atype
return
utype[DNSName] | type[DirectoryName] | type[IPAddress] | type[OtherName] | type[RFC822Name] | type[RegisteredID] | type[UniformResourceIdentifier]
ulist[_IPAddressTypes] | list[str] | list[OtherName] | list[Name] | list[ObjectIdentifier]
uGeneralNames.__repr__
uGeneralNames.__eq__
uGeneralNames.__hash__
aSUBJECT_ALTERNATIVE_NAME
uSubjectAlternativeName.__init__
uSubjectAlternativeName.get_values_for_type
uSubjectAlternativeName.__repr__
uSubjectAlternativeName.__eq__
uSubjectAlternativeName.__hash__
uSubjectAlternativeName.public_bytes
aISSUER_ALTERNATIVE_NAME
uIssuerAlternativeName.__init__
uIssuerAlternativeName.get_values_for_type
uIssuerAlternativeName.__repr__
uIssuerAlternativeName.__eq__
uIssuerAlternativeName.__hash__
uIssuerAlternativeName.public_bytes
aCERTIFICATE_ISSUER
uCertificateIssuer.__init__
uCertificateIssuer.get_values_for_type
uCertificateIssuer.__repr__
uCertificateIssuer.__eq__
uCertificateIssuer.__hash__
uCertificateIssuer.public_bytes
aCRL_REASON
D areason
return
aReasonFlags
aNone
uCRLReason.__init__
uCRLReason.__repr__
uCRLReason.__eq__
uCRLReason.__hash__
D areturn
aReasonFlags
uCRLReason.reason
uCRLReason.public_bytes
aINVALIDITY_DATE
D ainvalidity_date
return
udatetime.datetime
aNone
uInvalidityDate.__init__
uInvalidityDate.__repr__
uInvalidityDate.__eq__
uInvalidityDate.__hash__
D areturn
udatetime.datetime
uInvalidityDate.invalidity_date
invalidity_date_utc
uInvalidityDate.invalidity_date_utc
uInvalidityDate.public_bytes
aPRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
D asigned_certificate_timestamps
return
utyping.Iterable[SignedCertificateTimestamp]
aNone
uPrecertificateSignedCertificateTimestamps.__init__
T a_signed_certificate_timestamps
uPrecertificateSignedCertificateTimestamps.__repr__
uPrecertificateSignedCertificateTimestamps.__hash__
uPrecertificateSignedCertificateTimestamps.__eq__
uPrecertificateSignedCertificateTimestamps.public_bytes
aSIGNED_CERTIFICATE_TIMESTAMPS
uSignedCertificateTimestamps.__init__
uSignedCertificateTimestamps.__repr__
uSignedCertificateTimestamps.__hash__
uSignedCertificateTimestamps.__eq__
uSignedCertificateTimestamps.public_bytes
aNONCE
D anonce
return
bytes
aNone
uOCSPNonce.__init__
uOCSPNonce.__eq__
uOCSPNonce.__hash__
uOCSPNonce.__repr__
uOCSPNonce.nonce
uOCSPNonce.public_bytes
aACCEPTABLE_RESPONSES
D aresponses
return
utyping.Iterable[ObjectIdentifier]
aNone
uOCSPAcceptableResponses.__init__
uOCSPAcceptableResponses.__eq__
uOCSPAcceptableResponses.__hash__
uOCSPAcceptableResponses.__repr__
D areturn
utyping.Iterator[ObjectIdentifier]
uOCSPAcceptableResponses.__iter__
uOCSPAcceptableResponses.public_bytes
aISSUING_DISTRIBUTION_POINT
D afull_name
relative_name
only_contains_user_certs
only_contains_ca_certs
only_some_reasons
indirect_crl
only_contains_attribute_certs
return
utyping.Iterable[GeneralName] | None
uRelativeDistinguishedName | None
bool
pufrozenset[ReasonFlags] | None
bool
paNone
uIssuingDistributionPoint.__init__
uIssuingDistributionPoint.__repr__
uIssuingDistributionPoint.__eq__
uIssuingDistributionPoint.__hash__
uIssuingDistributionPoint.full_name
uIssuingDistributionPoint.relative_name
uIssuingDistributionPoint.only_contains_user_certs
uIssuingDistributionPoint.only_contains_ca_certs
uIssuingDistributionPoint.only_some_reasons
uIssuingDistributionPoint.indirect_crl
uIssuingDistributionPoint.only_contains_attribute_certs
uIssuingDistributionPoint.public_bytes
aMS_CERTIFICATE_TEMPLATE
D atemplate_id
major_version
minor_version
return
aObjectIdentifier
uint | None
uint | None
aNone
uMSCertificateTemplate.__init__
uMSCertificateTemplate.template_id
uMSCertificateTemplate.major_version
uMSCertificateTemplate.minor_version
uMSCertificateTemplate.__repr__
uMSCertificateTemplate.__eq__
uMSCertificateTemplate.__hash__
uMSCertificateTemplate.public_bytes
D aid
url
text
return
uObjectIdentifier | None
ustr | None
ustr | None
aNone
uNamingAuthority.__init__
D areturn
uObjectIdentifier | None
uNamingAuthority.id
uNamingAuthority.url
uNamingAuthority.text
uNamingAuthority.__repr__
uNamingAuthority.__eq__
uNamingAuthority.__hash__
D anaming_authority
profession_items
profession_oids
registration_number
add_profession_info
return
uNamingAuthority | None
utyping.Iterable[str]
utyping.Iterable[ObjectIdentifier] | None
ustr | None
ubytes | None
aNone
uProfessionInfo.__init__
D areturn
uNamingAuthority | None
uProfessionInfo.naming_authority
D areturn
ulist[str]
uProfessionInfo.profession_items
D areturn
ulist[ObjectIdentifier] | None
uProfessionInfo.profession_oids
uProfessionInfo.registration_number
uProfessionInfo.add_profession_info
uProfessionInfo.__repr__
uProfessionInfo.__eq__
uProfessionInfo.__hash__
D aadmission_authority
naming_authority
profession_infos
return
uGeneralName | None
uNamingAuthority | None
utyping.Iterable[ProfessionInfo]
aNone
uAdmission.__init__
D areturn
uGeneralName | None
uAdmission.admission_authority
uAdmission.naming_authority
D areturn
ulist[ProfessionInfo]
uAdmission.profession_infos
uAdmission.__repr__
uAdmission.__eq__
uAdmission.__hash__
aADMISSIONS
D aauthority
admissions
return
uGeneralName | None
utyping.Iterable[Admission]
aNone
uAdmissions.__init__
T a_admissions
uAdmissions.authority
uAdmissions.__repr__
uAdmissions.__eq__
uAdmissions.__hash__
uAdmissions.public_bytes
D aoid
value
return
aObjectIdentifier
bytes
aNone
uUnrecognizedExtension.__init__
uUnrecognizedExtension.oid
uUnrecognizedExtension.value
uUnrecognizedExtension.__repr__
uUnrecognizedExtension.__eq__
uUnrecognizedExtension.__hash__
uUnrecognizedExtension.public_bytes
ucryptography\x509\extensions.py
T a.0
info
T a.0
admission
T a.0
wxT a.0
wiatype
T a.0
name
T a.0
wrT a.0
sct
T a.0
item
T a.0
oid
u<module cryptography.x509.extensions>
T a__class__
T aself
other
T aself
T aself
aci
T aself
fn
crl_issuer
T aself
ps
es
T aself
pq
T aself
profession_oids
T aself
access_method
access_location
T aself
admission_authority
naming_authority
profession_infos
T aself
authority
admissions
T aself
descriptions
T aself
key_identifier
authority_cert_issuer
authority_cert_serial_number
T aself
ca
path_length
T aself
distribution_points
T aself
crl_number
T aself
reason
T aself
general_names
T aself
policies
T aself
full_name
relative_name
reasons
crl_issuer
T aself
msg
oid
a__class__
T aself
usages
T aself
oid
critical
value
T aself
extensions
T aself
skip_certs
T aself
invalidity_date
T	aself
full_name
relative_name
only_contains_user_certs
only_contains_ca_certs
only_some_reasons
indirect_crl
only_contains_attribute_certs
crl_constraints
T
self
digital_signature
content_commitment
key_encipherment
data_encipherment
key_agreement
key_cert_sign
crl_sign
encipher_only
decipher_only
T aself
template_id
major_version
minor_version
T aself
permitted_subtrees
excluded_subtrees
T aself
id
url
text
T aself
organization
notice_numbers
T aself
responses
T aself
nonce
T aself
require_explicit_policy
inhibit_policy_mapping
T aself
policy_identifier
policy_qualifiers
T aself
signed_certificate_timestamps
T aself
naming_authority
profession_items
profession_oids
registration_number
add_profession_info
T aself
digest
T aself
features
T aself
oid
value
T aself
notice_reference
explicit_text
T aself
encipher_only
decipher_only
T apublic_key
data
serialized
T afield_name
len_method
iter_method
getitem_method
T aself
tree
T acls
public_key
digest
T acls
ski
T acls
public_key
T aself
extclass
ext
T aself
oid
ext
T aself
type
T aself
type
objs
T aself
idx
field_name
T afield_name
T aself
field_name
a__spec__
.cryptography.x509.general_name
a
encode
T aascii
uRFC822Name values should be passed as an A-label string. This means unicode characters should be encoded via a library like idna.
uvalue must be string
parseaddr
uInvalid rfc822name value
a_value
a__new__
u<RFC822Name(value=
value

u)>
aRFC822Name
uDNSName values should be passed as an A-label string. This means unicode characters should be encoded via a library like idna.
u<DNSName(value=
aDNSName
uURI values should be passed as an A-label string. This means unicode characters should be encoded via a library like idna.
u<UniformResourceIdentifier(value=
aUniformResourceIdentifier
aName
uvalue must be a Name
u<DirectoryName(value=
aDirectoryName
aObjectIdentifier
uvalue must be an ObjectIdentifier
u<RegisteredID(value=
aRegisteredID
ipaddress
aIPv4Address
aIPv6Address
aIPv4Network
aIPv6Network
uvalue must be an instance of ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, or ipaddress.IPv6Network
packed
network_address
netmask
u<IPAddress(value=
aIPAddress
utype_id must be an ObjectIdentifier
uvalue must be a binary string
a_type_id
u<OtherName(type_id=
type_id
u, value=
aOtherName
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
typing
uemail.utils
T aparseaddr
ucryptography.x509.name
T aName
ucryptography.x509.oid
T aObjectIdentifier
aUnion
a_IPAddressTypes
T EException
a__prepare__
aUnsupportedGeneralNameType
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
