# Reconstructed from integrated Nuitka blob
# Module: ucryptography.x509.general_name

a__qualname__
a__orig_bases__
metaclass
aABCMeta
T aGeneralName
T
aGeneralName
property
abstractmethod
D areturn
utyping.Any

Return the value of the object
uGeneralName.value
D avalue
return
str
aNone
a__init__
uRFC822Name.__init__
D areturn
str
uRFC822Name.value
classmethod
D avalue
return
str
aRFC822Name
a_init_without_validation
uRFC822Name._init_without_validation
a__repr__
uRFC822Name.__repr__
D aother
return
object
bool
a__eq__
uRFC822Name.__eq__
D areturn
int
a__hash__
uRFC822Name.__hash__
uDNSName.__init__
uDNSName.value
D avalue
return
str
aDNSName
uDNSName._init_without_validation
uDNSName.__repr__
uDNSName.__eq__
uDNSName.__hash__
uUniformResourceIdentifier.__init__
uUniformResourceIdentifier.value
D avalue
return
str
aUniformResourceIdentifier
uUniformResourceIdentifier._init_without_validation
uUniformResourceIdentifier.__repr__
uUniformResourceIdentifier.__eq__
uUniformResourceIdentifier.__hash__
D avalue
return
aName
aNone
uDirectoryName.__init__
D areturn
aName
uDirectoryName.value
uDirectoryName.__repr__
uDirectoryName.__eq__
uDirectoryName.__hash__
D avalue
return
aObjectIdentifier
aNone
uRegisteredID.__init__
D areturn
aObjectIdentifier
uRegisteredID.value
uRegisteredID.__repr__
uRegisteredID.__eq__
uRegisteredID.__hash__
D avalue
return
a_IPAddressTypes
aNone
uIPAddress.__init__
D areturn
a_IPAddressTypes
uIPAddress.value
D areturn
bytes
a_packed
uIPAddress._packed
uIPAddress.__repr__
uIPAddress.__eq__
uIPAddress.__hash__
D atype_id
value
return
aObjectIdentifier
bytes
aNone
uOtherName.__init__
uOtherName.type_id
uOtherName.value
uOtherName.__repr__
uOtherName.__eq__
uOtherName.__hash__
ucryptography\x509\general_name.py
u<module cryptography.x509.general_name>
T a__class__
T aself
other
T aself
T aself
value
T aself
type_id
value
T aself
value
name
address
T acls
value
instance
a__spec__
.cryptography.x509.name
4
D u
w#abinascii
hexlify
decode
T autf8
replace
T w\u\\
T w"u\"
T w+u\+
T w,u\,
T w;u\;
T w<u\<
T w>u\>
T w
u\00
T w#w w\w :nq nu\
uEscape special characters in RFC4514 Distinguished Name value.
sub
u_unescape_dn_value.<locals>.sub
a_RFC4514NameParser
a_PAIR_RE
group
T l l aObjectIdentifier
uoid argument must be an ObjectIdentifier instance.
a_ASN1Type
aBitString
aNameOID
aX500_UNIQUE_IDENTIFIER
uoid must be X500_UNIQUE_IDENTIFIER for BitString type.
uvalue must be bytes for BitString
uvalue argument must be a str
a_NAMEOID_LENGTH_LIMIT
get
encode
uAttribute's length must be >=
u and <=
u, but it was
warnings
warn
D astacklevel
l a_NAMEOID_DEFAULT_TYPE
aUTF8String
u_type must be from the _ASN1Type enum
a_oid
a_value
a_type
a_NAMEOID_TO_NAME
oid
dotted_string

The short attribute name (for example "CN") if available,
otherwise the OID dotted string.
rfc4514_attribute_name
w=a_escape_dn_value
value

Format as RFC4514 Distinguished Name string.
Use short attribute name if available, otherwise fall back to OID
dotted string.
aNameAttribute
u<NameAttribute(oid=
u, value=
u)>
ua relative distinguished name cannot be empty
uattributes must be an iterable of NameAttribute
a_attributes
a_attribute_set
uduplicate attributes are not allowed
u<genexpr>
uRelativeDistinguishedName.__init__.<locals>.<genexpr>
w+u
Format as RFC4514 Distinguished Name string.
Within each RDN, attributes are joined by '+', although that is rarely
used in certificates.
rfc4514_string
attr_name_overrides
uRelativeDistinguishedName.rfc4514_string.<locals>.<genexpr>
aRelativeDistinguishedName
u<RelativeDistinguishedName(
cast
aList
uattributes must be a list of NameAttribute or a list RelativeDistinguishedName
uName.__init__.<locals>.<genexpr>
parse
w,u
Format as RFC4514 Distinguished Name string.
For example 'CN=foobar.com,O=Foo Corp,C=US'
An X.509 name is a two-level structure: a list of sets of attributes.
Each list element is separated by ',' and within each list element, set
elements are separated by '+'. The latter is almost never used in
real world certificates. According to RFC4514 section 2.1 the
RDNSequence must be reversed when converting to string representation.
uName.rfc4514_string.<locals>.<genexpr>
rust_x509
encode_name_bytes
aName
self
a__iter__
uName.__iter__
uName.__len__.<locals>.<genexpr>
u<Name(
uName.__repr__.<locals>.<genexpr>
a_data
a_idx
a_attr_name_overrides
a_has_data
a_peek
match
T apos
a_parse_rdn
a_read_char
T w,ardns

Parses the `data` string and converts it to a Name.
According to RFC4514 section 2.1 the RDNSequence must be
reversed when converting to string representation. So, when
we parse it, we need to reverse again to get the RDNs on the
correct order.
a_parse_na
T w+anas
a_read_re
a_OID_RE
a_DESCR_RE
a_NAME_TO_NAMEOID
oid_value
T w=a_HEXSTRING_RE
unhexlify
:l nna_STRING_RE
a_unescape_dn_value
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
re
sys
typing
cryptography
T autils
utils
ucryptography.hazmat.bindings._rust
T ax509
x509
ucryptography.x509.oid
T aNameOID
aObjectIdentifier
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
