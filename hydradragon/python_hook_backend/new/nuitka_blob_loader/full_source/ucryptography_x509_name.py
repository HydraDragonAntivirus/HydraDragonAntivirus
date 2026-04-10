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
udict[ObjectIdentifier, _ASN1Type]
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
items
T l pT l l@D aval
return
ustr | bytes
str
D aval
return
str
pT nD a_validate
tD aoid
value
a_type
a_validate
return
aObjectIdentifier
ustr | bytes
u_ASN1Type | None
bool
aNone
a__init__
uNameAttribute.__init__
D areturn
aObjectIdentifier
uNameAttribute.oid
D areturn
ustr | bytes
uNameAttribute.value
D areturn
str
uNameAttribute.rfc4514_attribute_name
D aattr_name_overrides
return
u_OidNameMap | None
str
uNameAttribute.rfc4514_string
D aother
return
object
bool
a__eq__
uNameAttribute.__eq__
D areturn
int
a__hash__
uNameAttribute.__hash__
a__repr__
uNameAttribute.__repr__
D aattributes
utyping.Iterable[NameAttribute]
uRelativeDistinguishedName.__init__
D aoid
return
aObjectIdentifier
ulist[NameAttribute]
get_attributes_for_oid
uRelativeDistinguishedName.get_attributes_for_oid
uRelativeDistinguishedName.rfc4514_string
uRelativeDistinguishedName.__eq__
uRelativeDistinguishedName.__hash__
D areturn
utyping.Iterator[NameAttribute]
uRelativeDistinguishedName.__iter__
a__len__
uRelativeDistinguishedName.__len__
uRelativeDistinguishedName.__repr__
overload
D aattributes
return
utyping.Iterable[NameAttribute]
aNone
uName.__init__
D aattributes
return
utyping.Iterable[RelativeDistinguishedName]
aNone
D aattributes
return
utyping.Iterable[NameAttribute | RelativeDistinguishedName]
aNone
D adata
attr_name_overrides
return
str
u_NameOidMap | None
aName
from_rfc4514_string
uName.from_rfc4514_string
uName.rfc4514_string
uName.get_attributes_for_oid
D areturn
ulist[RelativeDistinguishedName]
uName.rdns
D abackend
return
utyping.Any
bytes
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
D adata
attr_name_overrides
return
str
a_NameOidMap
aNone
u_RFC4514NameParser.__init__
D areturn
bool
u_RFC4514NameParser._has_data
D areturn
ustr | None
u_RFC4514NameParser._peek
D ach
return
str
aNone
u_RFC4514NameParser._read_char
u_RFC4514NameParser._read_re
D areturn
aName
u_RFC4514NameParser.parse
D areturn
aRelativeDistinguishedName
u_RFC4514NameParser._parse_rdn
D areturn
aNameAttribute
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
a__spec__
.cryptography.x509.oid
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucryptography.hazmat._oid
T aAttributeOID
aAuthorityInformationAccessOID
aCertificatePoliciesOID
aCRLEntryExtensionOID
aExtendedKeyUsageOID
aExtensionOID
aNameOID
aObjectIdentifier
aOCSPExtensionOID
aPublicKeyAlgorithmOID
aSignatureAlgorithmOID
aSubjectInformationAccessOID
aAttributeOID
aAuthorityInformationAccessOID
aCertificatePoliciesOID
aCRLEntryExtensionOID
aExtendedKeyUsageOID
aExtensionOID
aNameOID
aObjectIdentifier
aOCSPExtensionOID
aPublicKeyAlgorithmOID
aSignatureAlgorithmOID
aSubjectInformationAccessOID
L aAttributeOID
aAuthorityInformationAccessOID
aCRLEntryExtensionOID
aCertificatePoliciesOID
aExtendedKeyUsageOID
aExtensionOID
aNameOID
aOCSPExtensionOID
aObjectIdentifier
aPublicKeyAlgorithmOID
aSignatureAlgorithmOID
aSubjectInformationAccessOID
a__all__
ucryptography\x509\oid.py
u<module cryptography.x509.oid>

a__spec__
.cryptography.x509.verification
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
ucryptography.hazmat.bindings._rust
T ax509
x509
rust_x509
ucryptography.x509.general_name
T aDNSName
aIPAddress
aDNSName
aIPAddress
L aClientVerifier
aPolicyBuilder
aServerVerifier
aStore
aSubject
aVerificationError
aVerifiedClient
a__all__
aStore
aUnion
aSubject
aVerifiedClient
aClientVerifier
aServerVerifier
aPolicyBuilder
aVerificationError
ucryptography\x509\verification.py
u<module cryptography.x509.verification>

a__spec__
.cytoolz._signatures
O
create_signature_registry
cytoolz_info
module_info
update
a__doc__
a__file__
origin
has_location
a__cached__
utoolz._signatures
T w*T a_is_arity
a_has_varargs
a_has_keywords
a_num_required_args
a_is_partial_args
a_is_valid_args
a_is_arity
a_has_varargs
a_has_keywords
a_num_required_args
a_is_partial_args
a_is_valid_args
dict
u<lambda>
T nFTaassoc
assoc_in
dissoc
get_in
itemfilter
itemmap
keyfilter
keymap
merge
merge_with
update_in
valfilter
valmap
ucytoolz.dicttoolz
T nT nnT aapply
aCompose
complement
compose
compose_left
curry
do
excepts
flip
a_flip
identity
juxt
memoize
a_memoize
pipe
return_none
thread_first
thread_last
ucytoolz.functoolz
T a__no__default__
T'aaccumulate
concat
concatv
cons
count
diff
drop
first
frequencies
get
getter
groupby
identity
interleave
interpose
isdistinct
isiterable
iterate
join
last
mapcat
merge_sorted
nth
partition
partition_all
peek
peekn
pluck
random_sample
reduceby
remove
rest
second
sliding_window
tail
take
take_nth
topk
unique
ucytoolz.itertoolz
T acountby
partitionby
ucytoolz.recipes
update_signature_registry
ucytoolz\_signatures.py
T aargs
kwargs
T abinop
seq
initial
T acache
key
T wdakey
value
factory
T wdakeys
func
default
factory
T wdakeys
kwargs
T wdakeys
value
factory
T adata
funcs
T adicts
kwargs
T ael
seq
T aexc
T aexc
func
handler
T afunc
T afunc
waT afunc
wawbT afunc
cache
key
T afunc
wdafactory
T afunc
dicts
kwargs
T afunc
seq
T afunc
seqs
T afunc
wxT afunc_and_args
kwargs
T afuncs
T aind
seq
default
T aind
seqs
default
T aindex
T wkaseq
key
T akey
binop
seq
init
T akey
seq
T akeys
coll
default
no_default
T aleftkey
leftseq
rightkey
rightseq
left_default
right_default
T wnaseq
T wnaseq
pad
T apredicate
wdafactory
T apredicate
seq
T aprob
seq
random_state
T aseq
T aseq
key
T aseqs
T aseqs
kwargs
T aval
forms
T wxu<module cytoolz._signatures>

a__spec__
.cytoolz._version
>
json
loads
version_json
a__doc__
a__file__
origin
has_location
a__cached__

{
"date": "2024-12-12T22:48:53-0600",
"dirty": false,
"error": null,
"full-revisionid": "008f5d83b7b066993d820c0b41c8cc6fb583fd19",
"version": "1.0.1"
}
get_versions
ucytoolz\_version.py
u<module cytoolz._version>

a__spec__
.cytoolz
*
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_cytoolz
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
itertoolz
T w*afunctoolz
dicttoolz
recipes
partial
reduce
sorted
map
filter
compose
comp
curry
flip
memoize

T acurried
curried
a_sigs
update_signature_registry
u1.0.0
a__toolz_version__
a_version
T aget_versions
get_versions
version
a__version__
ucytoolz\__init__.py
u<module cytoolz>
a__spec__
.cytoolz.curried
[
_

Alternate namespace for cytoolz such that all functions are curried
Currying provides implicit partial evaluation of all functions
Example:
Get usually requires two arguments, an index and a collection
>>> from cytoolz.curried import get
>>> get(0, ('a', 'b'))
'a'
When we use it in higher order functions we often want to pass a partially
evaluated form
>>> data = [(1, 2), (11, 22), (111, 222)]
>>> list(map(lambda seq: get(0, seq), data))
[1, 11, 111]
The curried version allows simple expression of partial evaluation
>>> list(map(get(0), data))
[1, 11, 111]
See Also:
cytoolz.functoolz.curry
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_cytoolz
u\not_existing
curried
T aNUITKA_PACKAGE_cytoolz_curried
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
cytoolz

T aoperator
operator
T aapply
comp
complement
compose
compose_left
concat
concatv
count
curry
diff
first
flip
frequencies
identity
interleave
isdistinct
isiterable
juxt
last
memoize
merge_sorted
peek
pipe
second
thread_first
thread_last
apply
comp
complement
compose
compose_left
concat
concatv
count
curry
diff
first
flip
frequencies
identity
interleave
isdistinct
isiterable
juxt
last
memoize
merge_sorted
peek
pipe
second
thread_first
thread_last
exceptions
T amerge
merge_with
merge
merge_with
accumulate
assoc
assoc_in
cons
countby
dissoc
do
drop
excepts
filter
get_in
groupby
interpose
itemfilter
itemmap
iterate
keyfilter
keymap
map
mapcat
nth
partial
partition
partition_all
partitionby
peekn
pluck
random_sample
reduce
reduceby
remove
sliding_window
sorted
tail
take
take_nth
topk
unique
update_in
valfilter
valmap
ucytoolz\curried\__init__.py
u<module cytoolz.curried>
a__spec__
.cytoolz.curried.exceptions
cytoolz
merge
merge_with
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
curry
ucytoolz\curried\exceptions.py
u<module cytoolz.curried.exceptions>
T wdadicts
kwargs
T afunc
wdadicts
kwargs

a__spec__
.cytoolz.curried.operator
w
a__doc__
a__file__
origin
has_location
a__cached__
absolute_import
operator
ucytoolz.functoolz
T acurry
curry
S apos
a__not__
itemgetter
a__abs__
neg
a__invert__
a__pos__
abs
a_abs
invert
a__index__
a__neg__
index
not_
attrgetter
truth
inv
a__inv__
aIGNORE
update
items
callable
ucytoolz\curried\operator.py
u<module cytoolz.curried.operator>

a__spec__
.ecdsa._compat
z
7
integer_types
uTake index'th byte from string, return as integer
cast
T wBuCast the input into array of bytes.
re
sub
u\s+

aUNICODE
T aflags
uRemoves all whitespace from passed in string
binascii
a2b_hex
ascii
ubase16 error: %s
bit_length
uReturn number of bits necessary to represent an integer.
byte_length
val
to_bytes
T alength
byteorder
uConvert integer to bytes.
l l uReturn number of bytes necessary to represent an integer.

Common functions for providing cross-python version compatibility.
a__doc__
a__file__
origin
has_location
a__cached__
sys
six
T ainteger_types
str_idx_as_int
hmac_compat
normalise_bytes
compat26_str
remove_whitespace
from_bytes
bytes_to_int
T nabig
int_to_bytes
uecdsa\_compat.py
u<module ecdsa._compat>
T aval
weT aval
T aval
length
T adata
T aval
length
byteorder
T abuffer_object
T atext
T astring
index
val
a__spec__
.ecdsa._sha3
C
hashlib
new
shake256
digest
bytes_to_int
D abyteorder
little
l@g            L l
l l>l l l$l,l l7l l l
l+l l'l)l-l l l l l l=l8l L l l l	l l l l l ll l l l l l l l l l l l l l l
L l l   g
g      l   g   g      g
l  l  g     g
g     g
g
g
g
g
l   g
g      g
g   g      ;l
l l ;l
l l wcl ws;l
l l l a_rol
wdaPERMUTATION
;l
l l l l wil a_from_le
B
mp
int_to_bytes
a_reinterpret_to_words_and_xor
idx
r_b
a_sha3_transform
append
wmT l
l  aout
a_reinterpret_to_octets
uSemi-generic SHA-3 implementation
a_sha3_raw
l l u
Implementation of the SHAKE-256 algorithm for Ed448
a__doc__
a__file__
origin
has_location
a__cached__
T ashake256
T l@ashake_256
T ETypeError
EValueError
a_compat
T abytes_to_int
int_to_bytes
uecdsa\_sha3.py
u<module ecdsa._sha3>
T wsT wwamp
wjT wswbwjT wxwbT amsg
r_w
o_p
e_b
r_b
wsaidx
blocks
wiwmaout
T
wsaROTATIONS
aPERMUTATION
aRC
rnd
wcwdwiwtwjT amsg
outlen

a__spec__
.ecdsa._version
;
json
loads
version_json
a__doc__
a__file__
origin
has_location
a__cached__

{
"date": "2024-04-08T20:59:55+0200",
"dirty": false,
"error": null,
"full-revisionid": "be70016f8911f79e891a65dcfcb602e5ba866ed3",
"version": "0.19.0"
}
get_versions
uecdsa\_version.py
u<module ecdsa._version>

a__spec__
.ecdsa
H
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_ecdsa
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
six
keys
T aSigningKey
aVerifyingKey
aBadSignatureError
aBadDigestError
aMalformedPointError
aSigningKey
aVerifyingKey
aBadSignatureError
aBadDigestError
aMalformedPointError
curves
T aNIST192p
aNIST224p
aNIST256p
aNIST384p
aNIST521p
aSECP256k1
aBRAINPOOLP160r1
aBRAINPOOLP192r1
aBRAINPOOLP224r1
aBRAINPOOLP256r1
aBRAINPOOLP320r1
aBRAINPOOLP384r1
aBRAINPOOLP512r1
aSECP112r1
aSECP112r2
aSECP128r1
aSECP160r1
aEd25519
aEd448
aBRAINPOOLP160t1
aBRAINPOOLP192t1
aBRAINPOOLP224t1
aBRAINPOOLP256t1
aBRAINPOOLP320t1
aBRAINPOOLP384t1
aBRAINPOOLP512t1
aNIST192p
aNIST224p
aNIST256p
aNIST384p
aNIST521p
aSECP256k1
aBRAINPOOLP160r1
aBRAINPOOLP192r1
aBRAINPOOLP224r1
aBRAINPOOLP256r1
aBRAINPOOLP320r1
aBRAINPOOLP384r1
aBRAINPOOLP512r1
aSECP112r1
aSECP112r2
aSECP128r1
aSECP160r1
aEd25519
aEd448
aBRAINPOOLP160t1
aBRAINPOOLP192t1
aBRAINPOOLP224t1
aBRAINPOOLP256t1
aBRAINPOOLP320t1
aBRAINPOOLP384t1
aBRAINPOOLP512t1
ecdh
T aECDH
aNoKeyError
aNoCurveError
aInvalidCurveError
aInvalidSharedSecretError
aECDH
aNoKeyError
aNoCurveError
aInvalidCurveError
aInvalidSharedSecretError
der
T aUnexpectedDER
aUnexpectedDER

T a_version
a_version
L	acurves
der
ecdsa
ellipticcurve
keys
numbertheory
test_pyecdsa
util
six
a__all__
wbT u
a_hush_pyflakes
get_versions
version
a__version__
uecdsa\__init__.py
u<module ecdsa>
a__spec__
.ecdsa.curves
name
openssl_name
curve
generator
order
ellipticcurve
aCurveEdTw
bit_length
wpl l abaselen
verifying_key_length
orderlen
l asignature_length
oid
der
encode_oid
encoded_oid
aCurve
named_curve
explicit
T anamed_curve
explicit
uOnly 'named_curve' and 'explicit' encodings supported
aUnknownCurveError
T uCan't encode curve using named_curve encoding without associated curve OID
T uTwisted Edwards curves don't support explicit encoding
encode_integer
T l aencode_sequence
aPRIME_FIELD_OID
encode_octet_string
number_to_string
wawbato_bytes
cofactor
uSerialise the curve parameters to binary string.
:param str encoding: the format to save the curve parameters in.
Default is ``named_curve``, with fallback being the ``explicit``
if the OID is not set for the curve.
:param str point_encoding: the point encoding of the generator when
explicit curve encoding is used. Ignored for ``named_curve``
format.
:return: DER encoded ECParameters structure
:rtype: bytes
topem
to_der
uEC PARAMETERS

Serialise the curve parameters to the :term:`PEM` format.
:param str encoding: the format to save the curve parameters in.
Default is ``named_curve``, with fallback being the ``explicit``
if the OID is not set for the curve.
:param str point_encoding: the point encoding of the generator when
explicit curve encoding is used. Ignored for ``named_curve``
format.
:return: PEM encoded ECParameters structure
:rtype: str
S anamed_curve
explicit
uOnly named_curve and explicit encodings supported
normalise_bytes
is_sequence
aUnexpectedDER
T unamed_curve curve parameters not allowed
remove_object
T uUnexpected data after OID
find_curve
T uexplicit curve parameters not allowed
remove_sequence
T uUnexpected data after ECParameters structure
remove_integer
T uUnknown parameter encoding format
remove_octet_string
aCHARACTERISTIC_TWO_FIELD_OID
T uCharacteristic 2 curves unsupported
uUnknown field type: {0}
T uUnexpected data after ECParameters.fieldID.Prime-p element
string_to_number
aCurveFp
aPointJacobi
from_bytes
T auncompressed
compressed
hybrid
T avalid_encodings
order
generator
unknown
curves
uDecode the curve parameters from DER file.
:param data: the binary string to decode the parameters from
:type data: :term:`bytes-like object`
:param valid_encodings: set of names of allowed encodings, by default
ll (set by passing ``None``), supported ones are ``named_curve``
nd ``explicit``
:type valid_encodings: :term:`set-like object`
u<genexpr>
uCurve.from_der.<locals>.<genexpr>
aPY2
encode
find
T c-----BEGIN EC PARAMETERS-----
T uEC PARAMETERS PEM header not found
from_der
unpem
uDecode the curve parameters from PEM file.
:param str string: the text string to decode the parameters from
:param valid_encodings: set of names of allowed encodings, by default
ll (set by passing ``None``), supported ones are ``named_curve``
nd ``explicit``
:type valid_encodings: :term:`set-like object`
uI don't know about the curve with oid %s.I only know about these: %s
uSelect a curve based on its OID
:param tuple[int,...] oid_curve: ASN.1 Object Identifier of the
curve to return, like ``(1, 2, 840, 10045, 3, 1, 7)`` for ``NIST256p``.
:raises UnknownCurveError: When the oid doesn't match any of the supported
curves
:rtype: ~ecdsa.curves.Curve
uCurve with name {0!r} unknown, only curves supported: {1}
uSelect a curve based on its name.
Returns a :py:class:`~ecdsa.curves.Curve` object with a ``name`` name.
Note that ``name`` is case-sensitve.
:param str name: Name of the curve to return, like ``NIST256p`` or
``prime256v1``
:raises UnknownCurveError: When the name doesn't match any of the supported
curves
:rtype: ~ecdsa.curves.Curve
a__doc__
a__file__
origin
has_location
a__cached__
division
six
T aPY2

T ader
ecdsa
ellipticcurve
eddsa
ecdsa
eddsa
util
T aorderlen
number_to_string
string_to_number
a_compat
T anormalise_bytes
bit_length
L"aUnknownCurveError
orderlen
aCurve
aSECP112r1
aSECP112r2
aSECP128r1
aSECP160r1
aNIST192p
aNIST224p
aNIST256p
aNIST384p
aNIST521p
curves
find_curve
curve_by_name
aSECP256k1
aBRAINPOOLP160r1
aBRAINPOOLP160t1
aBRAINPOOLP192r1
aBRAINPOOLP192t1
aBRAINPOOLP224r1
aBRAINPOOLP224t1
aBRAINPOOLP256r1
aBRAINPOOLP256t1
aBRAINPOOLP320r1
aBRAINPOOLP320t1
aBRAINPOOLP384r1
aBRAINPOOLP384t1
aBRAINPOOLP512r1
aBRAINPOOLP512t1
aPRIME_FIELD_OID
aCHARACTERISTIC_TWO_FIELD_OID
aEd25519
aEd448
a__all__
T l l l  l Nl pT l l l  l Nl l T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
