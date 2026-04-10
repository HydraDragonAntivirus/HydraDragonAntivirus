# Reconstructed from integrated Nuitka blob
# Module: uasn1crypto.core


The basis of all ASN.1 values
a__qualname__
classmethod
uAsn1Value.load
T
nnFnnnnnnnuAsn1Value.__init__
a__str__
uAsn1Value.__str__
uAsn1Value.__repr__
uAsn1Value.__bytes__
uAsn1Value.__unicode__
uAsn1Value._new_instance
a__copy__
uAsn1Value.__copy__
a__deepcopy__
uAsn1Value.__deepcopy__
uAsn1Value.copy
uAsn1Value.retag
uAsn1Value.untag
uAsn1Value._copy
uAsn1Value.debug
uAsn1Value.dump
a__orig_bases__

Basic functionality that allows for mapping values from ints or OIDs to
python unicode strings
uValueMap._setup
aCastable

A mixin to handle converting an object between different classes that
represent the same encoded value, but with different rules for converting
to and from native Python values
cast
uCastable.cast

A mixin to handle string types that may be constructed from chunks
contained within an indefinite length BER-encoded container
uConstructable._merge_chunks
uConstructable._as_chunk
uConstructable._setable_native
uConstructable._copy
aVoid

A representation of an optional value that is not present. Has .native
property and .dump() method to be compatible with other value classes.
a__eq__
uVoid.__eq__
a__nonzero__
uVoid.__nonzero__
a__len__
uVoid.__len__
uVoid.__iter__
property

The native Python datatype representation of this value
:return:
None
uVoid.native
uVoid.dump

A value class that can contain any value, and allows for easy parsing of
the underlying encoded value using a spec. This is normally contained in
a Structure that has an ObjectIdentifier field and _oid_pair and _oid_specs
defined.
uAny.__init__
uAny.native
uAny.parsed
uAny.parse
uAny._copy
uAny.dump

A class to handle when a value may be one of several options
uChoice.load
uChoice._setup
uChoice.__init__
uChoice.contents
setter
name
uChoice.name
uChoice.parse
uChoice.chosen
uChoice.native
uChoice.validate
uChoice._format_class_tag
uChoice._copy
uChoice.dump
aConcat

A class that contains two or more encoded child values concatentated
together. THIS IS NOT PART OF THE ASN.1 SPECIFICATION! This exists to handle
the x509.TrustedCertificate() class for OpenSSL certificates containing
extra information.
uConcat.load
T nnFuConcat.__init__
uConcat.__str__
uConcat.__bytes__
uConcat.__unicode__
uConcat.__repr__
uConcat.__copy__
uConcat.__deepcopy__
uConcat.copy
uConcat._copy
uConcat.debug
uConcat.dump
uConcat.contents
uConcat.__len__
uConcat.__getitem__
uConcat.__setitem__
uConcat.__iter__

Sets the class_ and method attributes for primitive, universal values
T nnnuPrimitive.__init__
uPrimitive.set
uPrimitive.dump
a__ne__
uPrimitive.__ne__
uPrimitive.__eq__

A base class for all strings that have a known encoding. In general, we do
not worry ourselves with confirming that the decoded values match a specific
set of characters, only that they are decoded into a Python unicode string
latin1
uAbstractString.set
uAbstractString.__unicode__
uAbstractString._copy
uAbstractString.native
aBoolean

Represents a boolean in both ASN.1 and Python
uBoolean.set
uBoolean.__nonzero__
uBoolean.__bool__
uBoolean.native

Represents an integer in both ASN.1 and Python
uInteger.set
uInteger.__int__
uInteger.native

A mixin for IntegerBitString and BitString to parse the contents as an integer.
u_IntegerBitString._as_chunk
u_IntegerBitString._chunks_to_int
u_IntegerBitString._copy
u_IntegerBitString.unused_bits
aBitString

Represents a bit string from ASN.1 as a Python tuple of 1s and 0s
uBitString._setup
uBitString.set
uBitString.__getitem__
uBitString.__setitem__
uBitString.native

Represents a bit string in ASN.1 as a Python byte string
uOctetBitString.set
uOctetBitString.__bytes__
uOctetBitString._copy
uOctetBitString._as_chunk
uOctetBitString.native
uOctetBitString.unused_bits
aIntegerBitString

Represents a bit string in ASN.1 as a Python integer
uIntegerBitString.set
uIntegerBitString.native

Represents a byte string in both ASN.1 and Python
uOctetString.set
uOctetString.__bytes__
uOctetString._copy
uOctetString.native
aIntegerOctetString

Represents a byte string in ASN.1 as a Python integer
uIntegerOctetString.set
uIntegerOctetString.native
set_encoded_width
uIntegerOctetString.set_encoded_width
uParsableOctetString.__init__
uParsableOctetString.set
uParsableOctetString.parse
uParsableOctetString.__bytes__
uParsableOctetString._setable_native
uParsableOctetString._copy
uParsableOctetString.native
uParsableOctetString.parsed
uParsableOctetString.dump
aParsableOctetBitString
uParsableOctetBitString.set
uParsableOctetBitString._as_chunk
aNull

Represents a null value in ASN.1 as None in Python
uNull.set
uNull.native
aObjectIdentifier

Represents an object identifier in ASN.1 as a Python unicode dotted
integer string
l amap
uObjectIdentifier.map
unmap
uObjectIdentifier.unmap
uObjectIdentifier.set
uObjectIdentifier.__unicode__
uObjectIdentifier.dotted
uObjectIdentifier.native
aObjectDescriptor

Represents an object descriptor from ASN.1 - no Python implementation
aInstanceOf

Represents an instance from ASN.1 - no Python implementation
aReal

Represents a real number from ASN.1 - no Python implementation
l	aEnumerated

Represents a enumerated list of integers from ASN.1 as a Python
unicode string
uEnumerated.set
uEnumerated.native
aUTF8String

Represents a UTF-8 string from ASN.1 as a Python unicode string
l uutf-8
aRelativeOid
lu
Represents a sequence of fields from ASN.1 as a Python object with a
dict-like interface
l uSequence.__init__
uSequence.contents
uSequence._is_mutated
uSequence._lazy_child
uSequence.__len__
uSequence.__getitem__
uSequence.__setitem__
a__delitem__
uSequence.__delitem__
uSequence._set_contents
uSequence._setup
uSequence._determine_spec
uSequence._make_value
uSequence._parse_children
uSequence.spec
uSequence.native
uSequence._copy
uSequence.debug
uSequence.dump

Represents a sequence (ordered) of a single type of values from ASN.1 as a
Python object with a list-like interface
T nnnnuSequenceOf.__init__
uSequenceOf.contents
uSequenceOf._is_mutated
uSequenceOf._lazy_child
uSequenceOf._make_value
uSequenceOf.__len__
uSequenceOf.__getitem__
uSequenceOf.__setitem__
uSequenceOf.__delitem__
a__contains__
uSequenceOf.__contains__
uSequenceOf.append
uSequenceOf._set_contents
uSequenceOf._parse_children
uSequenceOf.spec
uSequenceOf.native
uSequenceOf._copy
uSequenceOf.debug
uSequenceOf.dump
aSet

Represents a set of fields (unordered) from ASN.1 as a Python object with a
dict-like interface
l uSet._setup
uSet._parse_children
uSet._set_contents
aSetOf

Represents a set (unordered) of a single type of values from ASN.1 as a
Python object with a list-like interface
uSetOf._set_contents
aEmbeddedPdv

A sequence structure
l aNumericString

Represents a numeric string from ASN.1 as a Python unicode string
l aPrintableString

Represents a printable string from ASN.1 as a Python unicode string
l aTeletexString

Represents a teletex string from ASN.1 as a Python unicode string
l ateletex
aVideotexString

Represents a videotex string from ASN.1 as a Python byte string
l aIA5String

Represents an IA5 string from ASN.1 as a Python unicode string
l aascii
aAbstractTime

Represents a time from ASN.1 as a Python datetime.datetime object
uAbstractTime._parsed_time
uAbstractTime.native
aUTCTime

Represents a UTC time from ASN.1 as a timezone aware Python datetime.datetime object
l u
^
# YYMMDD
(?P<year>\d{2})
(?P<month>\d{2})
(?P<day>\d{2})
# hhmm or hhmmss
(?P<hour>\d{2})
(?P<minute>\d{2})
(?P<second>\d{2})?
# Matches nothing, needed because GeneralizedTime uses this.
(?P<fraction>)
# Z or [-+]hhmm
(?:
(?P<zulu>Z)
|
(?:
(?P<dsign>[-+])
(?P<dhour>\d{2})
(?P<dminute>\d{2})
)
)
$
wXuUTCTime.set
uUTCTime._get_datetime
aGeneralizedTime

Represents a generalized time from ASN.1 as a Python datetime.datetime
object or asn1crypto.util.extended_datetime object in UTC
l u
^
# YYYYMMDD
(?P<year>\d{4})
(?P<month>\d{2})
(?P<day>\d{2})
# hh or hhmm or hhmmss
(?P<hour>\d{2})
(?:
(?P<minute>\d{2})
(?P<second>\d{2})?
)?
# Optional fraction; [.,]dddd (one or more decimals)
# If Seconds are given, it's fractions of Seconds.
# Else if Minutes are given, it's fractions of Minutes.
# Else it's fractions of Hours.
(?:
[,.]
(?P<fraction>\d+)
)?
# Optional timezone. If left out, the time is in local time.
# Z or [-+]hh or [-+]hhmm
(?:
(?P<zulu>Z)
|
(?:
(?P<dsign>[-+])
(?P<dhour>\d{2})
(?P<dminute>\d{2})?
)
)?
$
uGeneralizedTime.set
uGeneralizedTime._get_datetime
aGraphicString

Represents a graphic string from ASN.1 as a Python unicode string
l aVisibleString

Represents a visible string from ASN.1 as a Python unicode string
l aGeneralString

Represents a general string from ASN.1 as a Python unicode string
l aUniversalString

Represents a universal string from ASN.1 as a Python unicode string
l uutf-32-be
aCharacterString

Represents a character string from ASN.1 as a Python unicode string
l aBMPString

Represents a BMP string from ASN.1 as a Python unicode string
l uutf-16-be
T l
nnFuasn1crypto\core.py
T a.0
chunk
T act
u<module asn1crypto.core>
T a__class__
T aself
T aself
chunks
chunk
T aself
item
child
T aself
new_obj
T aself
memo
new_obj
T aself
key
name
w_aparams
T aself
key
T aself
other
self_bases
other_bases
T aself
other
T aself
key
is_int
T aself
key
weaargs
T aself
value
kwargs
weaargs
T aself
explicit
implicit
no_explicit
tag_type
class_
tag
optional
default
contents
method
cls
invalid_class
weaargs
T	aself
name
value
kwargs
w_aspec
params
weaargs
Taself
value
contents
strict
contents_len
offset
spec
child_value
extra_bytes
weaargs
index
data
T aself
value
parsed
kwargs
set_parsed
T aself
value
default
contents
kwargs
weaargs
T aself
value
default
kwargs
check_existing
keys
unused_keys
key
index
weaargs
T
self
value
default
contents
spec
kwargs
index
child
weaargs
T aself
info
T aself
index
T aself
key
value
is_int
new_native
max_key
T aself
key
value
T
self
key
value
field_name
field_spec
value_spec
field_params
w_anew_value
invalid_value
T aself
key
value
new_value
T aself
unused_bits_len
mask
last_byte
zeroed_byte
value
unused_bits
T aself
unused_bits_len
T aself
unused_bits_len
value
bits
unused_bits
T aprefix
self
has_header
method_name
class_name
class_
tag
T aclass_
method
tag
header
contents
trailer
spec
spec_params
nested_spec
header_set
no_explicit
value
original_explicit
explicit_info
parsed_class
parsed_method
parsed_tag
to_parse
explicit_header
explicit_trailer
expected_class
expected_tag
info
w_aparsed_header
parsed_trailer
weaargs
ber_indef
is_bad_tag
original_value
T aparams
spec
required_class
required_tag
T aself
value
total_bits
unused_bits
chunk
bits
T aself
other
copy_func
a__class__
T aself
other
copy_func
T aself
other
copy_func
child
a__class__
T	aself
index
name
field_spec
field_params
value_spec
spec_override
callback
oid
T avalue
params
retag
class_
tag
T aself
class_
tag
T aself
parsed
T avalue
bits
result
T aself
mutated
child
T aself
index
child
Taself
field_name
field_spec
value_spec
field_params
value
specs_different
is_any
is_asn1value
is_tuple
is_dict
wrapper
new_value
T aself
value
new_value
wrapper
params
T aself
pointer
contents_len
output
sub_value
T	aencoded_data
pointer
spec
spec_params
strict
encoded_len
info
new_pointer
extra_bytes
T aself
recurse
cls
index
w_aparams
field_name
field_spec
value_spec
field_params
contents_length
child_pointer
field
field_len
parts
again
spec_override
choice_match
tester
child
missed_fields
prev_field
prev_field_info
plural
missed_field_names
name
weaargs
T aself
recurse
contents_length
child_pointer
parts
child
weaargs
T aself
recurse
cls
index
w_aparams
field_name
field_spec
value_spec
field_params
child_map
contents_length
child_pointer
seen_field
parts
id_
field
spec_override
child
total_fields
name
missing
weaargs
T aself
string
wmagroups
tz
sign
fract
fract_usec
T aself
force
contents
index
info
child
child_dump
default_value
T aself
force
contents
child
T	aself
force
child_tag_encodings
index
child
child_encoding
name
spec
field_params
T aself
force
child_encodings
child
T aself
cls
T aself
cls
index
info
id_
T aself
cls
index
field
has_callback
is_mapped_oid
T aself
cls
key
value
T aparams
T aself
value
T aself
other_class
new_obj
T aself
nest_level
prefix
has_parsed
T aself
nest_level
prefix
child
T aself
nest_level
prefix
field_name
child
T aself
output
part
byte
T aself
force
T aself
force
contents
header
class_
tag
T aself
force
class_
tag
T aself
force
native
T aself
force
index
field_name
w_aparams
T acls
encoded_data
strict
kwargs
spec
value
w_T acls
encoded_data
strict
kwargs
value
w_T acls
encoded_data
strict
T aencoded_data
strict
T acls
value
T aself
parsed
fraction
value
T aself
int_value
bit_count
bits
index
bit
name
T aself
a__
T aself
index
child
name
weaargs
T aself
weaargs
T	aself
spec
spec_params
passed_params
contents
parsed_value
w_weaargs
T aself
w_aspec
params
weaargs
T aself
spec
spec_params
parsed_value
w_T aself
tagging
tag
new_obj
Taself
value
bits
index
key
bit
name
size
size_mod
extra_bits
size_in_bytes
extra_bits_byte
value_bytes
T aself
value
fraction
T aself
value
first
index
part
encoded_part
T aself
width
T aself
field_name
index
info
T aself
class_
tag
contents
id_
w_aasn1
asn1s
a__spec__
.asn1crypto.keys
OG
[ amath
ceil
log
l f
@amax
d aint_to_bytes
T awidth

Creates an ECPoint object from the X and Y integer coordinates of the
point
:param x:
The X coordinate, as an integer
:param y:
The Y coordinate, as an integer
:return:
An ECPoint object
native
:l
l n:l nnaint_from_bytes
P d d aunwrap
T u
Invalid EC public key - first byte is incorrect
T u
Compressed representations of EC public keys are not supported due
to patent US6252960

Returns the X and Y coordinates for this EC point, as native Python
integers
:return:
A 2-element tuple containing integers (X, Y)
a_map
a_reverse_map
a_key_sizes

Registers a new named elliptic curve that is not included in the
default list of named curves
:param name:
A unicode string of the curve name
:param oid:
A unicode string of the dotted format OID
:param key_size:
An integer of the number of bytes the private key should be
encoded to
name
implicit_ca
T u
Unable to calculate key_size from ECDomainParameters
that are implicitly defined by the CA key
specified
chosen
order
f
@adotted
aNamedCurve

The asn1crypto.keys.NamedCurve %s does not have a registered key length,
please call asn1crypto.keys.NamedCurve.register()
aECPrivateKey
a__setitem__
private_key
a_key_size
contents
byte_cls
set_key_size
a_update_key_size
parameters
aECDomainParameters
key_size

Sets the key_size to ensure the private key is encoded to the proper length
:param key_size:
An integer byte length to encode the private_key to
aIntegerOctetString
set_encoded_width

Ensure the private_key explicit encoding width is set
private_key_algorithm
algorithm
rsa
aRSAPrivateKey
rsassa_pss
dsa
aInteger
ec
x25519
aOctetString
x448
ed25519
ed448
aAsn1Value

private_key must be a byte string or Asn1Value, not %s
type_name
load
aNull
aDSAPrivateKey
aDSAParams
wpwqwgapublic_key
copy

lgorithm must be one of "rsa", "dsa", "ec", not %s
aPrivateKeyAlgorithm
aPrivateKeyAlgorithmId
params
a_algorithm
T l
version
a_public_key

Wraps a private key in a PrivateKeyInfo structure
:param private_key:
A byte string or Asn1Value object of the private key
:param algorithm:
A unicode string of "rsa", "dsa" or "ec"
:return:
A PrivateKeyInfo object
aPrivateKeyInfo
aParsableOctetString
parsed
aAPIException
T uasn1crypto.keys.PrivateKeyInfo().unwrap() has been removed, please use oscrypto.asymmetric.PrivateKey().unwrap() instead

Unwraps the private key into an RSAPrivateKey, DSAPrivateKey or
ECPrivateKey object
:return:
An RSAPrivateKey, DSAPrivateKey or ECPrivateKey object

Only EC keys have a curve, this key is %s
upper

Returns information about the curve used for an EC key
:raises:
ValueError - when the key is not an EC key
:return:
A two-element tuple, with the first element being a unicode string
of "implicit_ca", "specified" or "named". If the first element is
"implicit_ca", the second is None. If "specified", the second is
n OrderedDict that is the native version of SpecifiedECDomain. If
"named", the second is a unicode string of the curve name.

Only DSA keys are generated using a hash algorithm, this key is
%s
l l asha1
sha2

Returns the name of the family of hash algorithms used to generate a
DSA key
:raises:
ValueError - when the key is not a DSA key
:return:
A unicode string of "sha1" or "sha2"

:return:
A unicode string of "rsa", "rsassa_pss", "dsa" or "ec"
a_bit_size
modulus
prime

:return:
The bit size of the private key, as an integer
bit_size

:return:
The byte size of the private key, as an integer
T uasn1crypto.keys.PrivateKeyInfo().public_key has been removed, please use oscrypto.asymmetric.PrivateKey().public_key.unwrap() instead

:return:
If an RSA key, an RSAPublicKey object. If a DSA key, an Integer
object. If an EC key, an ECPointBitString object.
T uasn1crypto.keys.PrivateKeyInfo().public_key_info has been removed, please use oscrypto.asymmetric.PrivateKey().public_key.asn1 instead

:return:
A PublicKeyInfo object derived from this private key.
T uasn1crypto.keys.PrivateKeyInfo().fingerprint has been removed, please use oscrypto.asymmetric.PrivateKey().fingerprint instead

Creates a fingerprint that can be compared with a public key to see if
the two form a pair.
This fingerprint is not compatible with fingerprints generated by any
other software.
:return:
A byte string that is a sha256 hash of selected components (based
on the key type)
aRSAPublicKey
rsaes_oaep
aECPointBitString
dh
aOctetBitString

public_key must be a byte string or Asn1Value, not %s

lgorithm must "rsa", not %s
aPublicKeyAlgorithm
aPublicKeyAlgorithmId
untag
dump
aParsableOctetBitString

Wraps a public key in a PublicKeyInfo structure
:param public_key:
A byte string or Asn1Value object of the public key
:param algorithm:
A unicode string of "rsa"
:return:
A PublicKeyInfo object
T uasn1crypto.keys.PublicKeyInfo().unwrap() has been removed, please use oscrypto.asymmetric.PublicKey().unwrap() instead

Unwraps an RSA public key into an RSAPublicKey object. Does not support
DSA or EC public keys since they do not have an unwrapped form.
:return:
An RSAPublicKey object

Returns the name of the family of hash algorithms used to generate a
DSA key
:raises:
ValueError - when the key is not a DSA key
:return:
A unicode string of "sha1" or "sha2" or None if no parameters are
present

:return:
The bit size of the public key, as an integer

:return:
The byte size of the public key, as an integer
a_sha1
hashlib
digest

:return:
The SHA1 hash of the DER-encoded bytes of this public key info
a_sha256
sha256

:return:
The SHA-256 hash of the DER-encoded bytes of this public key info
T uasn1crypto.keys.PublicKeyInfo().fingerprint has been removed, please use oscrypto.asymmetric.PublicKey().fingerprint instead

Creates a fingerprint that can be compared with a private key to see if
the two form a pair.
This fingerprint is not compatible with fingerprints generated by any
other software.
:return:
A byte string that is a sha256 hash of selected components (based
on the key type)

ASN.1 type classes for public and private keys. Exports the following items:
- DSAPrivateKey()
- ECPrivateKey()
- EncryptedPrivateKeyInfo()
- PrivateKeyInfo()
- PublicKeyInfo()
- RSAPrivateKey()
- RSAPublicKey()
Other type classes are defined that help compose the types listed above.
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
a_errors
T aunwrap
aAPIException
a_types
T atype_name
byte_cls
algos
T a_ForceNullParameters
aDigestAlgorithm
aEncryptionAlgorithm
aRSAESOAEPParams
aRSASSAPSSParams
a_ForceNullParameters
aDigestAlgorithm
aEncryptionAlgorithm
aRSAESOAEPParams
aRSASSAPSSParams
core
T aAny
aAsn1Value
aBitString
aChoice
aInteger
aIntegerOctetString
aNull
aObjectIdentifier
aOctetBitString
aOctetString
aParsableOctetString
aParsableOctetBitString
aSequence
aSequenceOf
aSetOf
aAny
aBitString
aChoice
aObjectIdentifier
aSequence
aSequenceOf
aSetOf
util
T aint_from_bytes
int_to_bytes
a__prepare__
aOtherPrimeInfo
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
