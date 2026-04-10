# Reconstructed from integrated Nuitka blob
# Module: uasn1crypto.keys


Source: https://tools.ietf.org/html/rfc3447#page-46
a__qualname__
exponent
coefficient
a_fields
a__orig_bases__
aOtherPrimeInfos
a_child_spec
aRSAPrivateKeyVersion

Original Name: Version
Source: https://tools.ietf.org/html/rfc3447#page-45
D l
l utwo-prime
multi

Source: https://tools.ietf.org/html/rfc3447#page-45
public_exponent
private_exponent
prime1
prime2
exponent1
exponent2
other_prime_infos
D aoptional
tu
Source: https://tools.ietf.org/html/rfc3447#page-44

The ASN.1 structure that OpenSSL uses to store a DSA private key that is
not part of a PKCS#8 structure. Reversed engineered from english-language
description on linked OpenSSL documentation page.
Original Name: None
Source: https://www.openssl.org/docs/apps/dsa.html

In both PublicKeyInfo and PrivateKeyInfo, the EC public key is a byte
string that is encoded as a bit string. This class adds convenience
methods for converting to and from the byte string to a pair of integers
that are the X and Y coordinates.
a_ECPoint
from_coords
u_ECPoint.from_coords
to_coords
u_ECPoint.to_coords
aECPoint
aSpecifiedECDomainVersion

Source: http://www.secg.org/sec1-v2.pdf page 104
D l l l aecdpVer1
ecdpVer2
ecdpVer3
aFieldType

Original Name: None
Source: http://www.secg.org/sec1-v2.pdf page 101
D u1.2.840.10045.1.1
u1.2.840.10045.1.2
prime_field
characteristic_two_field
aCharacteristicTwoBasis

Original Name: None
Source: http://www.secg.org/sec1-v2.pdf page 102
D u1.2.840.10045.1.2.1.1
u1.2.840.10045.1.2.1.2
u1.2.840.10045.1.2.1.3
gn_basis
tp_basis
pp_basis
aPentanomial

Source: http://www.secg.org/sec1-v2.pdf page 102
k1
k2
k3
aCharacteristicTwo

Original Name: Characteristic-two
Source: http://www.secg.org/sec1-v2.pdf page 101
wmabasis
T abasis
parameters
a_oid_pair
gn_basis
tp_basis
pp_basis
a_oid_specs
aFieldID

Source: http://www.secg.org/sec1-v2.pdf page 100
field_type
T afield_type
parameters
prime_field
characteristic_two_field
aCurve
wawbaseed
aSpecifiedECDomain

Source: http://www.secg.org/sec1-v2.pdf page 103
field_id
curve
base
cofactor
hash

Various named curves
Original Name: None
Source: https://tools.ietf.org/html/rfc3279#page-23,
https://tools.ietf.org/html/rfc5480#page-5
DHu1.2.840.10045.3.0.1
u1.2.840.10045.3.0.2
u1.2.840.10045.3.0.3
u1.2.840.10045.3.0.4
u1.2.840.10045.3.0.5
u1.2.840.10045.3.0.6
u1.2.840.10045.3.0.7
u1.2.840.10045.3.0.8
u1.2.840.10045.3.0.9
u1.2.840.10045.3.0.10
u1.2.840.10045.3.0.11
u1.2.840.10045.3.0.12
u1.2.840.10045.3.0.13
u1.2.840.10045.3.0.14
u1.2.840.10045.3.0.15
u1.2.840.10045.3.0.16
u1.2.840.10045.3.0.17
u1.2.840.10045.3.0.18
u1.2.840.10045.3.0.19
u1.2.840.10045.3.0.20
u1.2.840.10045.3.1.2
u1.2.840.10045.3.1.3
u1.2.840.10045.3.1.4
u1.2.840.10045.3.1.5
u1.2.840.10045.3.1.6
u1.2.840.10045.3.1.1
u1.2.840.10045.3.1.7
u1.3.132.0.1
u1.3.132.0.2
u1.3.132.0.3
u1.3.132.0.4
u1.3.132.0.5
u1.3.132.0.6
u1.3.132.0.7
u1.3.132.0.8
u1.3.132.0.9
u1.3.132.0.10
u1.3.132.0.15
u1.3.132.0.16
u1.3.132.0.17
u1.3.132.0.22
u1.3.132.0.23
u1.3.132.0.24
u1.3.132.0.25
u1.3.132.0.26
u1.3.132.0.27
u1.3.132.0.28
u1.3.132.0.29
u1.3.132.0.30
u1.3.132.0.31
u1.3.132.0.32
u1.3.132.0.33
u1.3.132.0.34
u1.3.132.0.35
u1.3.132.0.36
u1.3.132.0.37
u1.3.132.0.38
u1.3.132.0.39
u1.3.36.3.3.2.8.1.1.1
u1.3.36.3.3.2.8.1.1.2
u1.3.36.3.3.2.8.1.1.3
u1.3.36.3.3.2.8.1.1.4
u1.3.36.3.3.2.8.1.1.5
u1.3.36.3.3.2.8.1.1.6
u1.3.36.3.3.2.8.1.1.7
u1.3.36.3.3.2.8.1.1.8
u1.3.36.3.3.2.8.1.1.9
u1.3.36.3.3.2.8.1.1.10
u1.3.36.3.3.2.8.1.1.11
u1.3.36.3.3.2.8.1.1.12
u1.3.36.3.3.2.8.1.1.13
u1.3.36.3.3.2.8.1.1.14
c2pnb163v1
c2pnb163v2
c2pnb163v3
c2pnb176w1
c2tnb191v1
c2tnb191v2
c2tnb191v3
c2onb191v4
c2onb191v5
c2pnb208w1
c2tnb239v1
c2tnb239v2
c2tnb239v3
c2onb239v4
c2onb239v5
c2pnb272w1
c2pnb304w1
c2tnb359v1
c2pnb368w1
c2tnb431r1
prime192v2
prime192v3
prime239v1
prime239v2
prime239v3
secp192r1
secp256r1
sect163k1
sect163r1
sect239k1
sect113r1
sect113r2
secp112r1
secp112r2
secp160r1
secp160k1
secp256k1
sect163r2
sect283k1
sect283r1
sect131r1
sect131r2
sect193r1
sect193r2
sect233k1
sect233r1
secp128r1
secp128r2
secp160r2
secp192k1
secp224k1
secp224r1
secp384r1
secp521r1
sect409k1
sect409r1
sect571k1
sect571r1
brainpoolp160r1
brainpoolp160t1
brainpoolp192r1
brainpoolp192t1
brainpoolp224r1
brainpoolp224t1
brainpoolp256r1
brainpoolp256t1
brainpoolp320r1
brainpoolp320t1
brainpoolp384r1
brainpoolp384t1
brainpoolp512r1
brainpoolp512t1
DHu1.2.840.10045.3.0.1
u1.2.840.10045.3.0.2
u1.2.840.10045.3.0.3
u1.2.840.10045.3.0.4
u1.2.840.10045.3.0.5
u1.2.840.10045.3.0.6
u1.2.840.10045.3.0.7
u1.2.840.10045.3.0.8
u1.2.840.10045.3.0.9
u1.2.840.10045.3.0.10
u1.2.840.10045.3.0.11
u1.2.840.10045.3.0.12
u1.2.840.10045.3.0.13
u1.2.840.10045.3.0.14
u1.2.840.10045.3.0.15
u1.2.840.10045.3.0.16
u1.2.840.10045.3.0.17
u1.2.840.10045.3.0.18
u1.2.840.10045.3.0.19
u1.2.840.10045.3.0.20
u1.2.840.10045.3.1.2
u1.2.840.10045.3.1.3
u1.2.840.10045.3.1.4
u1.2.840.10045.3.1.5
u1.2.840.10045.3.1.6
u1.2.840.10045.3.1.1
u1.2.840.10045.3.1.7
u1.3.132.0.1
u1.3.132.0.2
u1.3.132.0.3
u1.3.132.0.4
u1.3.132.0.5
u1.3.132.0.6
u1.3.132.0.7
u1.3.132.0.8
u1.3.132.0.9
u1.3.132.0.10
u1.3.132.0.15
u1.3.132.0.16
u1.3.132.0.17
u1.3.132.0.22
u1.3.132.0.23
u1.3.132.0.24
u1.3.132.0.25
u1.3.132.0.26
u1.3.132.0.27
u1.3.132.0.28
u1.3.132.0.29
u1.3.132.0.30
u1.3.132.0.31
u1.3.132.0.32
u1.3.132.0.33
u1.3.132.0.34
u1.3.132.0.35
u1.3.132.0.36
u1.3.132.0.37
u1.3.132.0.38
u1.3.132.0.39
u1.3.36.3.3.2.8.1.1.1
u1.3.36.3.3.2.8.1.1.2
u1.3.36.3.3.2.8.1.1.3
u1.3.36.3.3.2.8.1.1.4
u1.3.36.3.3.2.8.1.1.5
u1.3.36.3.3.2.8.1.1.6
u1.3.36.3.3.2.8.1.1.7
u1.3.36.3.3.2.8.1.1.8
u1.3.36.3.3.2.8.1.1.9
u1.3.36.3.3.2.8.1.1.10
u1.3.36.3.3.2.8.1.1.11
u1.3.36.3.3.2.8.1.1.12
u1.3.36.3.3.2.8.1.1.13
u1.3.36.3.3.2.8.1.1.14
l pppl ppppl l ppppl!l%l-pl5l pl ppl l l pl l pl pl pl l l$pl pl pl l l pl l l l l0lBl3l4lHpl pl pl pl pl(pl0pl@paclassmethod
register
uNamedCurve.register
named
a_alternatives
property
uECDomainParameters.key_size
aECPrivateKeyVersion

Original Name: None
Source: http://www.secg.org/sec1-v2.pdf page 108
D l aecPrivkeyVer1

Source: http://www.secg.org/sec1-v2.pdf page 108
D aexplicit
optional
l
tD aexplicit
optional
l tuECPrivateKey.__setitem__
uECPrivateKey.set_key_size
uECPrivateKey._update_key_size

Parameters for a DSA public or private key
Original Name: Dss-Parms
Source: https://tools.ietf.org/html/rfc3279#page-9
aAttribute

Source: https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.501-198811-S!!PDF-E&type=items page 8
type
values
spec
aAttributes

Source: https://tools.ietf.org/html/rfc5208#page-3

These OIDs for various public keys are reused when storing private keys
inside of a PKCS#8 structure
Original Name: None
Source: https://tools.ietf.org/html/rfc3279
D u1.2.840.113549.1.1.1
u1.2.840.113549.1.1.10
u1.2.840.10040.4.1
u1.2.840.10045.2.1
u1.3.101.110
u1.3.101.111
u1.3.101.112
u1.3.101.113
rsa
rsassa_pss
dsa
ec
x25519
x448
ed25519
ed448

Original Name: PrivateKeyAlgorithmIdentifier
Source: https://tools.ietf.org/html/rfc5208#page-3
T aalgorithm
parameters
attributes
D aimplicit
optional
l
ta_private_key_spec
uPrivateKeyInfo._private_key_spec
a_spec_callbacks
a_fingerprint
wrap
uPrivateKeyInfo.wrap
uPrivateKeyInfo.__setitem__
uPrivateKeyInfo.unwrap
uPrivateKeyInfo.curve
hash_algo
uPrivateKeyInfo.hash_algo
uPrivateKeyInfo.algorithm
uPrivateKeyInfo.bit_size
byte_size
uPrivateKeyInfo.byte_size
uPrivateKeyInfo.public_key
public_key_info
uPrivateKeyInfo.public_key_info
fingerprint
uPrivateKeyInfo.fingerprint
aEncryptedPrivateKeyInfo

Source: https://tools.ietf.org/html/rfc5208#page-4
encryption_algorithm
encrypted_data
aValidationParms

Source: https://tools.ietf.org/html/rfc3279#page-10
pgen_counter
aDomainParameters
wjavalidation_params

Original Name: None
Source: https://tools.ietf.org/html/rfc3279
D
u1.2.840.113549.1.1.1
u1.2.840.113549.1.1.7
u1.2.840.113549.1.1.10
u1.2.840.10040.4.1
u1.2.840.10045.2.1
u1.2.840.10046.2.1
u1.3.101.110
u1.3.101.111
u1.3.101.112
u1.3.101.113
rsa
rsaes_oaep
rsassa_pss
dsa
ec
dh
x25519
x448
ed25519
ed448

Original Name: AlgorithmIdentifier
Source: https://tools.ietf.org/html/rfc5280#page-18
aPublicKeyInfo

Original Name: SubjectPublicKeyInfo
Source: https://tools.ietf.org/html/rfc5280#page-17
a_public_key_spec
uPublicKeyInfo._public_key_spec
uPublicKeyInfo.wrap
uPublicKeyInfo.unwrap
uPublicKeyInfo.curve
uPublicKeyInfo.hash_algo
uPublicKeyInfo.algorithm
uPublicKeyInfo.bit_size
uPublicKeyInfo.byte_size
uPublicKeyInfo.sha1
uPublicKeyInfo.sha256
uPublicKeyInfo.fingerprint
uasn1crypto\keys.py
u<module asn1crypto.keys>
T a__class__
T aself
key
value
res
pkey_contents
a__class__
T aself
key
value
res
algorithm
a__class__
T aself
algorithm
T aself
T aself
prime
modulus
T aself
params
chosen
value
T acls
wxwyax_bytes
y_bytes
num_bytes
byte_string
T aself
byte_len
T aself
parameters
byte_len
T aself
order
oid
T acls
name
oid
key_size
T aself
key_size
T aself
data
first_byte
remaining
field_len
wxwyT acls
private_key
algorithm
params
public_key
private_key_algo
container
T acls
public_key
algorithm
algo
container

a__spec__
.asn1crypto.parser
\
M
uclass_ must be an integer, not %s
type_name
l uclass_ must be one of 0, 1, 2 or 3, not %s
umethod must be an integer, not %s
umethod must be 0 or 1, not %s
utag must be an integer, not %s
utag must be greater than zero, not %s
byte_cls
ucontents must be a byte string, not %s
a_dump_header

Constructs a byte string of an ASN.1 DER-encoded value
This is typically not useful. Instead, use one of the standard classes from
sn1crypto.core, or construct a new class with specific fields, and call the
.dump() method.
:param class_:
An integer ASN.1 class value: 0 (universal), 1 (application),
2 (context), 3 (private)
:param method:
An integer ASN.1 method value: 0 (primitive), 1 (constructed)
:param tag:
An integer ASN.1 tag value
:param contents:
A byte string of the encoded byte contents
:return:
A byte string of the ASN.1 DER value (header and contents)
a_parse
uExtra data - %d bytes of trailing data were provided

Parses a byte string of ASN.1 BER/DER-encoded data.
This is typically not useful. Instead, use one of the standard classes from
sn1crypto.core, or construct a new class with specific fields, and call the
.load() class method.
:param contents:
A byte string of BER/DER-encoded data
:param strict:
A boolean indicating if trailing data should be forbidden - if so, a
ValueError will be raised when trailing data exists
:raises:
ValueError - when the contents do not contain an ASN.1 header or are truncated in some way
TypeError - when contents is not a byte string
:return:
A 6-element tuple:
- 0: integer class (0 to 3)
- 1: integer method
- 2: integer tag
- 3: byte string header
- 4: byte string content
- 5: byte string trailer

Parses a byte string of ASN.1 BER/DER-encoded data to find the length
This is typically used to look into an encoded value to see how long the
next chunk of ASN.1-encoded data is. Primarily it is useful when a
value is a concatenation of multiple values.
:param contents:
A byte string of BER/DER-encoded data
:raises:
ValueError - when the contents do not contain an ASN.1 header or are truncated in some way
TypeError - when contents is not a byte string
:return:
An integer with the number of bytes occupied by the ASN.1 value
a_MAX_DEPTH
uIndefinite-length recursion limit exceeded
a_INSUFFICIENT_DATA_MESSAGE
a_PY2
l l apointer
l  atag
uNon-minimal tag encoding
l l c
int_from_bytes
D asigned
FuIndefinite-length element must be constructed
data_len
contents_end
l aencoded_data
b
depth
T alengths_only
depth
l u
Parses a byte string into component parts
:param encoded_data:
A byte string that contains BER-encoded data
:param data_len:
The integer length of the encoded data
:param pointer:
The index in the byte string to parse from
:param lengths_only:
A boolean to cause the call to return a 2-element tuple of the integer
number of bytes in the header and the integer number of bytes in the
contents. Internal use only.
:param depth:
The recursion depth when evaluating indefinite-length encoding.
:return:
A 2-element tuple:
- 0: A tuple of (class_, method, tag, header, content, trailer)
- 1: An integer indicating how many bytes were consumed
chr_cls
cont_bit
header
int_to_bytes

Constructs the header bytes for an ASN.1 object
:param class_:
An integer ASN.1 class value: 0 (universal), 1 (application),
2 (context), 3 (private)
:param method:
An integer ASN.1 method value: 0 (primitive), 1 (constructed)
:param tag:
An integer ASN.1 tag value
:param contents:
A byte string of the encoded byte contents
:return:
A byte string of the ASN.1 DER header

Functions for parsing and dumping using the ASN.1 DER encoding. Exports the
following items:
- emit()
- parse()
- peek()
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
sys
a_types
T abyte_cls
chr_cls
type_name
util
T aint_from_bytes
int_to_bytes
uInsufficient data - %s bytes requested but only %s available
l
emit
T Faparse
peek
T l
Fl
uasn1crypto\parser.py
u<module asn1crypto.parser>
T	aclass_
method
tag
contents
header
id_num
cont_bit
length
length_bytes
T aencoded_data
data_len
pointer
lengths_only
depth
start
first_octet
tag
constructed
num
length_octet
trailer
contents_end
length_octets
w_T aclass_
method
tag
contents
T acontents
strict
contents_len
info
consumed
T acontents
info
consumed

a__spec__
.asn1crypto.util
(
bit_length
l amath
ceil
bits_required
value
to_bytes
big
T abyteorder
signed

Converts an integer to a byte string
:param value:
The integer to convert
:param signed:
If the byte string should be encoded using two's complement
:param width:
If None, the minimal possible size (but at least 1),
otherwise an integer of the byte width for the return value
:return:
A byte string
from_bytes
T asigned

Converts a byte string to an integer
:param value:
The byte string to convert
:param signed:
If the byte string should be interpreted using two's complement
:return:
An integer

days
l l<aseconds
w-w+u%02d:%02d

Format a timedelta into "[+-]HH:MM" format or "" for None
timedelta
T l
a_timezone_cache
timezone

Returns a new datetime.timezone object with the given offset.
Uses cached objects if possible.
:param offset:
A datetime.timedelta object; It needs to be in full minutes and between -23:59 and +23:59.
:return:
A datetime.timezone object
uyear must be 0
date
l  a_y2k

:param year:
The integer 0
:param month:
An integer from 1 to 12
:param day:
An integer from 1 to 31
month

:return:
An integer from 1 to 12
day

:return:
An integer from 1 to 31
strftime
replace
T l  T ayear

Formats the date using strftime()
:param format:
A strftime() format string
:return:
A str, the formatted date as a unicode string
in Python 3 and a byte string in Python 2
T w2w4w0u<genexpr>
uextended_date.strftime.<locals>.<genexpr>
T u0000-%m-%d

Formats the date as %Y-%m-%d
:return:
The date formatted to %Y-%m-%d as a unicode string in Python 3
nd a byte string in Python 2
year
extended_date

Returns a new datetime.date or asn1crypto.util.extended_date
object with the specified components replaced
:return:
A datetime.date or asn1crypto.util.extended_date object
T u%Y-%m-%d

:return:
A str representing this extended_date, e.g. "0000-01-01"
a__cmp__

Compare two extended_date objects
:param other:
The other extended_date to compare to
:return:
A boolean
a__eq__
unwrap

An asn1crypto.util.extended_date object can only be compared to
n asn1crypto.util.extended_date or datetime.date object, not %s
type_name
a_comparison_error

Compare two extended_date or datetime.date objects
:param other:
The other extended_date object to compare to
:return:
An integer smaller than, equal to, or larger than 0
datetime
T l  u
:param year:
The integer 0
:param args:
Other positional arguments; see datetime.datetime.
:param kwargs:
Other keyword arguments; see datetime.datetime.
hour

:return:
An integer from 1 to 24
minute

:return:
An integer from 1 to 60
second
microsecond

:return:
An integer from 0 to 999999
tzinfo

:return:
If object is timezone aware, a datetime.tzinfo object, else None.
utcoffset

:return:
If object is timezone aware, a datetime.timedelta object, else None.
time

:return:
A datetime.time object

:return:
An asn1crypto.util.extended_date of the date

Performs strftime(), always returning a str
:param format:
A strftime() format string
:return:
A str of the formatted datetime
uextended_datetime.strftime.<locals>.<genexpr>
u0000-%02d-%02d%c%02d:%02d:%02d
u.%06d
a_format_offset

Formats the date as "%Y-%m-%d %H:%M:%S" with the sep param between the
date and time portions
:param set:
A single character of the separator to place between the date and
time
:return:
The formatted datetime as a unicode string in Python 3 and a byte
string in Python 2
extended_datetime
from_y2k

Returns a new datetime.datetime or asn1crypto.util.extended_datetime
object with the specified components replaced
:param year:
The new year to substitute. None to keep it.
:param args:
Other positional arguments; see datetime.datetime.replace.
:param kwargs:
Other keyword arguments; see datetime.datetime.replace.
:return:
A datetime.datetime or asn1crypto.util.extended_datetime object
astimezone

Convert this extended_datetime to another timezone.
:param tz:
A datetime.tzinfo object.
:return:
A new extended_datetime or datetime.datetime object
timestamp
aDAYS_IN_2000_YEARS
l   u
Return POSIX timestamp. Only supported in python >= 3.3
:return:
A float representing the seconds since 1970-01-01 UTC. This will be a negative value.
isoformat
T w T asep

:return:
A str representing this extended_datetime, e.g. "0000-01-01 00:00:00.000001-10:00"

Compare two extended_datetime objects
:param other:
The other extended_datetime to compare to
:return:
A boolean

An asn1crypto.util.extended_datetime object can only be compared to
n asn1crypto.util.extended_datetime or datetime.datetime object,
not %s

Raises a TypeError about the other object not being suitable for
comparison
:param other:
The object being compared to
ucan't compare offset-naive and offset-aware datetimes

Compare two extended_datetime or datetime.datetime objects
:param other:
The other extended_datetime or datetime.datetime object to compare to
:return:
An integer smaller than, equal to, or larger than 0

Adds a timedelta
:param other:
A datetime.timedelta object to add.
:return:
A new extended_datetime or datetime.datetime object.
T adays

Subtracts a timedelta or another datetime.
:param other:
A datetime.timedelta or datetime.datetime or extended_datetime object to subtract.
:return:
If a timedelta is passed, a new extended_datetime or datetime.datetime object.
Else a datetime.timedelta object.

Revert substitution of year 2000.
:param value:
A datetime.datetime object which is 2000 years in the future.
:return:
A new extended_datetime or datetime.datetime object.

Miscellaneous data helpers, including functions for converting integers to and
from bytes and UTC timezone. Exports the following items:
- OrderedDict()
- int_from_bytes()
- int_to_bytes()
- timezone.utc
- utc_with_dst
- create_timezone()
- inet_ntop()
- inet_pton()
- uri_to_iri()
- iri_to_uri()
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
sys
T adatetime
date
timedelta
tzinfo
a_errors
T aunwrap
a_iri
T airi_to_uri
uri_to_iri
iri_to_uri
uri_to_iri
a_ordereddict
T aOrderedDict
aOrderedDict
a_types
T atype_name
a_inet
T ainet_ntop
inet_pton
inet_ntop
inet_pton
T atimezone
T Fnaint_to_bytes
T Faint_from_bytes
a__prepare__
a_UtcWithDst
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
