# Reconstructed from integrated Nuitka blob
# Module: uasn1crypto._errors


An exception indicating an API has been removed from asn1crypto
a__qualname__
a__orig_bases__
unwrap
uasn1crypto\_errors.py
u<module asn1crypto._errors>
T astring
params
output

a__spec__
.asn1crypto._inet
S
@
socket
aAF_INET
aAF_INET6
unwrap

ddress_family must be socket.AF_INET (%s) or socket.AF_INET6 (%s),
not %s
byte_cls

packed_ip must be a byte string, not %s
type_name
l l u
packed_ip must be %d bytes long - is %d
u%d.%d.%d.%d
bytes_to_list
struct
unpack
c!HHHHHHHH
T q azero_index
runs_of_zero
max
longest_run
:l nnl w:u::

Windows compatibility shim for socket.inet_ntop().
:param address_family:
socket.AF_INET for IPv4 or socket.AF_INET6 for IPv6
:param packed_ip:
A byte string of the network form of an IP address
:return:
A unicode string of the IP address
str_cls

ip_string must be a unicode string, not %s
split
T w.l  aints

ip_string must be a dotted string with four integers in the
range of 0 to 255, got %s
pack
T c!BBBB
count
T u::
T w:w0aoctets
T c!HHHHHHHH

ip_string must be a valid ipv6 string, got %s

Windows compatibility shim for socket.inet_ntop().
:param address_family:
socket.AF_INET for IPv4 or socket.AF_INET6 for IPv6
:param ip_string:
A unicode string of an IP address
:return:
A byte string of the network form of the IP address
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
a_types
T abyte_cls
bytes_to_list
str_cls
type_name
inet_ntop
inet_pton
uasn1crypto\_inet.py
u<module asn1crypto._inet>
Taaddress_family
packed_ip
required_len
octets
runs_of_zero
longest_run
zero_index
wiaoctet
length
hexed
zero_start
zero_end
T aaddress_family
ip_string
octets
error
ints
woaomitted
begin
end
begin_octets
end_octets
missing

a__spec__
.asn1crypto._int
bytes_
d

Ensure a byte string representing a positive integer is a specific width
(in bytes)
:param bytes_:
The integer byte string
:param width:
The desired width as an integer
:return:
A byte string of the width specified
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
fill_width
uasn1crypto\_int.py
u<module asn1crypto._int>
T abytes_
width

a__spec__
.asn1crypto._iri
K
}
str_cls
unwrap

value must be a unicode string, not %s
type_name
urlsplit
a_urlquote
scheme
hostname
encode
T aidna
username
D asafe
u!$&'()*+,;=
password
port
T aascii
c
d:d@chttp
c80
chttps
c443
path
D asafe
u/!$&'()*+,;=@:
query
D asafe
u/?!$&'()*+,;=@:
fragment
d/u
urlunsplit
T alatin1

Encodes a unicode IRI into an ASCII byte string URI
:param value:
A unicode string of an IRI
:param normalize:
A bool that controls URI normalization
:return:
A byte string of the ASCII-encoded URI
byte_cls

value must be a byte string, not %s
decode
a_urlunquote
D aremap
L w:w@aint_types
w:w@D aremap
preserve
L w/tD aremap
preserve
L w&w=tu
Converts an ASCII URI byte string into a unicode IRI
:param value:
An ASCII-encoded byte string of the URI
:return:
A unicode string of the IRI
bytes_to_list
object
start
end
u%%%02x

Error handler for decoding UTF-8 parts of a URI into an IRI. Leaves byte
sequences encoded in %XX format, but as part of a unicode string.
:param exc:
The UnicodeDecodeError exception
:return:
A 2-element tuple of (replacement unicode string, integer index to
resume at)
re
search
u%[0-9a-fA-F]{2}
a_try_unescape
u_urlquote.<locals>._try_unescape
sub
u(?:%[0-9a-fA-F]{2})+
a_extract_escape
u_urlquote.<locals>._extract_escape
urlquote
string
T uutf-8
T asafe
a_return_escape
u_urlquote.<locals>._return_escape
c%00

Quotes a unicode string for use in a URL
:param string:
A unicode string
:param safe:
A unicode string of character to not encode
:return:
None (if string is None) or an ASCII byte string of the quoted string
unquote_to_bytes
group
T l
T uutf-8
iriutf8
safe
unicode_string
replace
escapes
append
w
pop
L w w w w w areplacements
preserve_unmap
byte_string
items
output

Unquotes a URI portion from a byte string into unicode using UTF-8
:param byte_string:
A byte string of the data to unquote
:param remap:
A list of characters (as unicode) that should be re-mapped to a
%XX encoding. This is used when characters are not valid in part of a
URL.
:param preserve:
A bool - indicates that the chars to be remapped if they occur in
non-hex form, should be preserved. E.g. / for URL path.
:return:
A unicode string

Functions to convert unicode IRIs into ASCII byte string URIs and back. Exports
the following items:
- iri_to_uri()
- uri_to_iri()
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
encodings
idna
codecs
sys
a_errors
T aunwrap
a_types
T abyte_cls
str_cls
type_name
bytes_to_list
int_types
uurllib.parse
T aquote
unquote_to_bytes
urlsplit
urlunsplit
quote
T Fairi_to_uri
uri_to_iri
a_iri_utf8_errors_handler
register_error
iriutf8
T u
T nnuasn1crypto\_iri.py
u<module asn1crypto._iri>
T amatch
escapes
T aescapes
T aexc
bytes_as_ints
replacements
T w_aescapes
T amatch
byte_string
unicode_string
safe_char
safe
T astring
safe
escapes
a_try_unescape
a_extract_escape
output
a_return_escape
T	abyte_string
remap
preserve
replacements
preserve_unmap
char
replacement
output
original
T avalue
normalize
scheme
real_prefix
prefix_match
parsed
hostname
username
password
port
netloc
default_http
default_https
path
query
fragment
output
T avalue
parsed
scheme
username
password
hostname
port
netloc
path
query
fragment
a__spec__
.asn1crypto._ordereddict
a__doc__
a__file__
origin
has_location
a__cached__
sys
collections
T aOrderedDict
aOrderedDict
uasn1crypto\_ordereddict.py
u<module asn1crypto._ordereddict>

a__spec__
.asn1crypto._teletex_codec
b
<
codecs
charmap_encode
aENCODING_TABLE
charmap_decode
aDECODING_TABLE
errors
teletex
aCodecInfo
aTeletexCodec
encode
decode
aTeletexIncrementalEncoder
aTeletexIncrementalDecoder
aTeletexStreamReader
aTeletexStreamWriter
T aname
encode
decode
incrementalencoder
incrementaldecoder
streamreader
streamwriter

Search function for teletex codec that is passed to codecs.register()
register
teletex_search_function

Registers the teletex codec

Implementation of the teletex T.61 codec. Exports the following items:
- register()
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
aCodec
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
