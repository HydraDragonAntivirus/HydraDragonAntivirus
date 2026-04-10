# Reconstructed from integrated Nuitka blob
# Module: uhttpx._types

a__qualname__
return
D areturn
nu
Subclasses can override this method to release any network resources
fter a request/response cycle is complete.
close
uSyncByteStream.close
uhttpx\_types.py
u<module httpx._types>
T a__class__
T aself

a__spec__
.httpx._urlparse
5

userinfo
w@w:ahost
w[w]aport
scheme
authority
path
query
fragment
urlparse
T u
u//
w?w#aMAX_URL_LENGTH
aInvalidURL
T uURL too long
find
uInvalid non-printable ASCII character in URL,
u at position
w.anetloc
pop
T anetloc
partition
T w:ausername
password
quote
T ausername

aUSERNAME_SAFE
T asafe
T apassword

aPASSWORD_SAFE
raw_path
T araw_path
T w?aget
T ahost
startswith
T w[aendswith
T w]aitems
uURL component '
u' too long
uInvalid non-printable ASCII character in URL
u component,
aCOMPONENT_REGEX
fullmatch
uInvalid URL component '
w'aURL_REGEX
match
groupdict
aAUTHORITY_REGEX
lower
aUSERINFO_SAFE
encode_host
normalize_port
validate_path
T ahas_scheme
has_authority
normalize_path
aPATH_SAFE
aQUERY_SAFE
aFRAG_SAFE
aParseResult
isascii
isprintable
u<genexpr>
uurlparse.<locals>.<genexpr>
aIPv4_STYLE_HOSTNAME
ipaddress
aIPv4Address
aAddressValueError
uInvalid IPv4 address:
aIPv6_STYLE_HOSTNAME
aIPv6Address
:l q nuInvalid IPv6 address:
aSUB_DELIMS
u"`{}%|\
idna
encode
decode
T aascii
aIDNAError
uInvalid IDNA hostname:
uInvalid port:
D aftp
http
https
ws
wss
l lPl  lPl  T w/T uFor absolute URLs, path must be empty or begin with '/'
T u//
T uRelative URLs cannot have a path starting with '//'
T uRelative URLs cannot have a path starting with ':'

Path validation rules that depend on if the URL contains
a scheme or authority component.
See https://datatracker.ietf.org/doc/html/rfc3986.html#section-3.3
split
u..
output
w/u
Drop "." and ".." segments from a URL path.
For example:
normalize_path("/path/./to/somewhere/..") == "/path/to"
T uutf-8
w%u02X
aUNRESERVED_CHARACTERS
rstrip
aPERCENT

Use percent-encoding to quote a string.
re
finditer
aPERCENT_ENCODED_REGEX
start
end
group
T l
current_position
parts
percent_encoded
safe
append

Use percent-encoding to quote a string, omitting existing '%xx' escape sequences.
See: https://www.rfc-editor.org/rfc/rfc3986#section-2.1
* `string`: The string to be percent-escaped.
* `safe`: A string containing characters that may be treated as safe, and do not
need to be escaped. Unreserved characters are always treated as safe.
See: https://www.rfc-editor.org/rfc/rfc3986#section-2.3

An implementation of `urlparse` that provides URL validation and normalization
s described by RFC3986.
We rely on this implementation rather than the one in Python's stdlib, because:
* It provides more complete URL validation.
* It properly differentiates between an empty querystring and an absent querystring,
to distinguish URLs with a trailing '?'.
* It handles scheme, hostname, port, and path normalization.
* It supports IDNA hostnames, normalizing them to their encoded form.
* The API supports passing individual components, as well as the complete URL string.
Previously we relied on the excellent `rfc3986` package to handle URL parsing and
validation, but this module provides a simpler alternative, with less indirection
required.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
a_exceptions
T aInvalidURL
l   uABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~
u!$&'()*+,;=
compile
T u%[A-Fa-f0-9]{2}
;l l l T l l"l<l>l`T l l"l#l<l>T	l l"l#l<l>l?l`l{l}T l l"l#l<l>l?l`l{l}l/l:l;l=l@l[l\l]l^l|T l l"l#l<l>l?l`l{l}l/l;l=l@l[l\l]l^l|T u(?:(?P<scheme>([a-zA-Z][a-zA-Z0-9+.-]*)?):)?(?://(?P<authority>[^/?#]*))?(?P<path>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?
T u(?:(?P<userinfo>.*)@)?(?P<host>(\[.*\]|[^:@]*)):?(?P<port>.*)?
T u([a-zA-Z][a-zA-Z0-9+.-]*)?
T u[^/?#]*
T u[^?#]*
T u[^#]*
T u.*
T u[^@]*
T u(\[.*\]|[^:]*)
T u^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$
T u^\[.*\]$
aNamedTuple
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
