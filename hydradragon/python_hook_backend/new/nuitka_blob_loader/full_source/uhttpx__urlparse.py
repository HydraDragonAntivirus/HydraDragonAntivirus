# Reconstructed from integrated Nuitka blob
# Module: uhttpx._urlparse

a__qualname__
a__annotations__
str
uint | None
ustr | None
property
D areturn
str
uParseResult.authority
uParseResult.netloc
D akwargs
return
ustr | None
aParseResult
copy_with
uParseResult.copy_with
a__str__
uParseResult.__str__
a__orig_bases__
D aurl
kwargs
return
str
ustr | None
aParseResult
D ahost
return
str
pD aport
scheme
return
ustr | int | None
str
uint | None
D apath
has_scheme
has_authority
return
str
bool
paNone
D apath
return
str
pD astring
return
str
pD astring
safe
return
str
ppuhttpx\_urlparse.py
T a.0
char
u<module httpx._urlparse>
T astring
T a__class__
T aself
authority
T aself
T aself
kwargs
defaults
T ahost
aWHATWG_SAFE
T apath
output
components
component
T aport
scheme
port_as_int
default_port
T astring
safe
aNON_ESCAPED_CHARS
T
string
safe
parts
current_position
match
start_position
end_position
matched_text
leading_text
trailing_text
T"aurl
kwargs
parsed_scheme
parsed_userinfo
parsed_host
parsed_port
parsed_path
parsed_query
parsed_frag
char
idx
error
port
netloc
w_ausername
password
raw_path
seperator
host
key
value
url_match
url_dict
scheme
authority
path
query
frag
authority_match
authority_dict
userinfo
has_scheme
has_authority
T apath
has_scheme
has_authority
a__spec__
.httpx._urls
&6
D ascheme
username
password
userinfo
host
port
netloc
path
query
raw_path
fragment
params
Ostr
ppObytes
Ostr
Oint
Obytes
Ostr
Obytes
pOstr
Oobject

u is an invalid keyword argument for URL()
a__name__
uArgument
u must be
u but got
decode
T aascii
kwargs
params
aQueryParams
query
urlparse
a_uri_reference
aURL
copy_with
uInvalid type for url.  Expected str or httpx.URL, got
u:
scheme

The URL scheme, such as "http", "https".
Always normalised to lowercase.
encode

The raw bytes representation of the URL scheme, such as b"http", b"https".
Always normalised to lowercase.
userinfo

The URL userinfo as a raw bytestring.
For example: b"jo%40email.com:a%20secret".
unquote
partition
T w:u
The URL username as a string, with URL decoding applied.
For example: "jo@email.com"
l u
The URL password as a string, with URL decoding applied.
For example: "a secret"
host
startswith
T uxn--
idna

The URL host as a string.
Always normalized to lowercase, with IDNA hosts decoded into unicode.
Examples:
url = httpx.URL("http://www.EXAMPLE.org")
ssert url.host == "www.example.org"
url = httpx.URL("http://      .icom.museum")
ssert url.host == "      .icom.museum"
url = httpx.URL("http://xn--fiqs8s.icom.museum")
ssert url.host == "      .icom.museum"
url = httpx.URL("https://[::ffff:192.168.0.1]")
ssert url.host == "::ffff:192.168.0.1"

The raw bytes representation of the URL host.
Always normalized to lowercase, and IDNA encoded.
Examples:
url = httpx.URL("http://www.EXAMPLE.org")
ssert url.raw_host == b"www.example.org"
url = httpx.URL("http://      .icom.museum")
ssert url.raw_host == b"xn--fiqs8s.icom.museum"
url = httpx.URL("http://xn--fiqs8s.icom.museum")
ssert url.raw_host == b"xn--fiqs8s.icom.museum"
url = httpx.URL("https://[::ffff:192.168.0.1]")
ssert url.raw_host == b"::ffff:192.168.0.1"
port

The URL port as an integer.
Note that the URL class performs port normalization as per the WHATWG spec.
Default ports for "http", "https", "ws", "wss", and "ftp" schemes are always
treated as `None`.
For example:
ssert httpx.URL("http://www.example.com") == httpx.URL("http://www.example.com:80")
ssert httpx.URL("http://www.example.com:80").port is None
netloc

Either `<host>` or `<host>:<port>` as bytes.
Always normalized to lowercase, and IDNA encoded.
This property may be used for generating the value of a request
"Host" header.
path
w/u
The URL path as a string. Excluding the query string, and URL decoded.
For example:
url = httpx.URL("https://example.com/pa%20th")
ssert url.path == "/pa th"

The URL query string, as raw bytes, excluding the leading b"?".
This is necessarily a bytewise interface, because we cannot
perform URL decoding of this representation until we've parsed
the keys and values into a QueryParams instance.
For example:
url = httpx.URL("https://example.com/?filter=some%20search%20terms")
ssert url.query == b"filter=some%20search%20terms"

The URL query parameters, neatly parsed and packaged into an immutable
multidict representation.
w?u
The complete URL path and query string as raw bytes.
Used as the target when constructing HTTP requests.
For example:
GET /users?search=some%20text HTTP/1.1
Host: www.example.org
Connection: close
fragment

The URL fragments, as used in HTML anchors.
As a string, without the leading '#'.

Return `True` for absolute URLs such as 'http://example.com/path',
nd `False` for relative URLs such as '/path'.
is_absolute_url

Return `False` for absolute URLs such as 'http://example.com/path',
nd `True` for relative URLs such as '/path'.

Copy this URL, returning a new URL with some components altered.
Accepts the same set of parameters as the components that are made
vailable via properties on the `URL` class.
For example:
url = httpx.URL("https://www.example.com").copy_with(
username="jo@gmail.com", password="a secret"
)
ssert url == "https://jo%40email.com:a%20secret@www.example.com"
set
T aparams
add
remove
merge
uurllib.parse
T aurljoin
urljoin

Return an absolute URL, using this URL as the base.
Eg.
url = httpx.URL("https://www.example.com/test")
url = url.join("/new/path")
ssert url == "https://www.example.com/new/path"
w:asplit
u:[secure]
w@w[w]u//
w#w(w)acollections
warnings
warn
T uURL.raw is deprecated.
namedtuple
aRawURL
L araw_scheme
raw_host
port
raw_path
raw_scheme
raw_host
raw_path
T araw_scheme
raw_host
port
raw_path
T uToo many arguments.
T uCannot mix named and unnamed arguments.
T Ostr
Obytes
parse_qs
D akeep_blank_values
ta_dict
items
T Olist
Otuple
dict_value
append
primitive_value_to_str
keys

Return all the keys in the query params.
Usage:
q = httpx.QueryParams("a=123&a=456&b=789")
ssert list(q.keys()) == ["a", "b"]
values

Return all the values in the query params. If a key occurs more than once
only the first item for that key is returned.
Usage:
q = httpx.QueryParams("a=123&a=456&b=789")
ssert list(q.values()) == ["123", "789"]

Return all items in the query params. If a key occurs more than once
only the first item for that key is returned.
Usage:
q = httpx.QueryParams("a=123&a=456&b=789")
ssert list(q.items()) == [("a", "123"), ("b", "789")]
multi_items

Return all items in the query params. Allow duplicate keys to occur.
Usage:
q = httpx.QueryParams("a=123&a=456&b=789")
ssert list(q.multi_items()) == [("a", "123"), ("a", "456"), ("b", "789")]

Get a value from the query param for a given key. If the key occurs
more than once, then only the first value is returned.
Usage:
q = httpx.QueryParams("a=123&a=456&b=789")
ssert q.get("a") == "123"
get

Get all values from the query param for a given key.
Usage:
q = httpx.QueryParams("a=123&a=456&b=789")
ssert q.get_list("a") == ["123", "456"]

Return a new QueryParams instance, setting the value of a key.
Usage:
q = httpx.QueryParams("a=123")
q = q.set("a", "456")
ssert q == httpx.QueryParams("a=456")
get_list

Return a new QueryParams instance, setting or appending the value of a key.
Usage:
q = httpx.QueryParams("a=123")
q = q.add("a", "456")
ssert q == httpx.QueryParams("a=123&a=456")
pop

Return a new QueryParams instance, removing the value of a key.
Usage:
q = httpx.QueryParams("a=123")
q = q.remove("a")
ssert q == httpx.QueryParams("")

Return a new QueryParams instance, updated with.
Usage:
q = httpx.QueryParams("a=123")
q = q.merge({"b": "456"})
ssert q == httpx.QueryParams("a=123&b=456")
q = httpx.QueryParams("a=123")
q = q.merge({"a": "456", "b": "789"})
ssert q == httpx.QueryParams("a=456&b=789")
sorted
urlencode
uQueryParams are immutable since 0.18.0. Use `q = q.merge(...)` to create an updated copy.
uQueryParams are immutable since 0.18.0. Use `q = q.set(key, value)` to create an updated copy.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
T aparse_qs
unquote
urlencode
a_types
T aQueryParamTypes
aQueryParamTypes
a_urlparse
T aurlparse
a_utils
T aprimitive_value_to_str
a__all__
