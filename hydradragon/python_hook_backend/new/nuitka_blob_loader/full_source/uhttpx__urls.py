# Reconstructed from integrated Nuitka blob
# Module: uhttpx._urls


url = httpx.URL("HTTPS://jo%40email.com:a%20secret@m  ller.de:1234/pa%20th?search=ab#anchorlink")
ssert url.scheme == "https"
ssert url.username == "jo@email.com"
ssert url.password == "a secret"
ssert url.userinfo == b"jo%40email.com:a%20secret"
ssert url.host == "m  ller.de"
ssert url.raw_host == b"xn--mller-kva.de"
ssert url.port == 1234
ssert url.netloc == b"xn--mller-kva.de:1234"
ssert url.path == "/pa th"
ssert url.query == b"?search=ab"
ssert url.raw_path == b"/pa%20th?search=ab"
ssert url.fragment == "anchorlink"
The components of a URL are broken down like this:
https://jo%40email.com:a%20secret@m  ller.de:1234/pa%20th?search=ab#anchorlink
[scheme]   [  username  ] [password] [ host ][port][ path ] [ query ] [fragment]
[       userinfo        ] [   netloc   ][    raw_path    ]
Note that:
* `url.scheme` is normalized to always be lowercased.
* `url.host` is normalized to always be lowercased. Internationalized domain
names are represented in unicode, without IDNA encoding applied. For instance:
url = httpx.URL("http://      .icom.museum")
ssert url.host == "      .icom.museum"
url = httpx.URL("http://xn--fiqs8s.icom.museum")
ssert url.host == "      .icom.museum"
* `url.raw_host` is normalized to always be lowercased, and is IDNA encoded.
url = httpx.URL("http://      .icom.museum")
ssert url.raw_host == b"xn--fiqs8s.icom.museum"
url = httpx.URL("http://xn--fiqs8s.icom.museum")
ssert url.raw_host == b"xn--fiqs8s.icom.museum"
* `url.port` is either None or an integer. URLs that include the default port for
"http", "https", "ws", "wss", and "ftp" schemes have their port
normalized to `None`.
ssert httpx.URL("http://example.com") == httpx.URL("http://example.com:80")
ssert httpx.URL("http://example.com").port is None
ssert httpx.URL("http://example.com:80").port is None
* `url.userinfo` is raw bytes, without URL escaping. Usually you'll want to work
with `url.username` and `url.password` instead, which handle the URL escaping.
* `url.raw_path` is raw bytes of both the path and query, without URL escaping.
This portion is used as the target when constructing HTTP requests. Usually you'll
want to work with `url.path` instead.
* `url.query` is raw bytes, without URL escaping. A URL query string portion can
only be properly URL escaped when decoding the parameter names and values
themselves.
a__qualname__
T u
D aurl
kwargs
return
uURL | str
utyping.Any
aNone
a__init__
uURL.__init__
D areturn
str
uURL.scheme
D areturn
bytes
uURL.raw_scheme
uURL.userinfo
username
uURL.username
password
uURL.password
uURL.host
uURL.raw_host
D areturn
uint | None
uURL.port
uURL.netloc
uURL.path
uURL.query
D areturn
aQueryParams
uURL.params
uURL.raw_path
uURL.fragment
D areturn
bool
uURL.is_absolute_url
is_relative_url
uURL.is_relative_url
D akwargs
return
utyping.Any
aURL
uURL.copy_with
T nD akey
value
return
str
utyping.Any
aURL
copy_set_param
uURL.copy_set_param
copy_add_param
uURL.copy_add_param
D akey
return
str
aURL
copy_remove_param
uURL.copy_remove_param
D aparams
return
aQueryParamTypes
aURL
copy_merge_params
uURL.copy_merge_params
D aurl
return
uURL | str
aURL
join
uURL.join
D areturn
int
a__hash__
uURL.__hash__
D aother
return
utyping.Any
bool
a__eq__
uURL.__eq__
a__str__
uURL.__str__
a__repr__
uURL.__repr__
D areturn
utuple[bytes, bytes, int, bytes]
raw
uURL.raw
aMapping
T Ostr
pa__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>

URL query parameters, as a multi-dict.
D aargs
kwargs
return
uQueryParamTypes | None
utyping.Any
aNone
uQueryParams.__init__
D areturn
utyping.KeysView[str]
uQueryParams.keys
D areturn
utyping.ValuesView[str]
uQueryParams.values
D areturn
utyping.ItemsView[str, str]
uQueryParams.items
D areturn
ulist[tuple[str, str]]
uQueryParams.multi_items
D akey
default
return
utyping.Any
utyping.Any
utyping.Any
uQueryParams.get
D akey
return
str
ulist[str]
uQueryParams.get_list
D akey
value
return
str
utyping.Any
aQueryParams
uQueryParams.set
uQueryParams.add
D akey
return
str
aQueryParams
uQueryParams.remove
D aparams
return
uQueryParamTypes | None
aQueryParams
uQueryParams.merge
D akey
return
utyping.Any
str
uQueryParams.__getitem__
D akey
return
utyping.Any
bool
a__contains__
uQueryParams.__contains__
D areturn
utyping.Iterator[typing.Any]
a__iter__
uQueryParams.__iter__
a__len__
uQueryParams.__len__
a__bool__
uQueryParams.__bool__
uQueryParams.__hash__
uQueryParams.__eq__
uQueryParams.__str__
uQueryParams.__repr__
D aparams
return
uQueryParamTypes | None
aNone
update
uQueryParams.update
D akey
value
return
str
paNone
a__setitem__
uQueryParams.__setitem__
a__orig_bases__
uhttpx\_urls.py
u<module httpx._urls>
T a__class__
T aself
T aself
key
T aself
other
T aself
args
kwargs
dict_value
value
item
T
self
url
kwargs
allowed
key
value
message
expected
seen
params
T aself
class_name
query_string
T
self
scheme
userinfo
host
port
path
query
fragment
authority
url
T aself
key
value
T aself
key
value
wqT aself
params
T aself
kwargs
T aself
key
default
T aself
host
T aself
url
urljoin
T aself
params
wqT aself
multi_items
wkwvT aself
userinfo
T aself
path
T aself
query
T aself
collections
warnings
aRawURL
T aself
key
wqa__spec__
.httpx._utils
true
false


Coerce a primitive data type into a string value.
Note that we prefer JSON-style 'true'/'false' for boolean values here.
getproxies
T ahttp
https
all
proxy_info
get
u://
uhttp://
mounts
T ano

split
T w,astrip
w*ais_ipv4_hostname
uall://
is_ipv6_hostname
uall://[
w]alower
localhost
uall://*
uGets proxy information from the environment
encode
decode
w":l q nafileno
fstat
st_size
T EAttributeError
EOSError
tell
seek
aSEEK_END

Given a file-like stream object, return its length in number of bytes
without reading it into memory.
a_urls
T aURL
aURL
w:uProxy keys should use proper URL forms rather than plain scheme strings. Instead of "
u", use "
u://"
pattern
scheme
all
host
port
host_regex
startswith
T u*.
re
escape
:l nnacompile
u^.+\.
w$T w*:l nnu^(.+\.)?
w^amatch

The priority allows URLPattern instances to be sortable, so that
we can match from most specific to least specific.
priority
aURLPattern
ipaddress
aIPv4Address
T w/aIPv6Address
a__doc__
a__file__
origin
has_location
a__cached__
annotations
os
typing
uurllib.request
T agetproxies
a_types
T aPrimitiveData
aPrimitiveData
D avalue
return
aPrimitiveData
str
primitive_value_to_str
D areturn
udict[str, str | None]
get_environment_proxies
T uutf-8
D avalue
encoding
return
ustr | bytes
str
bytes
to_bytes
D avalue
encoding
return
ustr | bytes
str
pato_str
D avalue
match_type_of
return
str
utyping.AnyStr
utyping.AnyStr
to_bytes_or_str
D avalue
return
str
paunquote
D astream
return
utyping.Any
uint | None
peek_filelike_length
