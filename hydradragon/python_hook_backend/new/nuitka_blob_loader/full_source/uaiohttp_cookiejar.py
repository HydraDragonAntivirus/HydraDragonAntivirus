# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.cookiejar

uImplements cookie storage adhering to RFC 6265.
a__qualname__
compile
T u[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]*(?P<token>[\x00-\x08\x0A-\x1F\d:a-zA-Z\x7F-\xFF]+)
T u(\d{1,2}):(\d{1,2}):(\d{1,2})
T u(\d{1,2})
u(jan)|(feb)|(mar)|(apr)|(may)|(jun)|(jul)|(aug)|(sep)|(oct)|(nov)|(dec)
wIT u(\d{2,4})
int
max
replace
timezone
utc
T atzinfo
timestamp
gmtime
aOSError
aValueError
T T	l  l l l l;pq ppaOverflowError
g      aSUB_MAX_TIME
D aunsafe
quote_cookie
treat_as_secure_origin
loop
Ftnnaunsafe
bool
quote_cookie
treat_as_secure_origin
loop
aAbstractEventLoop
return
uCookieJar.__init__
property
uCookieJar.quote_cookie
file_path
save
uCookieJar.save
uCookieJar.load
T nuCookieJar.clear
str
clear_domain
uCookieJar.clear_domain
D areturn
uIterator[Morsel[str]]
a__len__
uCookieJar.__len__
D areturn
nuCookieJar._do_expiration
uCookieJar._delete_cookies
when
float
name
uCookieJar._expire_cookie
cookies
update_cookies
uCookieJar.update_cookies
request_url
uBaseCookie[str]
filter_cookies
uCookieJar.filter_cookies
staticmethod
uCookieJar._is_domain_match
classmethod
date_str
uCookieJar._parse_date
a__orig_bases__
aDummyCookieJar
uImplements a dummy cookie storage.
It can be used with the ClientSession when no cookie processing is needed.
D aloop
nuDummyCookieJar.__init__
uDummyCookieJar.__len__
uDummyCookieJar.quote_cookie
uDummyCookieJar.clear
uDummyCookieJar.clear_domain
uDummyCookieJar.update_cookies
uDummyCookieJar.filter_cookies
uaiohttp\cookiejar.py
T a.0
cookie
T a.0
wsT wxaself
domain
T adomain
self
u<module aiohttp.cookiejar>
T a__class__
T aself
unsafe
quote_cookie
treat_as_secure_origin
loop
a__class__
T aself
loop
a__class__
T aself
val
T aself
T aself
to_del
domain
path
name
T aself
to_del
expire_heap_len
now
when
cookie_key
T aself
when
domain
path
name
cookie_key
T adomain
hostname
non_matching
T acls
date_str
found_time
found_day
found_month
found_year
hour
minute
second
day
month
year
token_match
token
time_match
day_match
month_match
year_match
T aself
predicate
now
key
to_del
T aself
predicate
T aself
domain
T aself
request_url
filtered
domains
hostname
is_not_secure
request_origin
wcapaths
pairs
path_len
wpaname
cookie
domain
mrsl_val
T aself
request_url
T aself
file_path
wfT aself
cookies
response_url
hostname
name
cookie
tmp
domain
path
max_age
delta_seconds
max_age_expiration
expires
expire_time
key
T aself
cookies
response_url
a__spec__
.aiohttp.formdata
.
x
multipart
aMultipartWriter
T uform-data
a_writer
a_fields
a_is_multipart
a_is_processed
a_quote_fields
a_charset
items
T Olist
Otuple
add_fields
aIOBase
T Obytes
Obytearray
Omemoryview
warnings
warn
uIn v4, passing bytes will no longer create a file field. Please explicitly use the filename parameter or pass a BytesIO object.
aDeprecationWarning
aMultiDict
name
ufilename must be an instance of str. Got: %s
guess_filename
filename
ucontent_type must be an instance of str. Got: %s
hdrs
aCONTENT_TYPE
ucontent_transfer_encoding must be an instance of str. Got: %s
ucontent_transfer_encoding is deprecated. To maintain compatibility with v4 please pass a BytesPayload.
append
to_add
pop
T l
unknown
self
add_field
aMultiDictProxy
extend
uOnly io.IOBase, multidict and (name, file) pairs allowed, use .add_field() for passing more complex parameters, got {!r}
data
uutf-8
uapplication/x-www-form-urlencoded
uapplication/x-www-form-urlencoded; charset=%s
payload
aBytesPayload
urlencode
T adoseq
encoding
encode
T acontent_type
uForm data has been processed already
get_payload
T acontent_type
headers
encoding
T aheaders
encoding
uCan not serialize value type: %r
headers: %r
value: %r
value
headers
set_content_disposition
quote_fields
popall
aCONTENT_LENGTH
append_payload
uEncode a list of fields using the multipart/form-data MIME format
a_gen_form_data
a_gen_form_urlencoded
a__doc__
a__file__
origin
has_location
a__cached__
io
aAny
aIterable
aList
aOptional
uurllib.parse
T aurlencode
multidict
T aMultiDict
aMultiDictProxy

T ahdrs
multipart
payload
helpers
T aguess_filename
T aPayload
aPayload
T aFormData
a__all__
