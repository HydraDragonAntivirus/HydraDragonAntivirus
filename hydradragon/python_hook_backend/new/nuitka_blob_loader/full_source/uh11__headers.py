# Reconstructed from integrated Nuitka blob
# Module: uh11._headers


A list-like interface that allows iterating over headers as byte-pairs
of (lowercased-name, value).
Internally we actually store the representation as three-tuples,
including both the raw original casing, in order to preserve casing
over-the-wire, and the lowercased name, for case-insensitive comparisions.
r = Request(
method="GET",
target="/",
headers=[("Host", "example.org"), ("Connection", "keep-alive")],
http_version="1.1",
)
ssert r.headers == [
(b"host", b"example.org"),
(b"connection", b"keep-alive")
]
ssert r.headers.raw_items() == [
(b"Host", b"example.org"),
(b"Connection", b"keep-alive")
]
a__qualname__
a__slots__
full_items
bytes
return
a__init__
uHeaders.__init__
bool
a__bool__
uHeaders.__bool__
other
object
a__eq__
uHeaders.__eq__
int
a__len__
uHeaders.__len__
str
a__repr__
uHeaders.__repr__
idx
uHeaders.__getitem__
raw_items
uHeaders.raw_items
a__orig_bases__
T Obytes
Ostr
T Ostr
Obytes
T Ostr
paHeaderTypes
a_parsed
T Fanew_values
set_comma_header
D arequest
return
aRequest
Obool
has_expect_100_continue
uh11\_headers.py
u<module h11._headers>
T a__class__
T aself
T aself
other
T aself
idx
w_aname
value
T aself
full_items
T aheaders
name
out
w_afound_name
found_raw_value
found_split_value
T arequest
expect
T aheaders
a_parsed
T	aheaders
a_parsed
new_headers
seen_content_length
saw_transfer_encoding
name
value
raw_name
lengths
T aheaders
name
new_values
new_headers
found_raw_name
found_name
found_raw_value
new_value

a__spec__
.h11._readers
]
lines
obs_fold_re
match
last
aLocalProtocolError
T ucontinuation line at start of headers
d aend
a_obsolete_line_fold
validate
header_field_re
uillegal header line: {!r}
field_name
field_value
a_decode_header_lines
maybe_extract_lines
is_next_line_obviously_invalid_request_line
T uillegal request line
T uno request line received
request_line_re
uillegal request line: {!r}
aRequest
headers
:l nna_parsed
T uno response line received
status_line_re
uillegal status line: {!r}
http_version
c1.1
reason
c
status_code
l  aInformationalResponse
aResponse
T aheaders
a_parsed
status_code
reason
http_version
a_length
a_remaining
aEndOfMessage
maybe_extract_at_most
aData
T adata
aRemoteProtocolError
upeer closed connection without sending complete message body (received {} bytes, expected {})
a_bytes_in_chunk
a_bytes_to_discard
a_reading_trailer
T aheaders
maybe_extract_next_line
chunk_header_re
uillegal chunk header: {!r}
chunk_size
l l T adata
chunk_start
chunk_end
T upeer closed connection without sending complete message body (incomplete chunked read)
T l     T uGot data when expecting EOF
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
re
aAny
aCallable
aDict
aIterable
aNoReturn
aOptional
aTuple
aType
aUnion
a_abnf
T achunk_header
header_field
request_line
status_line
chunk_header
header_field
request_line
status_line
a_events
T aData
aEndOfMessage
aInformationalResponse
aRequest
aResponse
a_receivebuffer
T aReceiveBuffer
aReceiveBuffer
a_state
T aCLIENT
aCLOSED
aDONE
aIDLE
aMUST_CLOSE
aSEND_BODY
aSEND_RESPONSE
aSERVER
aCLIENT
aCLOSED
aDONE
aIDLE
aMUST_CLOSE
aSEND_BODY
aSEND_RESPONSE
aSERVER
a_util
T aLocalProtocolError
aRemoteProtocolError
aSentinel
validate
aSentinel
aREADERS
a__all__
compile
encode
T aascii
T c[ \t]+
return
T Obytes
pabuf
maybe_read_from_IDLE_client
maybe_read_from_SEND_RESPONSE_server
