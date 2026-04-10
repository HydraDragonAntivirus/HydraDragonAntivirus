# Reconstructed from integrated Nuitka blob
# Module: uh11._events


Base class for h11 events.
a__qualname__
a__slots__
a__orig_bases__
aRequest
T FtT ainit
frozen
uThe beginning of an HTTP request.
Fields:
.. attribute:: method
An HTTP method, e.g. ``b"GET"`` or ``b"POST"``. Always a byte
string. :term:`Bytes-like objects <bytes-like object>` and native
strings containing only ascii characters will be automatically
converted to byte strings.
.. attribute:: target
The target of an HTTP request, e.g. ``b"/index.html"``, or one of the
more exotic formats described in `RFC 7320, section 5.3
<https://tools.ietf.org/html/rfc7230#section-5.3>`_. Always a byte
string. :term:`Bytes-like objects <bytes-like object>` and native
strings containing only ascii characters will be automatically
converted to byte strings.
.. attribute:: headers
Request headers, represented as a list of (name, value) pairs. See
:ref:`the header normalization rules <headers-format>` for details.
.. attribute:: http_version
The HTTP protocol version, represented as a byte string like
``b"1.1"``. See :ref:`the HTTP version normalization rules
<http_version-format>` for details.
a__annotations__
T amethod
headers
target
http_version
bytes
D ahttp_version
a_parsed
c1.1
Fastr
a_parsed
bool
return
uRequest.__init__
a__hash__
a_ResponseBase
T aheaders
http_version
reason
status_code
int
D ahttp_version
reason
a_parsed
c1.1
c
Fu_ResponseBase.__init__
D areturn
nu_ResponseBase.__post_init__
aInformationalResponse
uAn HTTP informational response.
Fields:
.. attribute:: status_code
The status code of this response, as an integer. For an
:class:`InformationalResponse`, this is always in the range [100,
200).
.. attribute:: headers
Request headers, represented as a list of (name, value) pairs. See
:ref:`the header normalization rules <headers-format>` for
details.
.. attribute:: http_version
The HTTP protocol version, represented as a byte string like
``b"1.1"``. See :ref:`the HTTP version normalization rules
<http_version-format>` for details.
.. attribute:: reason
The reason phrase of this response, as a byte string. For example:
``b"OK"``, or ``b"Not Found"``.
uInformationalResponse.__post_init__
aResponse
uThe beginning of an HTTP response.
Fields:
.. attribute:: status_code
The status code of this response, as an integer. For an
:class:`Response`, this is always in the range [200,
1000).
.. attribute:: headers
Request headers, represented as a list of (name, value) pairs. See
:ref:`the header normalization rules <headers-format>` for details.
.. attribute:: http_version
The HTTP protocol version, represented as a byte string like
``b"1.1"``. See :ref:`the HTTP version normalization rules
<http_version-format>` for details.
.. attribute:: reason
The reason phrase of this response, as a byte string. For example:
``b"OK"``, or ``b"Not Found"``.
uResponse.__post_init__
aData
uPart of an HTTP message body.
Fields:
.. attribute:: data
A :term:`bytes-like object` containing part of a message body. Or, if
using the ``combine=False`` argument to :meth:`Connection.send`, then
ny object that your socket writing code knows what to do with, and for
which calling :func:`len` returns the number of bytes that will be
written -- see :ref:`sendfile` for details.
.. attribute:: chunk_start
A marker that indicates whether this data object is from the start of a
chunked transfer encoding chunk. This field is ignored when when a Data
event is provided to :meth:`Connection.send`: it is only valid on
events emitted from :meth:`Connection.next_event`. You probably
shouldn't use this attribute at all; see
:ref:`chunk-delimiters-are-bad` for details.
.. attribute:: chunk_end
A marker that indicates whether this data object is the last for a
given chunked transfer encoding chunk. This field is ignored when when
a Data event is provided to :meth:`Connection.send`: it is only valid
on events emitted from :meth:`Connection.next_event`. You probably
shouldn't use this attribute at all; see
:ref:`chunk-delimiters-are-bad` for details.
T adata
chunk_start
chunk_end
T FpuData.__init__
aEndOfMessage
uThe end of an HTTP message.
Fields:
.. attribute:: headers
Default value: ``[]``
Any trailing headers attached to this message, represented as a list of
(name, value) pairs. See :ref:`the header normalization rules
<headers-format>` for details.
Must be empty unless ``Transfer-Encoding: chunked`` is in use.
T aheaders
D aheaders
a_parsed
nFuEndOfMessage.__init__
aConnectionClosed
T tT afrozen
uThis event indicates that the sender has closed their outgoing
connection.
Note that this does not necessarily mean that they can't *receive* further
data, because TCP connections are composed to two one-way channels which
can be closed independently. See :ref:`closing` for details.
No fields.
uh11\_events.py
u<module h11._events>
T a__class__
T aself
data
chunk_start
chunk_end
T aself
headers
a_parsed
a__class__
T
self
method
headers
target
http_version
a_parsed
host_count
name
value
a__class__
T aself
headers
status_code
http_version
reason
a_parsed
a__class__
T aself

a__spec__
.h11._headers
k
{
a_full_items
u<Headers(%s)>
bytesify
validate
a_field_name_re
uIllegal header name {!r}
a_field_value_re
uIllegal header value {!r}
name
value
lower
ccontent-length
split
T d,astrip
aLocalProtocolError
T uconflicting Content-Length headers
pop
a_content_length_re
ubad Content-Length
seen_content_length
new_headers
ctransfer-encoding
saw_transfer_encoding
T umultiple Transfer-Encoding headers
l  T aerror_status_hint
cchunked
T uOnly Transfer-Encoding: chunked is supported
l  aHeaders
out
title
normalize_and_validate
http_version
c1.1
get_comma_header
headers
cexpect
c100-continue
a__doc__
a__file__
origin
has_location
a__cached__
re
aAnyStr
cast
aList
overload
aSequence
aTuple
aTYPE_CHECKING
aUnion
a_abnf
T afield_name
field_value
field_name
field_value
a_util
T abytesify
aLocalProtocolError
validate
aLiteral
typing_extensions
T aLiteral
compile
T c[0-9]+
encode
T aascii
T Obytes
pa__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
