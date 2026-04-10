# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.client_exceptions

uBase class for client connection errors.
a__qualname__
a__orig_bases__
aClientResponseError
uBase class for exceptions that occur after getting a response.
request_info: An instance of RequestInfo.
history: A sequence of responses, if redirects occurred.
status: HTTP status code.
message: Error message.
headers: Response headers.
D acode
status
message
headers
nnu
nacode
int
str
return
uClientResponseError.__init__
a__str__
uClientResponseError.__str__
a__repr__
uClientResponseError.__repr__
property
uClientResponseError.code
setter
value
aContentTypeError
uContentType found is not valid.
aWSServerHandshakeError
uwebsocket server handshake error.
aClientHttpProxyError
uHTTP proxy error.
Raised in :class:`aiohttp.connector.TCPConnector` if
proxy responds with status other than ``200 OK``
on ``CONNECT`` request.
aTooManyRedirects
uClient was redirected too many times.
aClientConnectionError
uBase class for client socket errors.
aClientConnectionResetError
aConnectionResetError
aClientOSError
uOSError error.
aClientConnectorError
uClient connector error.
Raised in :class:`aiohttp.connector.TCPConnector` if
a connection can not be established.
connection_key
os_error
aOSError
uClientConnectorError.__init__
uClientConnectorError.os_error
uClientConnectorError.host
uClientConnectorError.port
bool
aFingerprint
uClientConnectorError.ssl
uClientConnectorError.__str__
aBaseException
a__reduce__
aClientConnectorDNSError
uDNS resolution failed during client connection.
Raised in :class:`aiohttp.connector.TCPConnector` if
DNS resolution fails.
aClientProxyConnectionError
uProxy connection error.
Raised in :class:`aiohttp.connector.TCPConnector` if
connection to proxy can not be established.
aUnixClientConnectorError
uUnix connector error.
Raised in :py:class:`aiohttp.connector.UnixConnector`
if connection to unix socket can not be established.
path
uUnixClientConnectorError.__init__
uUnixClientConnectorError.path
uUnixClientConnectorError.__str__
aServerConnectionError
uServer connection errors.
aServerDisconnectedError
uServer disconnected.
T nuServerDisconnectedError.__init__
aTimeoutError
aServerTimeoutError
uServer timeout error.
aConnectionTimeoutError
uConnection timeout error.
aSocketTimeoutError
uSocket timeout error.
aServerFingerprintMismatch
uSSL certificate does not match expected fingerprint.
bytes
uServerFingerprintMismatch.__init__
uServerFingerprintMismatch.__repr__
aClientPayloadError
uResponse payload error.
aInvalidURL
uInvalid URL.
URL used for fetching is malformed, e.g. it doesn't contains host
part.
url
description
uInvalidURL.__init__
uInvalidURL.url
D areturn
ustr | None
uInvalidURL.description
uInvalidURL.__repr__
uInvalidURL.__str__
aInvalidUrlClientError
uInvalid URL client error.
aRedirectClientError
uClient redirect error.
aNonHttpUrlClientError
uNon http URL client error.
aInvalidUrlRedirectClientError
uInvalid URL redirect client error.
aNonHttpUrlRedirectClientError
uNon http URL redirect client error.
aClientSSLError
uBase error for ssl.*Errors.
aCertificateError
cert_errors
cert_errors_bases
aSSLError
ssl_errors
ssl_error_bases
aClientConnectorSSLError
uResponse ssl error.
aClientConnectorCertificateError
uResponse certificate error.
certificate_error
aException
uClientConnectorCertificateError.__init__
uClientConnectorCertificateError.certificate_error
uClientConnectorCertificateError.host
uClientConnectorCertificateError.port
uClientConnectorCertificateError.ssl
uClientConnectorCertificateError.__str__
T ETypeError
aWSMessageTypeError
uWebSocket message type is not valid.
uaiohttp\client_exceptions.py
u<module aiohttp.client_exceptions>
T a__class__
T aself
connection_key
certificate_error
T aself
connection_key
os_error
a__class__
T aself
request_info
history
code
status
message
headers
T aself
url
description
a__class__
T aself
message
T aself
expected
got
host
port
T aself
path
connection_key
os_error
a__class__
T aself
args
T aself
T aself
value
a__spec__
.aiohttp.client_proto
aBaseProtocol
a__init__
T aloop
aDataQueue
a_should_close
a_payload
a_skip_payload
a_payload_parser
a_timer
c
a_tail
a_upgraded
a_parser
a_read_timeout
a_read_timeout_handle
l a_timeout_ceil_threshold
is_eof
a_exception
a_buffer
transport
close
a_drop_timeout
is_closing
suppress
T EException
a__enter__
a__exit__
feed_eof
T nnnuResponse payload is not completed:

u.
set_exception
aClientPayloadError
aClientOSError
args
aServerDisconnectedError
a_EXC_SENTINEL
a_reading_paused
a__class__
connection_lost
reraised_exc
pause_reading
resume_reading
a_reschedule_timeout
data_received
aHttpResponseParser
a_loop
T atimer
payload_exception
response_with_body
read_until_eof
auto_decompress
max_line_size
max_field_size
cancel
call_later
a_on_read_timeout
aSocketTimeoutError
T uTimeout on reading data from socket
feed_data
aHttpProcessingError
code
message
headers
T acode
message
headers
should_close
self
aEMPTY_BODY_STATUS_CODES
aEMPTY_PAYLOAD
payload
on_eof
a__doc__
a__file__
origin
has_location
a__cached__
asyncio
contextlib
T asuppress
aAny
aOptional
aTuple
base_protocol
T aBaseProtocol
client_exceptions
T aClientOSError
aClientPayloadError
aServerDisconnectedError
aSocketTimeoutError
helpers
T a_EXC_SENTINEL
aEMPTY_BODY_STATUS_CODES
aBaseTimerContext
set_exception
aBaseTimerContext
http
T aHttpResponseParser
aRawResponseMessage
aRawResponseMessage
http_exceptions
T aHttpProcessingError
streams
T aEMPTY_PAYLOAD
aDataQueue
aStreamReader
aStreamReader
a__prepare__
aResponseHandler
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
