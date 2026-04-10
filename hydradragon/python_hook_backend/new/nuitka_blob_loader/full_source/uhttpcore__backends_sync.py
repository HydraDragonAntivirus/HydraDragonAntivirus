# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._backends.sync


Because the standard `SSLContext.wrap_socket` method does
not work for `SSLSocket` objects, we need this class
to implement TLS stream using an underlying `SSLObject`
instance in order to support TLS on top of TLS.
a__qualname__
l   T nnD asock
ssl_context
server_hostname
timeout
usocket.socket
ussl.SSLContext
ustr | None
ufloat | None
a__init__
uTLSinTLSStream.__init__
D afunc
return
utyping.Callable[..., typing.Any]
utyping.Any
uTLSinTLSStream._perform_io
T nD amax_bytes
timeout
return
int
ufloat | None
bytes
uTLSinTLSStream.read
D abuffer
timeout
return
bytes
ufloat | None
aNone
uTLSinTLSStream.write
D areturn
aNone
uTLSinTLSStream.close
D assl_context
server_hostname
timeout
return
ussl.SSLContext
ustr | None
ufloat | None
aNetworkStream
start_tls
uTLSinTLSStream.start_tls
D ainfo
return
str
utyping.Any
get_extra_info
uTLSinTLSStream.get_extra_info
a__orig_bases__
D asock
return
usocket.socket
aNone
uSyncStream.__init__
uSyncStream.read
uSyncStream.write
uSyncStream.close
uSyncStream.start_tls
uSyncStream.get_extra_info
aSyncBackend
D ahost
port
timeout
local_address
socket_options
return
str
int
ufloat | None
ustr | None
utyping.Iterable[SOCKET_OPTION] | None
aNetworkStream
connect_tcp
uSyncBackend.connect_tcp
D apath
timeout
socket_options
return
str
ufloat | None
utyping.Iterable[SOCKET_OPTION] | None
aNetworkStream
connect_unix_socket
uSyncBackend.connect_unix_socket
uhttpcore\_backends\sync.py
u<module httpcore._backends.sync>
T a__class__
T aself
sock
T aself
sock
ssl_context
server_hostname
timeout
T aself
func
ret
errno
weabuf
T aself
T aself
host
port
timeout
local_address
socket_options
exc_map
address
source_address
sock
option
T aself
path
timeout
socket_options
exc_map
sock
option
T aself
info
T aself
max_bytes
timeout
exc_map
T aself
ssl_context
server_hostname
timeout
exc_map
sock
exc
T aself
ssl_context
server_hostname
timeout
T aself
buffer
timeout
exc_map
wnT aself
buffer
timeout
exc_map
nsent

a__spec__
.httpcore._backends.trio
~
a_stream
timeout
Z atrio
aTooSlowError
aReadTimeout
aBrokenResourceError
aReadError
aClosedResourceError
map_exceptions
a__enter__
a__exit__
fail_after
self
receive_some
max_bytes
T amax_bytes
T nnnaread
uTrioStream.read
buffer
aWriteTimeout
aWriteError
send_all
T adata
write
uTrioStream.write
aclose
uTrioStream.aclose
aConnectTimeout
aConnectError
aSSLStream
ssl_context
server_hostname
T assl_context
server_hostname
https_compatible
server_side
do_handshake
aTrioStream
start_tls
uTrioStream.start_tls
ssl_object
a_ssl_object
client_addr
a_get_socket_stream
socket
getsockname
server_addr
getpeername
stream
transport_stream
aSocketStream
is_readable
get_extra_info
T asocket
socket_options
open_tcp_stream
host
port
local_address
T ahost
port
local_address
setsockopt
connect_tcp
uTrioBackend.connect_tcp
open_unix_socket
path
connect_unix_socket
uTrioBackend.connect_unix_socket
sleep
seconds
uTrioBackend.sleep
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ssl
typing
a_exceptions
T aConnectError
aConnectTimeout
aExceptionMapping
aReadError
aReadTimeout
aWriteError
aWriteTimeout
map_exceptions
l aExceptionMapping
base
T aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
