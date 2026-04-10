# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._backends.base

aNetworkStream
a__qualname__
T nD amax_bytes
timeout
return
int
ufloat | None
bytes
uNetworkStream.read
D abuffer
timeout
return
bytes
ufloat | None
aNone
uNetworkStream.write
D areturn
aNone
close
uNetworkStream.close
T nnD assl_context
server_hostname
timeout
return
ussl.SSLContext
ustr | None
ufloat | None
aNetworkStream
uNetworkStream.start_tls
D ainfo
return
str
utyping.Any
get_extra_info
uNetworkStream.get_extra_info
aNetworkBackend
T nnnD ahost
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
uNetworkBackend.connect_tcp
D apath
timeout
socket_options
return
str
ufloat | None
utyping.Iterable[SOCKET_OPTION] | None
aNetworkStream
uNetworkBackend.connect_unix_socket
D aseconds
return
float
aNone
uNetworkBackend.sleep
aAsyncNetworkStream
D assl_context
server_hostname
timeout
return
ussl.SSLContext
ustr | None
ufloat | None
aAsyncNetworkStream
uAsyncNetworkStream.get_extra_info
aAsyncNetworkBackend
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
aAsyncNetworkStream
D apath
timeout
socket_options
return
str
ufloat | None
utyping.Iterable[SOCKET_OPTION] | None
aAsyncNetworkStream
uhttpcore\_backends\base.py
u<module httpcore._backends.base>
T aself
T aself
host
port
timeout
local_address
socket_options
T aself
path
timeout
socket_options
T aself
info
T aself
max_bytes
timeout
T aself
seconds
T aself
ssl_context
server_hostname
timeout
T aself
buffer
timeout

a__spec__
.httpcore._backends
3
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_httpcore
u\not_existing
a_backends
T aNUITKA_PACKAGE_httpcore__backends
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uhttpcore\_backends\__init__.py
u<module httpcore._backends>

a__spec__
.httpcore._backends.mock
t
a_http2
h2
uhttp/1.1
a_buffer
a_closed
aReadError
T uConnection closed
c
pop
T l
ssl_object
aMockSSLObject
T ahttp2
aMockStream
self
read
uAsyncMockStream.read
write
uAsyncMockStream.write
aclose
uAsyncMockStream.aclose
start_tls
uAsyncMockStream.start_tls
aAsyncMockStream
connect_tcp
uAsyncMockBackend.connect_tcp
connect_unix_socket
uAsyncMockBackend.connect_unix_socket
sleep
uAsyncMockBackend.sleep
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ssl
typing
a_exceptions
T aReadError
l abase
T aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aNetworkBackend
aNetworkStream
aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aNetworkBackend
aNetworkStream
