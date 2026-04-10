# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_urldispatcher

a__qualname__
str
aAbstractRoute
aApplication
aAbstractRuleMatching
a__orig_bases__
D aname
nuAbstractResource.__init__
property
uAbstractResource.name
abstractmethod
uExposes the resource's canonical path.
For example '/foo/bar/{name}'
uAbstractResource.canonical
kwargs
uConstruct url for resource with additional params.
uAbstractResource.url_for
uAdd a prefix to processed URLs.
Required for subapplications support.
uAbstractResource.add_prefix
uReturn a dict with additional info useful for introspection
uAbstractResource.get_info
D areturn
nuAbstractResource.freeze
bool
uPerform a raw match against path
uAbstractResource.raw_match
aABC
D aexpect_handler
resource
nnaexpect_handler
resource
uAbstractRoute.__init__
uAbstractRoute.method
uAbstractRoute.handler
uOptional route's name, always equals to resource's name.
uAbstractRoute.name
uAbstractRoute.resource
uAbstractRoute.get_info
args
uAbstractRoute.url_for
T a_route
a_apps
a_current_app
a_frozen
a__slots__
match_dict
route
uUrlMappingMatchInfo.__init__
uUrlMappingMatchInfo.handler
uUrlMappingMatchInfo.route
uUrlMappingMatchInfo.expect_handler
uUrlMappingMatchInfo.http_exception
uUrlMappingMatchInfo.get_info
T aApplication
Q
apps
uUrlMappingMatchInfo.apps
D aapp
return
aApplication
nuUrlMappingMatchInfo.add_app
D areturn
aApplication
current_app
uUrlMappingMatchInfo.current_app
setter
uUrlMappingMatchInfo.freeze
uUrlMappingMatchInfo.__repr__
T a_exception
uMatchInfoError.__init__
uMatchInfoError.http_exception
uMatchInfoError.__repr__
uResource.__init__
D aexpect_handler
nuResource.add_route
D aroute
return
aResourceRoute
nuResource.register_route
uResource._match
int
a__len__
uResource.__len__
uResource.__iter__
uPlainResource.__init__
uPlainResource.canonical
uPlainResource.freeze
uPlainResource.add_prefix
uPlainResource._match
uPlainResource.raw_match
uPlainResource.get_info
uPlainResource.url_for
uPlainResource.__repr__
T u\{(?P<var>[_a-zA-Z][_a-zA-Z0-9]*)\}
T u\{(?P<var>[_a-zA-Z][_a-zA-Z0-9]*):(?P<re>.+)\}
u[^{}/]+
uDynamicResource.__init__
uDynamicResource.canonical
uDynamicResource.add_prefix
uDynamicResource._match
uDynamicResource.raw_match
uDynamicResource.get_info
parts
uDynamicResource.url_for
uDynamicResource.__repr__
aPrefixResource
uPrefixResource.__init__
uPrefixResource.canonical
uPrefixResource.add_prefix
uPrefixResource.raw_match
wvD aname
expect_handler
chunk_size
show_index
follow_symlinks
append_version
nnl   Fppachunk_size
show_index
follow_symlinks
append_version
uStaticResource.__init__
D aappend_version
nuStaticResource.url_for
staticmethod
byte_array
bytes
uStaticResource._get_file_hash
uStaticResource.get_info
set_options_route
uStaticResource.set_options_route
uStaticResource.__len__
uStaticResource.__iter__
unresolved_path
uStaticResource._resolve_path_to_response
dir_path
uStaticResource._directory_as_html
uStaticResource.__repr__
aPrefixedSubAppResource
uPrefixedSubAppResource.__init__
uPrefixedSubAppResource.add_prefix
uPrefixedSubAppResource._add_prefix_to_resources
uPrefixedSubAppResource.url_for
uPrefixedSubAppResource.get_info
uPrefixedSubAppResource.__len__
uPrefixedSubAppResource.__iter__
uPrefixedSubAppResource.__repr__
uAbstractRuleMatching.get_info
uReturn a str
uAbstractRuleMatching.canonical
aDomain
T u(?!-)[a-z\d-]{1,63}(?<!-)
uDomain.__init__
uDomain.canonical
uDomain.validation
host
uDomain.match_domain
uDomain.get_info
aMaskDomain
T u(?!-)[a-z\d\*-]{1,63}(?<!-)
uMaskDomain.__init__
uMaskDomain.canonical
uMaskDomain.match_domain
uMatchedSubAppResource.__init__
uMatchedSubAppResource.canonical
uMatchedSubAppResource.get_info
uMatchedSubAppResource.__repr__
uA route with resource
uResourceRoute.__init__
uResourceRoute.__repr__
uResourceRoute.name
uResourceRoute.url_for
uResourceRoute.get_info
uSystemRoute.__init__
uSystemRoute.url_for
uSystemRoute.name
uSystemRoute.get_info
uSystemRoute.status
uSystemRoute.reason
uSystemRoute.__repr__
aView
uView.__await__
uView._raise_allowed_methods
uResourcesView.__init__
uResourcesView.__len__
object
a__contains__
uResourcesView.__contains__
uRoutesView.__init__
uRoutesView.__len__
uRoutesView.__contains__
aUrlDispatcher
T u[.:-]
uUrlDispatcher.__init__
uUrlDispatcher.__iter__
uUrlDispatcher.__len__
uUrlDispatcher.__contains__
uUrlDispatcher.__getitem__
uUrlDispatcher.resources
uUrlDispatcher.routes
named_resources
uUrlDispatcher.named_resources
uUrlDispatcher.register_resource
uUrlDispatcher._get_resource_index_key
uUrlDispatcher.index_resource
uUrlDispatcher.unindex_resource
uUrlDispatcher.add_resource
D aname
expect_handler
nnuUrlDispatcher.add_route
add_static
uUrlDispatcher.add_static
add_head
uUrlDispatcher.add_head
add_options
uUrlDispatcher.add_options
D aname
allow_head
ntaallow_head
add_get
uUrlDispatcher.add_get
add_post
uUrlDispatcher.add_post
add_put
uUrlDispatcher.add_put
add_patch
uUrlDispatcher.add_patch
add_delete
uUrlDispatcher.add_delete
add_view
uUrlDispatcher.add_view
uUrlDispatcher.freeze
add_routes
uUrlDispatcher.add_routes
D avalue
return
Ostr
puaiohttp\web_urldispatcher.py
T a.0
wxaself
u<module aiohttp.web_urldispatcher>
T a__class__
T aself
resource
T aself
route
T aself
name
T aself
method
handler
expect_handler
resource
handler_wrapper
old_handler
T aself
domain
a__class__
T
self
path
name
pattern
formatter
part
match
compiled
exc
a__class__
T aself
domain
mask
a__class__
T aself
http_exception
a__class__
T aself
rule
app
T aself
path
name
a__class__
T aself
prefix
name
a__class__
T aself
prefix
app
a__class__
T aself
name
a__class__
T aself
method
handler
resource
expect_handler
a__class__
T aself
resources
T aself
resources
resource
route
T aself
prefix
directory
name
expect_handler
chunk_size
show_index
follow_symlinks
append_version
error
a__class__
T aself
a__class__
T aself
match_dict
route
a__class__
T aself
prefix
router
resource
T arequest
expect
T aself
dir_path
relative_path_to_dir
index_of
h1
index_list
dir_index
a_file
rel_path
quoted_file_url
file_name
ul
body
head_str
html
T abyte_array
wmab64
T aself
resource
index_key
T aself
request
rel_url
filename
unresolved_path
loop
T aself
request
T aself
method
ret
T aself
path
match
T aself
path
T avalue
T aself
allowed_methods
T avalue
result
T aself
unresolved_path
normalized_path
file_path
error
T aself
app
T aself
path
handler
kwargs
T aself
path
handler
name
allow_head
kwargs
resource
T aself
prefix
T aself
prefix
a__class__
T aself
path
name
resource
T aself
method
handler
expect_handler
route
route_obj
T aself
method
path
handler
name
expect_handler
resource
T aself
routes
registered_routes
route_def
T
self
prefix
path
name
expect_handler
chunk_size
show_index
follow_symlinks
append_version
resource
T aself
resource
a__class__
T arequest
result
old_handler
T aold_handler
T aself
resource
resource_key
T aself
request
host
T aself
host
T aself
resource
name
parts
part
T aself
request
match_info
methods
T aself
request
match_dict
route
T aself
request
path
method
allowed_methods
match_dict
T	aself
request
allowed_methods
resource_index
url_part
candidate
match_dict
allowed
resource
T aself
handler
T aself
kwargs
T aself
args
kwargs
T aself
parts
url
T
self
filename
append_version
url
unresolved_path
normalized_path
filepath
wfafile_bytes
whT aself
domain
url
a__spec__
.aiohttp.web_ws
ok
a__class__
a__init__
T leT astatus
a_protocols
a_timeout
a_receive_timeout
a_autoclose
a_autoping
a_heartbeat
f
@a_pong_heartbeat
a_compress
a_max_msg_size
a_writer_limit
a_cancel_pong_response_cb
a_heartbeat_cb
cancel
a_ping_task
a_pong_response_cb
a_req
a_protocol
a_timeout_ceil_threshold
l a_loop
time
calculate_timeout_when
a_heartbeat_when
call_at
a_send_heartbeat
a_writer
a_pong_not_received
send_frame
c
aWSMsgType
aPING
create_task
done
add_done_callback
a_ping_task_done
cancelled
exception
a_handle_ping_pong_exception
exc
uCallback for when the ping task completes.
transport
asyncio
aTimeoutError
uNo PONG received after

u seconds
a_closed
a_set_closed
a_set_code_close_transport
aWSCloseCode
aABNORMAL_CLOSURE
a_exception
a_waiting
a_closing
a_reader
feed_data
aWSMessage
aERROR
uHandle exceptions raised during ping/pong processing.
a_cancel_heartbeat
uSet the connection to closed.
Cancel any heartbeat timers and set the closed flag.
self
a_payload_writer
a_pre_start
request
prepare
a_post_start
drain
uWebSocketResponse.prepare
headers
websocket
get
hdrs
aUPGRADE
lower
strip
aHTTPBadRequest
uNo WebSocket UPGRADE hdr: {}
Can "Upgrade" only to "WebSocket".
T atext
upgrade
aCONNECTION
uNo CONNECTION upgrade hdr: {}
aSEC_WEBSOCKET_PROTOCOL
split
T w,aws_logger
warning
uClient protocols %r don   t overlap server-known ones %r
aSEC_WEBSOCKET_VERSION
T u13
w8w7uUnsupported version:
aSEC_WEBSOCKET_KEY
base64
b64decode
uHandshake error:
binascii
aError
b64encode
hashlib
sha1
encode
aWS_KEY
digest
decode
aCIMultiDict
aSEC_WEBSOCKET_ACCEPT
aSEC_WEBSOCKET_EXTENSIONS
ws_ext_parse
D aisserver
taws_ext_gen
T acompress
isserver
server_notakeover
compress
notakeover
a_handshake
set_status
update
force_close
aWebSocketWriter
T acompress
notakeover
limit
a_ws_protocol
a_reset_heartbeat
aWebSocketDataQueue
l   T aloop
protocol
set_parser
aWebSocketReader
T acompress
keep_alive
T FuAlready started
aHTTPException
aWebSocketReady
T Fna_close_code
get_extra_info
uGet optional transport information.
If no value associated with ``name`` is found, ``default`` is returned.
uCall .prepare() first
message
ping
uWebSocketResponse.ping
aPONG
pong
uWebSocketResponse.pong
uSend a frame over the websocket.
opcode
uWebSocketResponse.send_frame
data
udata argument must be str (%r)
T uutf-8
aTEXT
send_str
uWebSocketResponse.send_str
T Obytes
Obytearray
Omemoryview
udata argument must be byte-ish (%r)
aBINARY
send_bytes
uWebSocketResponse.send_bytes
dumps
send_json
uWebSocketResponse.send_json
a_eof_sent
uResponse has not been started
close
write_eof
uWebSocketResponse.write_eof
uClose websocket connection.
code
aCancelledError
a_close_wait
create_future
aWS_CLOSING_MESSAGE
a_close_transport
async_timeout
timeout
a__aenter__
a__aexit__
reader
read
type
aCLOSE
T nnnuWebSocketResponse.close
uSet the close code and mark the connection as closing.
uSet the close code and close the transport.
uClose the transport.
uConcurrent call to receive() is not allowed
a_conn_lost
aTHRESHOLD_CONNLOST_ACCESS
uWebSocket connection is closed.
aWS_CLOSED_MESSAGE
receive_timeout
set_result
aEofStream
aOK
aCLOSED
aWebSocketError
T acode
a_set_closing
msg
a_INTERNAL_RECEIVE_TYPES
T adrain
aCLOSING
receive
uWebSocketResponse.receive
aWSMessageTypeError
uReceived message
w:u is not WSMsgType.TEXT
cast
receive_str
uWebSocketResponse.receive_str
u is not WSMsgType.BINARY
receive_bytes
uWebSocketResponse.receive_bytes
T atimeout
loads
receive_json
uWebSocketResponse.receive_json
uCannot call .write() for websocket
write
uWebSocketResponse.write
a__anext__
uWebSocketResponse.__anext__
set_exception
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
json
sys
aAny
aFinal
aIterable
aOptional
aTuple
aUnion
attr
multidict
T aCIMultiDict
T ahdrs
u_websocket.reader
T aWebSocketDataQueue
u_websocket.writer
T aDEFAULT_LIMIT
aDEFAULT_LIMIT
abc
T aAbstractStreamWriter
aAbstractStreamWriter
client_exceptions
T aWSMessageTypeError
helpers
T acalculate_timeout_when
set_exception
set_result
http
T aWS_CLOSED_MESSAGE
aWS_CLOSING_MESSAGE
aWS_KEY
aWebSocketError
aWebSocketReader
aWebSocketWriter
aWSCloseCode
aWSMessage
aWSMsgType
ws_ext_gen
ws_ext_parse
http_websocket
T a_INTERNAL_RECEIVE_TYPES
log
T aws_logger
streams
T aEofStream
typedefs
T aJSONDecoder
aJSONEncoder
aJSONDecoder
aJSONEncoder
web_exceptions
T aHTTPBadRequest
aHTTPException
web_request
T aBaseRequest
aBaseRequest
web_response
T aStreamResponse
aStreamResponse
T aWebSocketResponse
aWebSocketReady
aWSMsgType
a__all__
wsT tppT aauto_attribs
frozen
slots
