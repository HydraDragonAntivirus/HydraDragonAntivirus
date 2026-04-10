# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.tracing

uFirst-class used to trace requests launched via ClientSession objects.
aTraceConfig
a__qualname__
trace_config_ctx_factory
return
a__init__
uTraceConfig.__init__
T natrace_request_ctx
T Ostr
patrace_config_ctx
uTraceConfig.trace_config_ctx
D areturn
nuTraceConfig.freeze
D areturn
uSignal[_SignalCallback[TraceRequestStartParams]]
uTraceConfig.on_request_start
D areturn
uSignal[_SignalCallback[TraceRequestChunkSentParams]]
uTraceConfig.on_request_chunk_sent
D areturn
uSignal[_SignalCallback[TraceResponseChunkReceivedParams]]
uTraceConfig.on_response_chunk_received
D areturn
uSignal[_SignalCallback[TraceRequestEndParams]]
uTraceConfig.on_request_end
D areturn
uSignal[_SignalCallback[TraceRequestExceptionParams]]
uTraceConfig.on_request_exception
D areturn
uSignal[_SignalCallback[TraceRequestRedirectParams]]
on_request_redirect
uTraceConfig.on_request_redirect
D areturn
uSignal[_SignalCallback[TraceConnectionQueuedStartParams]]
uTraceConfig.on_connection_queued_start
D areturn
uSignal[_SignalCallback[TraceConnectionQueuedEndParams]]
uTraceConfig.on_connection_queued_end
D areturn
uSignal[_SignalCallback[TraceConnectionCreateStartParams]]
uTraceConfig.on_connection_create_start
D areturn
uSignal[_SignalCallback[TraceConnectionCreateEndParams]]
uTraceConfig.on_connection_create_end
D areturn
uSignal[_SignalCallback[TraceConnectionReuseconnParams]]
uTraceConfig.on_connection_reuseconn
D areturn
uSignal[_SignalCallback[TraceDnsResolveHostStartParams]]
uTraceConfig.on_dns_resolvehost_start
D areturn
uSignal[_SignalCallback[TraceDnsResolveHostEndParams]]
uTraceConfig.on_dns_resolvehost_end
D areturn
uSignal[_SignalCallback[TraceDnsCacheHitParams]]
uTraceConfig.on_dns_cache_hit
D areturn
uSignal[_SignalCallback[TraceDnsCacheMissParams]]
uTraceConfig.on_dns_cache_miss
D areturn
uSignal[_SignalCallback[TraceRequestHeadersSentParams]]
on_request_headers_sent
uTraceConfig.on_request_headers_sent
wsT tppT aauto_attribs
frozen
slots
uParameters sent by the `on_request_start` signal
a__annotations__
uCIMultiDict[str]
uParameters sent by the `on_request_chunk_sent` signal
uParameters sent by the `on_response_chunk_received` signal
uParameters sent by the `on_request_end` signal
uParameters sent by the `on_request_exception` signal
uParameters sent by the `on_request_redirect` signal
uParameters sent by the `on_connection_queued_start` signal
uParameters sent by the `on_connection_queued_end` signal
uParameters sent by the `on_connection_create_start` signal
uParameters sent by the `on_connection_create_end` signal
uParameters sent by the `on_connection_reuseconn` signal
uParameters sent by the `on_dns_resolvehost_start` signal
uParameters sent by the `on_dns_resolvehost_end` signal
uParameters sent by the `on_dns_cache_hit` signal
uParameters sent by the `on_dns_cache_miss` signal
uParameters sent by the `on_request_headers_sent` signal
uInternal dependency holder class.
Used to keep together the main dependencies used
t the moment of send a signal.
aTrace
session
aClientSession
trace_config
uTrace.__init__
D ahost
return
Ostr
nuaiohttp\tracing.py
u<module aiohttp.tracing>
T a__class__
T aself
session
trace_config
trace_config_ctx
T aself
trace_config_ctx_factory
T aself
T aself
host
T aself
method
url
chunk
T aself
method
url
headers
response
T aself
method
url
headers
exception
T aself
method
url
headers
T aself
trace_request_ctx

a__spec__
.aiohttp.typedefs
7
L
a__doc__
a__file__
origin
has_location
a__cached__
json
os
aTYPE_CHECKING
aAny
aAwaitable
aCallable
aIterable
aMapping
aProtocol
aTuple
aUnion
multidict
T aCIMultiDict
aCIMultiDictProxy
aMultiDict
aMultiDictProxy
istr
aCIMultiDict
aCIMultiDictProxy
aMultiDict
aMultiDictProxy
istr
yarl
T aURL
aQuery
aURL
aQuery
a_Query
dumps
aDEFAULT_JSON_ENCODER
loads
aDEFAULT_JSON_DECODER
a_CIMultiDict
a_CIMultiDictProxy
a_MultiDict
a_MultiDictProxy
T Obytes
Obytearray
Omemoryview
aByteish
aJSONEncoder
aJSONDecoder
T Ostr
paLooseHeaders
T Obytes
paRawHeaders
aStrOrURL
T Ostr
uBaseCookie[str]
uMorsel[Any]
aLooseCookiesMappings
aLooseCookiesIterables
uBaseCookie[str]
aLooseCookies
aRequest
aStreamResponse
aHandler
a__prepare__
aMiddleware
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
