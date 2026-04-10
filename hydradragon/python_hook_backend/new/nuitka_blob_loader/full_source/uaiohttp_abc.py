# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.abc

a__qualname__
D areturn
na__init__
uAbstractRouter.__init__
app
return
uPost init stage.
Not an abstract method for sake of backward compatibility,
but if the router wants to be aware of the application
it can override this.
post_init
uAbstractRouter.post_init
property
bool
frozen
uAbstractRouter.frozen
freeze
uAbstractRouter.freeze
request
aAbstractMatchInfo
a__orig_bases__
a__slots__
uExecute matched request handler
handler
uAbstractMatchInfo.handler
uExpect handler for 100-continue processing
expect_handler
uAbstractMatchInfo.expect_handler
uHTTPException instance raised on router's resolving, or None
http_exception
uAbstractMatchInfo.http_exception
str
uReturn a dict with additional info useful for introspection
get_info
uAbstractMatchInfo.get_info
uStack of nested applications.
Top level application is left-most element.
apps
uAbstractMatchInfo.apps
uAdd application to the nested apps stack.
add_app
uAbstractMatchInfo.add_app
uFreeze the match info.
The method is called after route resolution.
After the call .add_app() is forbidden.
uAbstractMatchInfo.freeze
aAbstractView
uAbstract class based view.
uAbstractView.__init__
uAbstractView.request
uExecute the view handler.
a__await__
uAbstractView.__await__
aResolveResult
uResolve result.
This is the result returned from an AbstractResolver's
resolve method.
:param hostname: The hostname that was provided.
:param host: The IP address that was resolved.
:param port: The port that was resolved.
:param family: The address family that was resolved.
:param proto: The protocol that was resolved.
:param flags: The flags that were resolved.
a__annotations__
hostname
host
int
port
family
proto
flags
aAbstractResolver
uAbstract DNS resolver.
aAF_INET
aAddressFamily
aIterableBase
T L uMorsel[str]
Obool
aClearCookiePredicate
aAbstractCookieJar
uAbstract Cookie Jar.
D aloop
naloop
aAbstractEventLoop
uAbstractCookieJar.__init__
uReturn True if cookies should be quoted.
quote_cookie
uAbstractCookieJar.quote_cookie
T napredicate
uClear all cookies if no predicate is passed.
clear
uAbstractCookieJar.clear
domain
uClear all cookies for domain and all subdomains.
clear_domain
uAbstractCookieJar.clear_domain
cookies
response_url
uUpdate cookies.
update_cookies
uAbstractCookieJar.update_cookies
request_url
uBaseCookie[str]
uReturn the jar's cookies filtered by their attributes.
filter_cookies
uAbstractCookieJar.filter_cookies
aAbstractStreamWriter
uAbstract stream writer.
buffer_size
output_size
length
chunk
bytes
bytearray
memoryview
T c
deflate
aZ_DEFAULT_STRATEGY
encoding
strategy
uEnable HTTP body compression
enable_compression
uAbstractStreamWriter.enable_compression
uEnable HTTP chunked mode
enable_chunking
uAbstractStreamWriter.enable_chunking
status_line
headers
uCIMultiDict[str]
aAbstractAccessLogger
uAbstract writer to access log.
T alogger
log_format
aLogger
uAbstractAccessLogger.__init__
response
time
float
uEmit log to logger.
log
uAbstractAccessLogger.log
uCheck if logger is enabled.
enabled
uAbstractAccessLogger.enabled
uaiohttp\abc.py
u<module aiohttp.abc>
T a__class__
T aself
T aself
logger
log_format
T aself
loop
T aself
request
T aself
app
T aself
predicate
T aself
domain
T aself
encoding
strategy
T aself
request_url
T aself
request
response
time
T aself
host
port
family
T aself
cookies
response_url
T aself
chunk
T aself
status_line
headers

a__spec__
.aiohttp.base_protocol
V
a_loop
a_paused
a_drain_waiter
a_reading_paused
transport
uReturn True if the connection is open.
done
set_result
T napause_reading
T EAttributeError
ENotImplementedError
ERuntimeError
resume_reading
cast
asyncio
aTransport
tcp_nodelay
set_exception
uConnection lost
self
aClientConnectionResetError
T uConnection lost
create_future
shield
waiter
a_drain_helper
uBaseProtocol._drain_helper
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
client_exceptions
T aClientConnectionResetError
helpers
T aset_exception
tcp_helpers
T atcp_nodelay
aProtocol
a__prepare__
aBaseProtocol
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
