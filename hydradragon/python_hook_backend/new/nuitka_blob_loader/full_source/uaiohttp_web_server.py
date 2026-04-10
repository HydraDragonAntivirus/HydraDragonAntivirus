# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_server

aServer
a__qualname__
D arequest_factory
handler_cancellation
loop
nFnaAbstractEventLoop
kwargs
return
a__init__
uServer.__init__
connections
uServer.connections
transport
aTransport
connection_made
uServer.connection_made
T naexc
connection_lost
uServer.connection_lost
message
payload
protocol
writer
task
uasyncio.Task[None]
uServer._make_request
D areturn
napre_shutdown
uServer.pre_shutdown
a__call__
uServer.__call__
uaiohttp\web_server.py
T a.0
conn
timeout
T wfaself
handler
T ahandler
self
u<module aiohttp.web_server>
T a__class__
T aself
kwargs
T aself
handler
request_factory
handler_cancellation
loop
kwargs
T aself
message
payload
protocol
writer
task
T aself
handler
exc
T aself
handler
transport
T aself
T aself
conn
T aself
timeout
coros

a__spec__
.aiohttp.web_urldispatcher
;
a_name
uResolve resource.
Return (UrlMappingMatchInfo, allowed_methods) pair.
resolve
uAbstractResource.resolve
a_default_expect_handler
asyncio
iscoroutinefunction
uCoroutine is expected, got

upper
aHTTP_METHOD_RE
match
u is not allowed HTTP method
callable
inspect
isgeneratorfunction
warnings
warn
uBare generators are deprecated, use @coroutine wrapper
aDeprecationWarning
aAbstractView
uBare functions are deprecated, use async ones
wraps
request
aRequest
return
aStreamResponse
handler_wrapper
uAbstractRoute.__init__.<locals>.handler_wrapper
a_method
handler
a_handler
a_expect_handler
a_resource
old_handler
iscoroutine
result
self
handle_expect_header
uAbstractRoute.handle_expect_header
a__class__
a__init__
a_route
a_apps
a_current_app
a_frozen
get_info
uCannot change apps stack after .freeze() call
insert
aDEBUG
uExpected one of the following apps {!r}, got {!r}
u<MatchInfo
a__repr__
u:
w>a_exception
aSystemRoute
u<MatchInfoError {}: {}>
status
reason
uDefault handler for Expect header.
Just send "100 Continue" to client.
raise HTTPExpectationFailed if value of header is not "100-continue"
headers
get
hdrs
aEXPECT
version
aHttpVersion11
lower
u100-continue
writer
write
T cHTTP/1.1 100 Continue
output_size
aHTTPExpectationFailed
uUnknown Expect: %s
T atext
T aname
a_routes
a_any_route
a_allowed_methods
uAdded route will never be executed, method
method
u is already registered
aResourceRoute
T aexpect_handler
register_route
uInstance of Route class is required, got
aMETH_ANY
add
a_match
rel_url
path_safe
T nS
aUrlMappingMatchInfo
uResource.resolve
values
startswith
T w/a_path
w/aendswith
path
aURL
build
T apath
encoded
name
w'u'
u<PlainResource
w a_orig_path
aROUTE_RE
split
aDYN
fullmatch
pattern
u(?P<{}>{})
group
T avar
aGOOD
formatter
w{w}aDYN_WITH_RE
u(?P<{var}>{re})
format
groupdict
uInvalid path '
u'['
u']
a_requote_path
re
escape
compile
error
uBad pattern '
u':
aPATH_SEP
a_pattern
a_formatter
items
a_unquote_path_safe
format_map
a_quote_path
u<DynamicResource {name} {formatter}>
T aname
formatter
T u
w/a_prefix
a_prefix2
aPath
expanduser
T tT astrict
u' does not exist
is_dir
u' is not a directory
a_directory
a_show_index
a_chunk_size
a_follow_symlinks
a_append_version
aGET
a_handle
aHEAD
lstrip
aYARL_VERSION
T l l areplace
T w%u%25
joinpath
filename
relative_to
T EValueError
EFileNotFoundError
filepath
is_file
open
T arb
a__enter__
a__exit__
read
T nnna_get_file_hash
file_bytes
with_query
aVERSION_KEY
hashlib
sha256
update
base64
urlsafe_b64encode
digest
decode
T aascii
directory
prefix
routes
aOPTIONS
uOPTIONS route was set already
T aOPTIONS
uStaticResource.resolve
match_info
anchor
aHTTPForbidden
get_running_loop
run_in_executor
a_resolve_path_to_response
uStaticResource._handle
T EValueError
aCIRCULAR_SYMLINK_ERROR
aHTTPNotFound
file_path
aResponse
a_directory_as_html
utext/html
T atext
content_type
aFileResponse
T achunk_size
uTake the unresolved path and query the file system to form a response.
as_posix
uIndex of /
html_escape
u<h1>
u</h1>
iterdir
sorted
index_list
u<li><a href="
u">
u</a></li>
u<ul>
{}
</ul>
w
u<body>

</body>
u<head>
<title>
u</title>
</head>
u<html>

</html>
ureturns directory's index as html.
u<StaticResource {name} {path} -> {directory!r}>
T aname
path
directory
a_app
a_add_prefix_to_resources
add_prefix
router
resources
unindex_resource
index_resource
u.url_for() is not supported by sub-application root
app
add_app
http_exception
aHTTPMethodNotAllowed
allowed_methods
uPrefixedSubAppResource.resolve
u<PrefixedSubAppResource {prefix} -> {app!r}>
T aprefix
app
uReturn bool if the request satisfies the criteria
uAbstractRuleMatching.match
validation
a_domain
uDomain must be str
rstrip
T w.uDomain cannot be empty
u://
uScheme not supported
uhttp://
raw_host
uDomain not valid
port
lPw:are_part
u<genexpr>
uDomain.validation.<locals>.<genexpr>
aHOST
match_domain
uDomain.match
domain
T w.u\.
T w*u.*
a_mask
aAbstractResource
a_rule
canonical
rule
uMatchedSubAppResource.resolve
u<MatchedSubAppResource ->
T aexpect_handler
resource
u<ResourceRoute [{method}] {resource} -> {handler!r}
T amethod
resource
handler
url_for
uConstruct url for route with additional params.
a_http_exception
u.url_for() is not allowed for SystemRoute
uSystemRoute._handle
u<SystemRoute {self.status}: {self.reason}>
T aself
aMETH_ALL
a_raise_allowed_methods
a_iter
uView._iter
a__await__
a_resources
a__iter__
uResourcesView.__iter__
append
uRoutesView.__iter__
a_named_resources
a_resource_index
a_matched_sub_app_resources
url_part
resource_index
rpartition
aMatchInfoError
uUrlDispatcher.resolve
aResourcesView
aRoutesView
aMappingProxyType
uInstance of AbstractResource class is required, got
frozen
uCannot register a resource into frozen router.
aNAME_SPLIT_RE
keyword
iskeyword
uIncorrect route name
u, python keywords cannot be used for route name
isidentifier
uIncorrect route name {!r}, the name should be a sequence of python identifiers separated by dash, dot or column
uDuplicate {!r}, already handled by {!r}
aMatchedSubAppResource
partition
T w{uReturn a key to index the resource in the resource index.
a_get_resource_index_key
setdefault
uAdd a resource to the resource index.
remove
uRemove a resource from the resource index.
upath should be started with / or be empty
raw_match
cast
aResource
search
aPlainResource
register_resource
aDynamicResource
add_resource
add_route
:nq naStaticResource
T aname
expect_handler
chunk_size
show_index
follow_symlinks
append_version
uAdd static files view.
prefix - url prefix
path - folder with files
aMETH_HEAD
uShortcut for add_route with method HEAD.
aMETH_OPTIONS
uShortcut for add_route with method OPTIONS.
aMETH_GET
uShortcut for add_route with method GET.
If allow_head is true, another
route is added allowing head requests to the same endpoint.
aMETH_POST
uShortcut for add_route with method POST.
aMETH_PUT
uShortcut for add_route with method PUT.
aMETH_PATCH
uShortcut for add_route with method PATCH.
aMETH_DELETE
uShortcut for add_route with method DELETE.
uShortcut for add_route with ANY methods for a class-based view.
freeze
registered_routes
register
uAppend routes to route table.
Parameter should be a sequence of RouteDef objects.
Returns a list of registered AbstractRoute instances.
raw_path
w%T u%2F
w/T u%25
w%a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
abc
functools
html
os
sys
pathlib
T aPath
aTYPE_CHECKING
aAny
aAwaitable
aCallable
aContainer
aDict
aFinal
aGenerator
aIterable
aIterator
aList
aMapping
aNoReturn
aOptional
aPattern
aSet
aSized
aTuple
aType
aTypedDict
aUnion
yarl
T aURL
a__version__
a__version__
yarl_version
T ahdrs
T aAbstractMatchInfo
aAbstractRouter
aAbstractView
aAbstractMatchInfo
aAbstractRouter
helpers
T aDEBUG
http
T aHttpVersion11
typedefs
T aHandler
aPathLike
aHandler
aPathLike
web_exceptions
T aHTTPException
aHTTPExpectationFailed
aHTTPForbidden
aHTTPMethodNotAllowed
aHTTPNotFound
aHTTPException
web_fileresponse
T aFileResponse
web_request
T aRequest
web_response
T aResponse
aStreamResponse
web_routedef
T aAbstractRouteDef
aAbstractRouteDef
T
aUrlDispatcher
aUrlMappingMatchInfo
aAbstractResource
aResource
aPlainResource
aDynamicResource
aAbstractRoute
aResourceRoute
aStaticResource
aView
a__all__
aBaseDict
T ERuntimeError
:nl nT Oint
Q
T u^[0-9A-Za-z!#\$%&'\*\+\-\.\^_`\|~]+$
T u(\{[_a-zA-Z][^{}]*(?:\{[^{}]*\}[^{}]*)*\})
a_ExpectHandler
a_Resolve
partial
D aquote
tD atotal
Fa__prepare__
a_InfoDict
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
