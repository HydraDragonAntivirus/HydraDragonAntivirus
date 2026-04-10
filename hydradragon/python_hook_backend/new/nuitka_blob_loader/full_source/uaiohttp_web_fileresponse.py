# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_fileresponse

uThe result of the file response.
a__qualname__
a__orig_bases__
clear
extension
add_type
aFuture
aFileResponse
uA response object can be used to send files.
T l   l  nnapath
int
reason
str
return
uFileResponse.__init__
uFileResponse._seek_and_read
aBaseRequest
staticmethod
etags
bool
uFileResponse._etag_match
float
accept_encoding
aBufferedReader
stat_result
uFileResponse._make_response
uFileResponse._get_file_path_stat_encoding
uaiohttp\web_fileresponse.py
T a.0
etag
weak
etag_value
u<module aiohttp.web_fileresponse>
T a__class__
T aself
path
chunk_size
status
reason
headers
a__class__
T aetag_value
etags
weak
T aself
accept_encoding
file_path
file_extension
file_encoding
compressed_path
ast
T aself
request
accept_encoding
file_path
ast
file_encoding
etag_value
ifmatch
unmodsince
ifnonematch
modsince
fobj
T aself
request
etag_value
last_modified
a__class__
T aself
request
a__class__
T aself
request
fobj
ast
file_encoding
file_size
file_mtime
count
start
end
status
ifrange
rng
guesser
real_start
offset
a__class__
T aself
fobj
offset
chunk_size
T	aself
request
fobj
offset
count
writer
loop
transport
a__class__
T aself
writer
fobj
offset
count
chunk_size
loop
chunk
T aself
request
loop
accept_encoding
response_result
fobj
ast
file_encoding
etag_value
last_modified
close_future
a__class__
a__spec__
.aiohttp.web_log
&
a__class__
a__init__
T alog_format
aAccessLogger
a_FORMAT_CACHE
get
compile_format
a_compiled_format
a_log_format
a_methods
uInitialise the logger.
logger is a logger object to be used for logging.
log_format is a string with apache compatible log format description.
aFORMAT_RE
findall

self
aLOG_FORMAT_MAP
u_format_%s
aKeyMethod
l apartial
methods
sub
u%s
aCLEANUP_RE
u%\1
uTranslate log_format into form usable by modulo formatting
All known atoms will be replaced with %s
Also methods for formatting of those atoms will be added to
_methods in appropriate order
For example we have log_format = "%a %t"
This format will be translated to "%s %s"
Also contents of _methods will be
[self._format_a, self._format_t]
These method will be called and results will be passed
to translated string format.
Each _format_* method receive 'args' which is list of arguments
given to self.log
Exceptions are _format_e, _format_i and _format_o methods which
lso receive key name (by functools.partial)
u(no headers)
headers
w-aremote
datetime
timezone
timedelta
time_mod
T aseconds
now
strftime
T u[%d/%b/%Y:%H:%M:%S %z]
u<%s>
getpid
u{} {} HTTP/{}.{}
method
path_qs
version
major
minor
status
body_length
round
u%06f
l  =arequest
response
time
logger
isEnabledFor
logging
aINFO
uCheck if logger is enabled.
a_format_line
values
extra
info
T aextra
exception
T uError in logging
a__doc__
a__file__
origin
has_location
a__cached__
functools
os
re
collections
T anamedtuple
namedtuple
aAny
aCallable
aDict
aIterable
aList
aTuple
abc
T aAbstractAccessLogger
aAbstractAccessLogger
web_request
T aBaseRequest
aBaseRequest
web_response
T aStreamResponse
aStreamResponse
T aKeyMethod
ukey method
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
