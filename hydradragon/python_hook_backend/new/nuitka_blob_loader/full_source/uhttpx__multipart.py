# Reconstructed from integrated Nuitka blob
# Module: uhttpx._multipart


A single form field item, within a multipart form field.
a__qualname__
D aname
value
return
str
ustr | bytes | int | float | None
aNone
a__init__
uDataField.__init__
D areturn
bytes
uDataField.render_headers
uDataField.render_data
D areturn
int
uDataField.get_length
D areturn
utyping.Iterator[bytes]

A single file field item, within a multipart form field.
l   D aname
value
return
str
aFileTypes
aNone
uFileField.__init__
D areturn
uint | None
uFileField.get_length
uFileField.render_headers
a__prepare__
aMultipartStream
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Request content as streaming multipart encoded form data.
T nD adata
files
boundary
return
aRequestData
aRequestFiles
ubytes | None
aNone
uMultipartStream.__init__
D adata
files
return
aRequestData
aRequestFiles
utyping.Iterator[FileField | DataField]
uMultipartStream.get_content_length
D areturn
udict[str, str]
get_headers
uMultipartStream.get_headers
D areturn
utyping.AsyncIterator[bytes]
a__orig_bases__
uhttpx\_multipart.py
T a.0
key
u<module httpx._multipart>
T a__class__
T aself
chunk
T aself
name
value
T aself
name
value
fileobj
headers
content_type
filename
has_content_type_header
T aself
data
files
boundary
T aname
value
replacer
T afilename
T aself
data
files
name
value
item
file_items
T aself
boundary_length
length
field
field_length
T aself
content_length
content_type
T aself
headers
data
T aself
headers
file_length
T acontent_type
section
T aself
field
T aself
T aself
name
T aself
parts
filename
header_name
header_value
key
val
T amatch
a__spec__
.httpx._status_codes
S
a__new__
a_value_
phrase
value
codes

ldl  u
Returns `True` for 1xx status codes, `False` otherwise.
l  l  u
Returns `True` for 2xx status codes, `False` otherwise.
l  l  u
Returns `True` for 3xx status codes, `False` otherwise.
l  l  u
Returns `True` for 4xx status codes, `False` otherwise.
l  l  u
Returns `True` for 5xx status codes, `False` otherwise.

Returns `True` for 4xx or 5xx status codes, `False` otherwise.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
enum
T aIntEnum
aIntEnum
a__all__
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
