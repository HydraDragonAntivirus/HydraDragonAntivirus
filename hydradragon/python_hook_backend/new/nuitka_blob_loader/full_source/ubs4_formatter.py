# Reconstructed from integrated Nuitka blob
# Module: ubs4.formatter

uDescribes a strategy to use when outputting a parse tree to a string.
Some parts of this strategy come from the distinction between
HTML4, HTML5, and XML. Others are configurable by the user.
Formatters are passed in as the `formatter` argument to methods
like `bs4.element.Tag.encode`. Most people won't need to
think about formatters, and most people who need to think about
them can pass in one of these predefined strings as `formatter`
rather than making a new Formatter object:
For HTML documents:
* 'html' - HTML entity substitution for generic HTML documents. (default)
* 'html5' - HTML entity substitution for HTML5 documents, as
well as some optimizations in the way tags are rendered.
* 'html5-4.12.0' - The version of the 'html5' formatter used prior to
Beautiful Soup 4.13.0.
* 'minimal' - Only make the substitutions necessary to guarantee
valid HTML.
* None - Do not perform any substitution. This will be faster
but may result in invalid markup.
For XML documents:
* 'html' - Entity substitution for XHTML documents.
* 'minimal' - Only make the substitutions necessary to guarantee
valid XML. (default)
* None - Do not perform any substitution. This will be faster
but may result in invalid markup.
a__qualname__
html
str
xml
dict
set
script
style
S ascript
style
T acdata_containing_tags
uDict[str, Set[str]]
uOptional[str]
uOptional[_EntitySubstitutionFunction]
uSet[str]
bool
D alanguage
value
kwarg
return
str
uOptional[Set[str]]
str
uSet[str]
uFormatter._default
T nnw/nFl D alanguage
entity_substitution
void_element_close_prefix
cdata_containing_tags
empty_attributes_are_booleans
indent
uOptional[str]
uOptional[_EntitySubstitutionFunction]
str
uOptional[Set[str]]
bool
uUnion[int, str]
uFormatter.__init__
D ans
return
str
puFormatter.substitute
D avalue
return
str
paattribute_value
uFormatter.attribute_value
D atag
return
ubs4.element.Tag
uIterable[Tuple[str, Optional[_AttributeValue]]]
attributes
uFormatter.attributes
a__orig_bases__
uA generic Formatter for HTML.
aREGISTRY
uDict[Optional[str], HTMLFormatter]
T nw/nFl D aentity_substitution
void_element_close_prefix
cdata_containing_tags
empty_attributes_are_booleans
indent
uOptional[_EntitySubstitutionFunction]
str
uOptional[Set[str]]
bool
uUnion[int, str]
uHTMLFormatter.__init__
uA generic Formatter for XML.
uDict[Optional[str], XMLFormatter]
uXMLFormatter.__init__
substitute_html
T aentity_substitution
substitute_html5
T aentity_substitution
void_element_close_prefix
empty_attributes_are_booleans
html5
uhtml5-4.12
substitute_xml
minimal
T nT L Ostr
Ostr
a_EntitySubstitutionFunction
a_FormatterOrName
ubs4\formatter.py
T a.0
wkwvaself
u<module bs4.formatter>
T a__class__
T aself
language
entity_substitution
void_element_close_prefix
cdata_containing_tags
empty_attributes_are_booleans
indent
indent_str
T aself
entity_substitution
void_element_close_prefix
cdata_containing_tags
empty_attributes_are_booleans
indent
a__class__
T aself
language
value
kwarg
T aself
value
T aself
tag
items
T aself
ns
aNavigableString
a__spec__
.cbor2._decoder
4
fp
tag_hook
object_hook
str_errors
a_share_index
a_shareables
a_stringref_namespace
a_immutable

:param fp:
the file to read from (any file-like object opened for reading in binary
mode)
:param tag_hook:
callable that takes 2 arguments: the decoder instance, and the
:class:`.CBORTag` to be decoded. This callback is invoked for any tags
for which there is no built-in decoder. The return value is substituted
for the :class:`.CBORTag` object in the deserialized output
:param object_hook:
callable that takes 2 arguments: the decoder instance, and a
dictionary. This callback is invoked for each deserialized
:class:`dict` object. The return value is substituted for the dict in
the deserialized output.
:param str_errors:
determines how to handle unicode decoding errors (see the `Error Handlers`_
section in the standard library documentation for details)
.. _Error Handlers: https://docs.python.org/3/library/codecs.html#error-handlers

Used by decoders to check if the calling context requires an immutable
type.  Object_hook or tag_hook should raise an exception if this flag
is set unless the result can be safely used as a dict key.
a_fp
callable
read
ufp.read is not callable
ufp object has no read method
a_fp_read
a_tag_hook
utag_hook must be None or a callable
a_object_hook
uobject_hook must be None or a callable
a_str_errors
T astrict
error
replace
uinvalid str_errors value

u (must be one of 'strict', 'error', or 'replace')

Set the shareable value for the last encountered shared value marker,
if any. If the current shared index is ``None``, nothing is done.
:param value: the shared value
:returns: the shared value to permit chaining
l l l g
l l aappend
aCBORDecodeEOF
upremature end of stream (expected to read
u bytes, got
u instead)

Read bytes from the data stream.
:param int amount: the number of bytes to read
T l l amajor_decoders
old_immutable
old_index
a_decode

Decode the next value from the stream.
:raises CBORDecodeError: if there is any problem decoding the stream
aBytesIO
a__enter__
a__exit__
T nnnu
Wrap the given bytestring as a file and call :meth:`decode` with it as
the argument.
This method was intended to be used from the ``tag_hook`` hook when an
object needs to be decoded separately from the rest but while still
taking advantage of the shared value registry.
l l acast
struct
unpack
u>H
T l l u>L
T l l u>Q
T l aCBORDecodeValueError
uunknown unsigned integer subtype 0x
wxaset_shareable
a_decode_length
D aallow_indefinite
taself
l  c
buf
l g            uinvalid length for indefinite bytestring chunk 0x
T unon-bytestring found in indefinite length bytestring
uinvalid length for bytestring 0x
l   B
left
min
buffer
extend
a_stringref_namespace_add
length
result
uinvalid length for indefinite string chunk 0x
decode
uutf-8
T uerror decoding unicode string
T unon-string found in indefinite length string
uinvalid length for string 0x
incremental_utf8_decoder
codec
break_marker
items
uinvalid length for array 0x
T tpT aimmutable
unshared
T tT aunshared
dictionary
aFrozenDict
semantic_decoders
get
aCBORTag
value
tag
l aCBORSimpleValue
special_decoders
uUndefined Reserved major type 7 subtype 0x
date
fromordinal
l  +afromisoformat
timestamp_re
match
groups
u<06
w-atimezone
timedelta
T ahours
minutes
utc
datetime
uinvalid datetime string:
fromtimestamp
T EOverflowError
EOSError
EValueError
T uerror decoding datetime from epoch
binascii
T ahexlify
hexlify
uinvalid bignum value
l adecode_positive_bignum
decimal
T aDecimal
aDecimal
T ETypeError
EValueError
T uIncorrect tag 4 payload
as_tuple
sign
digits
T uIncorrect tag 5 payload
T ustring reference outside of namespace
ustring reference %d not found
T nushared reference %d not found
ushared value %d has not been initialized
fractions
T aFraction
aFraction
T ETypeError
EZeroDivisionError
T uerror decoding rational: input value was not a tuple
T uerror decoding rational
re
compile
error
T uerror decoding regular expression
uemail.parser
T aParser
aParser
parsestr
T uerror decoding MIME message
uuid
T aUUID
aUUID
T abytes
T uerror decoding UUID value
T aimmutable
ipaddress
T aip_address
ip_address
T l l l uinvalid ipaddress value
T l l l  T aip_network
ip_network
aMapping
D astrict
Fuinvalid ipnetwork value
u>e
u>f
u>d
undefined
aCBORDecoder
T atag_hook
object_hook
str_errors

Deserialize an object from a bytestring.
:param bytes s:
the bytestring to deserialize
:param tag_hook:
callable that takes 2 arguments: the decoder instance, and the :class:`.CBORTag`
to be decoded. This callback is invoked for any tags for which there is no
built-in decoder. The return value is substituted for the :class:`.CBORTag`
object in the deserialized output
:param object_hook:
callable that takes 2 arguments: the decoder instance, and a dictionary. This
callback is invoked for each deserialized :class:`dict` object. The return value
is substituted for the dict in the deserialized output.
:param str_errors:
determines how to handle unicode decoding errors (see the `Error Handlers`_
section in the standard library documentation for details)
:return:
the deserialized object
.. _Error Handlers: https://docs.python.org/3/library/codecs.html#error-handlers

Deserialize an object from an open file.
:param fp:
the file to read from (any file-like object opened for reading in binary mode)
:param tag_hook:
callable that takes 2 arguments: the decoder instance, and the :class:`.CBORTag`
to be decoded. This callback is invoked for any tags for which there is no
built-in decoder. The return value is substituted for the :class:`.CBORTag`
object in the deserialized output
:param object_hook:
callable that takes 2 arguments: the decoder instance, and a dictionary. This
callback is invoked for each deserialized :class:`dict` object. The return value
is substituted for the dict in the deserialized output.
:param str_errors:
determines how to handle unicode decoding errors (see the `Error Handlers`_
section in the standard library documentation for details)
:return:
the deserialized object
.. _Error Handlers: https://docs.python.org/3/library/codecs.html#error-handlers
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
sys
codecs
T agetincrementaldecoder
getincrementaldecoder
ucollections.abc
T aCallable
aMapping
aSequence
aCallable
aSequence
T adate
datetime
timedelta
timezone
aIO
aTYPE_CHECKING
aAny
aTypeVar
overload
a_types
T aCBORDecodeEOF
aCBORDecodeValueError
aCBORSimpleValue
aCBORTag
aFrozenDict
break_marker
undefined
T wTwTT u^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,6})\d*)?(?:Z|([+-])(\d\d):(\d\d))$
T uutf-8
