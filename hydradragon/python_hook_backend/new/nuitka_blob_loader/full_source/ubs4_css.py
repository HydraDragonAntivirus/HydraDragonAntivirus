# Reconstructed from integrated Nuitka blob
# Module: ubs4.css

uA proxy object against the ``soupsieve`` library, to simplify its
CSS selector API.
You don't need to instantiate this class yourself; instead, use
`element.Tag.css`.
:param tag: All CSS selectors run by this object will use this as
their starting point.
:param api: An optional drop-in replacement for the ``soupsieve`` module,
intended for use in unit tests.
a__qualname__
T nD atag
api
uelement.Tag
uOptional[ModuleType]
a__init__
uCSS.__init__
D aident
return
str
puCSS.escape
D ans
select
return
uOptional[_NamespaceMapping]
str
uOptional[_NamespaceMapping]
uCSS._ns
D aresults
return
uIterable[Tag]
uResultSet[Tag]
uCSS._rs
T nl
D aselect
namespaces
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
aAny
aSoupSieve
uCSS.compile
D aselect
namespaces
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
aAny
uelement.Tag | None
uCSS.select_one
T nl
pD aselect
namespaces
limit
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
paAny
uResultSet[element.Tag]
uCSS.select
D aselect
namespaces
limit
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
paAny
uIterator[element.Tag]
uCSS.iselect
D aselect
namespaces
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
aAny
uOptional[element.Tag]
uCSS.closest
D aselect
namespaces
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
aAny
bool
uCSS.match
D aselect
namespaces
flags
kwargs
return
str
uOptional[_NamespaceMapping]
int
aAny
uResultSet[element.Tag]
uCSS.filter
a__orig_bases__
ubs4\css.py
u<module bs4.css>
T a__class__
T aself
tag
api
T aself
ns
select
T aself
results
aResultSet
T aself
select
namespaces
flags
kwargs
T aself
ident
T aself
select
namespaces
limit
flags
kwargs

a__spec__
.bs4.dammit
AR
Q achardet_module
detect
encoding
uTry as hard as possible to detect the encoding of a bytestring.
defaultdict
T Oset
sorted
html5
items
endswith
T w;:nq naname_to_unicode
unicode_to_name
l  u<>
w&ashort_entities
add
particles

u%s(?![%s])
values
u(%s)
w|T w&acodepoint2name
aCHARACTER_TO_HTML_ENTITY
aHTML_ENTITY_TO_CHARACTER
re
compile
aCHARACTER_TO_HTML_ENTITY_RE
aCHARACTER_TO_HTML_ENTITY_WITH_AMPERSAND_RE
uInitialize variables used by this class to manage the plethora of
HTML5 named entities.
This function sets the following class variables:
CHARACTER_TO_HTML_ENTITY - A mapping of Unicode strings like "   " to
entity names like "angmsdaa". When a single Unicode string has
multiple entity names, we try to choose the most commonly-used
name.
HTML_ENTITY_TO_CHARACTER: A mapping of entity names like "angmsdaa" to
Unicode strings like "   ".
CHARACTER_TO_HTML_ENTITY_RE: A regular expression matching (almost) any
Unicode string that corresponds to an HTML5 named entity.
CHARACTER_TO_HTML_ENTITY_WITH_AMPERSAND_RE: A very similar
regular expression to CHARACTER_TO_HTML_ENTITY_RE, but which
lso matches unescaped ampersands. This is used by the 'html'
formatted to provide backwards-compatibility, even though the HTML5
spec allows most ampersands to go unescaped.
u<genexpr>
uEntitySubstitution._populate_class_variables.<locals>.<genexpr>
group
T l
get
u&amp;%s;
u&%s;
uUsed with a regular expression to substitute the
ppropriate HTML entity for a special character string.
aCHARACTER_TO_XML_ENTITY
uUsed with a regular expression to substitute the
ppropriate XML entity for a special character string.
T l w"w'areplace
T w"u&quot;
uMake a value into a quoted XML attribute, possibly escaping it.
Most strings will be quoted using double quotes.
Bob's Bar -> "Bob's Bar"
If a string contains double quotes, it will be quoted using
single quotes.
Welcome to "my bar" -> 'Welcome to "my bar"'
If a string contains both single and double quotes, the
double quotes will be escaped, and the string will be quoted
using double quotes.
Welcome to "Bob's Bar" -> Welcome to &quot;Bob's bar&quot;
:param value: The XML attribute value to quote
:return: The quoted value
aAMPERSAND_OR_BRACKET
sub
a_substitute_xml_entity
quoted_attribute_value
uReplace special XML characters with named XML entities.
The less-than sign will become &lt;, the greater-than sign
will become &gt;, and any ampersands will become &amp;. If you
want ampersands that seem to be part of an entity definition
to be left alone, use `substitute_xml_containing_entities`
instead.
:param value: A string to be substituted.
:param make_quoted_attribute: If True, then the string will be
quoted, as befits an attribute value.
:return: A version of ``value`` with special characters replaced
with named entities.
aBARE_AMPERSAND_OR_BRACKET
uSubstitute XML entities for special XML characters.
:param value: A string to be substituted. The less-than sign will
become &lt;, the greater-than sign will become &gt;, and any
mpersands that are not part of an entity defition will
become &amp;.
:param make_quoted_attribute: If True, then the string will be
quoted, as befits an attribute value.
a_substitute_html_entity
uReplace certain Unicode characters with named HTML entities.
This differs from ``data.encode(encoding, 'xmlcharrefreplace')``
in that the goal is to make the result more readable (to those
with ASCII displays) rather than to recover from
errors. There's absolutely nothing wrong with a UTF-8 string
containg a LATIN SMALL LETTER E WITH ACUTE, but replacing that
character with "&eacute;" will make it more readable to some
people.
:param s: The string to be modified.
:return: The string with some Unicode characters replaced with
HTML entities.
aANY_ENTITY_RE
a_escape_entity_name
uReplace certain Unicode characters with named HTML entities
using HTML5 rules.
Specifically, this method is much less aggressive about
escaping ampersands than substitute_html. Only ambiguous
mpersands are escaped, per the HTML5 standard:
"An ambiguous ampersand is a U+0026 AMPERSAND character (&)
that is followed by one or more ASCII alphanumerics, followed
by a U+003B SEMICOLON character (;), where these characters do
not match any of the names given in the named character
references section."
Unlike substitute_html5_raw, this method assumes HTML entities
were converted to Unicode characters on the way in, as
Beautiful Soup does. By the time Beautiful Soup does its work,
the only ambiguous ampersands that need to be escaped are the
ones that were escaped in the original markup when mentioning
HTML entities.
:param s: The string to be modified.
:return: The string with some Unicode characters replaced with
HTML entities.
a_escape_unrecognized_entity_name
uReplace certain Unicode characters with named HTML entities
using HTML5 rules.
substitute_html5_raw is similar to substitute_html5 but it is
designed for standalone use (whereas substitute_html5 is
designed for use with Beautiful Soup).
:param s: The string to be modified.
:return: The string with some Unicode characters replaced with
HTML entities.
known_definite_encodings
warnings
warn
uThe 'override_encodings' argument was deprecated in 4.10.0. Use 'known_definite_encodings' instead.
aDeprecationWarning
D astacklevel
l auser_encodings
lower
exclude_encodings
chardet_encoding
is_html
declared_encoding
strip_byte_order_mark
markup
sniffed_encoding
uShould we even bother to try this encoding?
:param encoding: Name of an encoding.
:param tried: Encodings that have already been tried. This
will be modified as a side effect.
uYield a number of encodings that might work for this markup.
:yield: A sequence of strings. Each is the name of an encoding
that *might* work to convert a bytestring into Unicode.
self
a_usable
tried
find_declared_encoding
a_chardet_dammit
T uutf-8
uwindows-1252
encodings
uEncodingDetector.encodings
:nl nc
:l l nb
uutf-16be
:l nnc
uutf-16le
:nl nc
uutf-8
:l nn:nl nb
uutf-32be
:l nnb
uutf-32le
data
uIf a byte-order mark is present, strip it and return the encoding it implies.
:param data: A bytestring that may or may not begin with a
byte-order mark.
:return: A 2-tuple (data stripped of byte-order mark, encoding implied by byte-order mark)
l  amax
l  f       ?aencoding_res
xml
html
search
T aendpos
groups
decode
T aascii
replace
uGiven a document, tries to find an encoding declared within the
text of the document itself.
An XML encoding is declared at the beginning of the document.
An HTML encoding is declared in a <meta> tag, hopefully near the
beginning of the document.
:param markup: Some markup.
:param is_html: If True, this markup is considered to be HTML. Otherwise
it's assumed to be XML.
:param search_entire_document: Since an encoding is supposed
to declared near the beginning of the document, most of
the time it's only necessary to search a few kilobytes of
data.  Set this to True to force this method to search the
entire document.
:return: The declared encoding, if one is found.
smart_quotes_to
tried_encodings
contains_replacement_characters
getLogger
T ubs4.dammit
log
aEncodingDetector
detector
c
unicode_markup
original_encoding
a_convert_from
wuaascii
warning
T uSome characters could not be decoded, and were replaced with REPLACEMENT CHARACTER.
aMS_CHARS_TO_ASCII
encode
aMS_CHARS
c&#x
d;d&acast
uChanges a MS smart quote character to an XML or HTML
entity, or an ASCII character.
TODO: Since this is only used to convert smart quotes, it
could be simplified, and MS_CHARS_TO_ASCII made much less
parochial.
find_codec
append
aENCODINGS_WITH_SMART_QUOTES
T c([ - ])
a_sub_ms_char
a_to_unicode
uAttempt to convert the markup to the proposed encoding.
:param proposed: The name of a character encoding.
:param errors: An error handling strategy, used when calling `str`.
:return: The converted markup, or `None` if the proposed
encoding/error handling strategy didn't work.
uGiven a bytestring and its encoding, decodes the string into Unicode.
:param encoding: The name of an encoding.
:param errors: An error handling strategy, used when calling `str`.
uIf the markup is an HTML document, returns the encoding, if any,
declared *inside* the document.
a_codec
aCHARSET_ALIASES
T w-u
T w-w_uLook up the Python codec corresponding to a given character set.
:param charset: The name of a character set.
:return: The name of a Python codec.
codecs
lookup
T ELookupError
EValueError
T w_w-T uwindows-1252
windows_1252
uWindows-1252 and ISO-8859-1 are the only currently supported embedded encodings.
T autf8
uutf-8
uUTF-8 is the only currently supported main encoding.
pos
cls
aFIRST_MULTIBYTE_MARKER
aLAST_MULTIBYTE_MARKER
aMULTIBYTE_MARKERS_AND_SIZES
aWINDOWS_1252_TO_UTF8
byte_chunks
chunk_start
uFix characters from one encoding embedded in some other encoding.
Currently the only situation supported is Windows-1252 (or its
subset ISO-8859-1), embedded in UTF-8.
:param in_bytes: A bytestring that you suspect contains
characters from multiple encodings. Note that this *must*
be a bytestring. If you've already converted the document
to Unicode, you're too late.
:param main_encoding: The primary encoding of ``in_bytes``.
:param embedded_encoding: The encoding that was used to embed characters
in the main document.
:return: A bytestring similar to ``in_bytes``, in which
``embedded_encoding`` characters have been converted to
their ``main_encoding`` equivalents.
uBeautiful Soup bonus library: Unicode, Dammit
This library converts a bytestream to Unicode through any means
necessary. It is heavily based on code from Mark Pilgrim's `Universal
Feed Parser <https://pypi.org/project/feedparser/>`_, now maintained
by Kurt McKee. It does not rewrite the body of an XML or HTML document
to reflect a new encoding; that's the job of `TreeBuilder`.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aMIT
a__license__
uhtml.entities
T acodepoint2name
collections
T adefaultdict
T ahtml5
logging
T aLogger
getLogger
aLogger
aModuleType
aDict
aIterator
aList
aOptional
aPattern
aSet
aTuple
aType
aUnion
typing_extensions
T aLiteral
aLiteral
ubs4._typing
T a_Encoding
a_Encodings
a_Encoding
a_Encodings
cchardet
chardet
charset_normalizer
wsareturn
u^\s*<\?.*encoding=['"](.*?)['"].*\?>
xml_encoding
u<\s*meta[^>]+charset\s*=\s*["']?([^>]*?)[ /;'">]
html_meta
T aascii
wIT Oobject
a__prepare__
aEntitySubstitution
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
