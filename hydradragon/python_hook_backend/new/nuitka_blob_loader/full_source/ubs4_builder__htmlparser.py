# Reconstructed from integrated Nuitka blob
# Module: ubs4.builder._htmlparser

a__qualname__
a__annotations__
replace
str
ignore
D asoup
on_duplicate_attribute
args
kwargs
aBeautifulSoup
uUnion[str, _DuplicateAttributeHandler]
aAny
puBeautifulSoupHTMLParser.__init__
uUnion[str, _DuplicateAttributeHandler]
uList[str]
aBeautifulSoup
D amessage
return
str
aNone
error
uBeautifulSoupHTMLParser.error
D aname
attrs
return
str
uList[Tuple[str, Optional[str]]]
aNone
handle_startendtag
uBeautifulSoupHTMLParser.handle_startendtag
T tD aname
attrs
handle_empty_element
return
str
uList[Tuple[str, Optional[str]]]
bool
aNone
uBeautifulSoupHTMLParser.handle_starttag
D aname
check_already_closed
return
str
bool
aNone
uBeautifulSoupHTMLParser.handle_endtag
D adata
return
str
aNone
uBeautifulSoupHTMLParser.handle_data
D aname
return
str
aNone
handle_charref
uBeautifulSoupHTMLParser.handle_charref
handle_entityref
uBeautifulSoupHTMLParser.handle_entityref
handle_comment
uBeautifulSoupHTMLParser.handle_comment
handle_decl
uBeautifulSoupHTMLParser.handle_decl
unknown_decl
uBeautifulSoupHTMLParser.unknown_decl
handle_pi
uBeautifulSoupHTMLParser.handle_pi
a__orig_bases__
uA Beautiful soup `bs4.builder.TreeBuilder` that uses the
:py:class:`html.parser.HTMLParser` parser, found in the Python
standard library.
is_xml
bool
picklable
aNAME
features
uIterable[str]
uTuple[Iterable[Any], Dict[str, Any]]
aTRACKS_LINE_NUMBERS
T nnD aparser_args
parser_kwargs
kwargs
uOptional[Iterable[Any]]
uOptional[Dict[str, Any]]
aAny
uHTMLParserTreeBuilder.__init__
T nnnD amarkup
user_specified_encoding
document_declared_encoding
exclude_encodings
return
a_RawMarkup
uOptional[_Encoding]
uOptional[_Encoding]
uOptional[_Encodings]
uIterable[Tuple[str, Optional[_Encoding], Optional[_Encoding], bool]]
D amarkup
return
a_RawMarkup
aNone
uHTMLParserTreeBuilder.feed
ubs4\builder\_htmlparser.py
u<module bs4.builder._htmlparser>
T a__class__
T aself
soup
on_duplicate_attribute
args
kwargs
T aself
parser_args
parser_kwargs
kwargs
extra_parser_kwargs
arg
value
a__class__
T aself
message
T aself
markup
args
kwargs
parser
weT aself
name
real_name
data
encoding
T aself
data
T aself
name
check_already_closed
T aself
name
character
data
T aself
name
attrs
T aself
name
attrs
handle_empty_element
attr_dict
sourceline
sourcepos
key
value
on_dupe
tag
T aself
markup
user_specified_encoding
document_declared_encoding
exclude_encodings
known_definite_encodings
user_encodings
dammit
T aself
data
cls
a__spec__
.bs4.builder._lxml
items
uInvert a dictionary.
u<genexpr>
u_invert.<locals>.<genexpr>
aLXMLTreeBuilderForXML
initialize_soup
a_register_namespaces
aDEFAULT_NSMAPS
uLet the BeautifulSoup object know about the standard namespace
mapping.
:param soup: A `BeautifulSoup`.
soup
self
a_namespaces
uLet the BeautifulSoup object know about namespaces encountered
while parsing the document.
This might be useful later on when creating CSS selectors.
This will track (almost) all namespaces, even ones that were
only in scope for part of the document. If two namespaces have
the same prefix, only the first one encountered will be
tracked. Un-prefixed namespaces are not tracked.
:param mapping: A dictionary mapping namespace prefixes to URIs.
a_default_parser
aDEFAULT_PARSER_CLASS
T atarget
recover
encoding
uFind the default parser for the given encoding.
:return: Either a parser object or a class, which
will be instantiated with default arguments.
default_parser
callable
uInstantiate an appropriate parser for the given encoding.
:param encoding: A string.
:return: A parser object such as an `etree.XMLParser`.
aDEFAULT_NSMAPS_INVERTED
nsmaps
active_namespace_prefixes
attribute_dict_class
aXMLAttributeDict
a__init__
w{:l nnasplit
T w}l uRun any preliminary steps necessary to make incoming markup
cceptable to the parser.
lxml really wants to get a bytestring and convert it to
Unicode itself. So instead of using UnicodeDammit to convert
the bytestring to Unicode using different encodings, this
implementation uses EncodingDetector to iterate over the
encodings, and tell lxml to try to parse the document as each
one in turn.
:param markup: Some markup -- hopefully a bytestring.
:param user_specified_encoding: The user asked to try this encoding.
:param document_declared_encoding: The markup itself claims to be
in this encoding.
:param exclude_encodings: The user asked _not_ to try any of
these encodings.
:yield: A series of 4-tuples: (markup, encoding, declared encoding,
has undergone character replacement)
Each 4-tuple represents a strategy for converting the
document to Unicode and parsing it. Each strategy will be tried
in turn.
is_xml
aProcessingInstruction
processing_instruction_class
aDetectsXMLParsedAsHTML
warn_if_markup_looks_like_xml
markup
D astacklevel
l aXMLProcessingInstruction

document_declared_encoding
encode
T autf8
utf8
user_specified_encoding
aEncodingDetector
exclude_encodings
T aknown_definite_encodings
user_encodings
is_html
exclude_encodings
encodings
detector
prepare_markup
uLXMLTreeBuilderForXML.prepare_markup
aBytesIO
aStringIO
io
read
aCHUNK_SIZE
parser_for
original_encoding
parser
feed
data
close
etree
aParserError
aParserRejectedMarkup
new_attrs
append
T na_invert

aNamespacedAttribute
xmlns
uhttp://www.w3.org/2000/xmlns/
a_getNsTag
final_attrs
a_prefix_for_namespace
handle_starttag
T anamespaces
uFind the currently active prefix for the given namespace.
endData
handle_endtag
pop
w ahandle_data
aDoctype
a_string_for_name_and_ids
T acontainerClass
aComment
uHandle comments as Comment objects.
u<?xml version="1.0" encoding="utf-8"?>
%s
uSee `TreeBuilder`.
aHTMLParser
u<html><body>%s</body></html>
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
aMIT
a__license__
aLXMLTreeBuilder
a__all__
aAny
aDict
aIterable
aList
aOptional
aSet
aTuple
aType
aTYPE_CHECKING
aUnion
typing_extensions
T aTypeAlias
aTypeAlias
lxml
T aetree
ubs4.element
T aAttributeDict
aXMLAttributeDict
aComment
aDoctype
aNamespacedAttribute
aProcessingInstruction
aXMLProcessingInstruction
aAttributeDict
ubs4.builder
T aDetectsXMLParsedAsHTML
aFAST
aHTML
aHTMLTreeBuilder
aPERMISSIVE
aTreeBuilder
aXML
aFAST
aHTML
aHTMLTreeBuilder
aPERMISSIVE
aTreeBuilder
aXML
ubs4.dammit
T aEncodingDetector
ubs4.exceptions
T aParserRejectedMarkup
aLXML
str
D wdareturn
udict[Any, Any]
udict[Any, Any]
aXMLParser
a_LXMLParser
a_ParserOrParserClass
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
