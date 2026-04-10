# Reconstructed from integrated Nuitka blob
# Module: ubs4.builder._lxml

a__qualname__
uType[etree.XMLParser]
bool
uType[ProcessingInstruction]
ulxml-xml
aNAME
xml
aALTERNATE_NAMES
uIterable[str]
features
l  aint
dict
T uhttp://www.w3.org/XML/1998/namespace
T axml
D axml
uhttp://www.w3.org/XML/1998/namespace
a_NamespaceMapping
a_InvertedNamespaceMapping
uList[Optional[_InvertedNamespaceMapping]]
uSet[str]
empty_element_tags
uOptional[etree.XMLParser]
D asoup
return
aBeautifulSoup
aNone
uLXMLTreeBuilderForXML.initialize_soup
D amapping
return
uDict[str, str]
aNone
uLXMLTreeBuilderForXML._register_namespaces
D aencoding
return
uOptional[_Encoding]
a_ParserOrParserClass
uLXMLTreeBuilderForXML.default_parser
D aencoding
return
uOptional[_Encoding]
a_LXMLParser
uLXMLTreeBuilderForXML.parser_for
T nnD aparser
empty_element_tags
kwargs
uOptional[etree.XMLParser]
uOptional[Set[str]]
aAny
uLXMLTreeBuilderForXML.__init__
D atag
return
str
uTuple[Optional[str], str]
uLXMLTreeBuilderForXML._getNsTag
T nnnD amarkup
user_specified_encoding
document_declared_encoding
exclude_encodings
return
a_RawMarkup
uOptional[_Encoding]
uOptional[_Encoding]
uOptional[_Encodings]
uIterable[Tuple[Union[str, bytes], Optional[_Encoding], Optional[_Encoding], bool]]
D amarkup
return
a_RawMarkup
aNone
uLXMLTreeBuilderForXML.feed
D areturn
aNone
uLXMLTreeBuilderForXML.close
D atag
attrs
nsmap
return
ustr | bytes
uDict[str | bytes, str | bytes]
a_NamespaceMapping
aNone
start
uLXMLTreeBuilderForXML.start
D anamespace
return
uOptional[_NamespaceURL]
uOptional[_NamespacePrefix]
uLXMLTreeBuilderForXML._prefix_for_namespace
D aname
return
ustr | bytes
aNone
end
uLXMLTreeBuilderForXML.end
D atarget
data
return
str
paNone
pi
uLXMLTreeBuilderForXML.pi
D adata
return
ustr | bytes
aNone
uLXMLTreeBuilderForXML.data
D aname
pubid
system
return
str
ppaNone
doctype
uLXMLTreeBuilderForXML.doctype
D atext
return
ustr | bytes
aNone
comment
uLXMLTreeBuilderForXML.comment
D afragment
return
str
patest_fragment_to_document
uLXMLTreeBuilderForXML.test_fragment_to_document
a__orig_bases__
ulxml-html
list
uLXMLTreeBuilder.default_parser
uLXMLTreeBuilder.feed
uLXMLTreeBuilder.test_fragment_to_document
ubs4\builder\_lxml.py
T a.0
wkwvu<module bs4.builder._lxml>
T a__class__
T aself
parser
empty_element_tags
kwargs
a__class__
T aself
tag
namespace
name
T wdT aself
namespace
inverted_nsmap
T aself
mapping
key
value
T aself
T aself
text
T aself
data
T aself
encoding
T aself
name
pubid
system
doctype_string
T aself
name
namespace
nsprefix
inverted_nsmap
out_of_scope_nsmap
T aself
markup
encoding
weT aself
markup
io
data
weT aself
soup
a__class__
T aself
encoding
parser
T aself
target
data
T
self
markup
user_specified_encoding
document_declared_encoding
exclude_encodings
known_definite_encodings
user_encodings
is_html
detector
encoding
T aself
tag
attrs
nsmap
new_attrs
nsprefix
namespace
final_attrs
wkwvacurrent_mapping
prefix
attribute
attr
value
T aself
fragment
a__spec__
.bs4.builder
iB
Z adefaultdict
T Olist
builders_for_feature
builders
features
self
insert
treebuilder_class
uRegister a treebuilder based on its advertised features.
:param treebuilder_class: A subclass of `TreeBuilder`. its
`TreeBuilder.features` attribute should list its features.
feature_list
get
candidates
candidate_set
intersection
uLook up a TreeBuilder subclass with the desired features.
:param features: A list of features to look for. If none are
provided, the most recently registered TreeBuilder subclass
will be used.
:return: A TreeBuilder subclass, or None if there's no
registered subclass with all the requested features.
soup
aUSE_DEFAULT
aDEFAULT_CDATA_LIST_ATTRIBUTES
cdata_list_attributes
aDEFAULT_PRESERVE_WHITESPACE_TAGS
preserve_whitespace_tags
aDEFAULT_EMPTY_ELEMENT_TAGS
empty_element_tags
aTRACKS_LINE_NUMBERS
store_line_numbers
aDEFAULT_STRING_CONTAINERS
string_containers
attribute_dict_class
attribute_value_list_class
uThe BeautifulSoup object has been initialized and is now
being associated with the TreeBuilder.
:param soup: A BeautifulSoup object.
uMight a tag with this name be an empty-element tag?
The final markup may or may not actually present this tag as
self-closing.
For instance: an HTMLBuilder does not consider a <p> tag to be
n empty-element tag (it's not in
HTMLBuilder.empty_element_tags). This means an empty <p> tag
will be presented as "<p></p>", not "<p/>" or "<p>".
The default implementation has no opinion about which tags are
empty-element tags, so a tag will be presented as an
empty-element tag if and only if it has no children.
"<foo></foo>" will become "<foo/>", and "<foo>bar</foo>" will
be left alone.
:param tag_name: The name of a markup tag.
uRun incoming markup through some parsing process.
uRun any preliminary steps necessary to make incoming markup
cceptable to the parser.
:param markup: The markup that's about to be parsed.
:param user_specified_encoding: The user asked to try this encoding
to convert the markup into a Unicode string.
:param document_declared_encoding: The markup itself claims to be
in this encoding. NOTE: This argument is not used by the
calling code and can probably be removed.
:param exclude_encodings: The user asked *not* to try any of
these encodings.
:yield: A series of 4-tuples: (markup, encoding, declared encoding,
has undergone character replacement)
Each 4-tuple represents a strategy that the parser can try
to convert the document to Unicode and parse it. Each
strategy will be tried in turn.
By default, the only strategy is to parse the markup
s-is. See `LXMLTreeBuilderForXML` and
`HTMLParserTreeBuilder` for implementations that take into
ccount the quirks of particular parsers.
:meta private:
markup
prepare_markup
uTreeBuilder.prepare_markup
uWrap an HTML fragment to make it look like a document.
Different parsers do this differently. For instance, lxml
introduces an empty <head> tag, and html5lib
doesn't. Abstracting this away lets us write simple tests
which run HTML fragments through the parser and compare the
results against other HTML fragments.
This method should not be used outside of unit tests.
:param fragment: A fragment of HTML.
:return: A full HTML document.
:meta private:
cast
a_AttributeValues
w*alower
keys
modified_attrs
a_RawAttributeValue
nonwhitespace_re
findall
uWhen an attribute value is associated with a tag that can
have multiple values for that attribute, convert the string
value to a list of strings.
Basically, replaces class="foo bar" with class=["foo", "bar"]
NOTE: This method modifies its input in place.
:param tag_name: The name of a tag.
:param attrs: A dictionary containing the tag's attributes.
Any appropriate attribute values will be modified in place.
:return: The modified dictionary that was originally passed in.
warnings
warn
uThe SAXTreeBuilder class was deprecated in 4.13.0 and will be removed soon thereafter. It is completely untested and probably doesn't work; do not use it.
aDeprecationWarning
D astacklevel
l aSAXTreeBuilder
a__init__
aAttributeDict
items
handle_starttag
u<genexpr>
uSAXTreeBuilder.startElement.<locals>.<genexpr>
handle_endtag
startElement
endElement
handle_data
name
meta
aOptional
T acontent
T acharset
get_attribute_list
T uhttp-equiv
aCharsetMetaAttributeValue
charset
aContentMetaAttributeValue
content
uReplace the declared encoding in a <meta> tag with a placeholder,
to be substituted when the tag is output to a string.
An HTML document may come in to Beautiful Soup as one
encoding, but exit in a different encoding, and the <meta> tag
needs to be changed to reflect this.
:return: Whether or not a substitution was performed.
:meta private:
ucontent-type
uHTMLTreeBuilder.set_up_substitutions.<locals>.<genexpr>
:nl  nastartswith
aXML_PREFIX_B
aLOOKS_LIKE_HTML_B
search
aXML_PREFIX
aLOOKS_LIKE_HTML
cls
a_warn
l T astacklevel
uPerform a check on some markup to see if it looks like XML
that's not XHTML. If so, issue a warning.
This is much less reliable than doing the check while parsing,
but some of the tree builders can't do that.
:param stacklevel: The stacklevel of the code calling this         function.
:return: True if the markup looks like non-XHTML XML, False
otherwise.
aXMLParsedAsHTMLWarning
aMESSAGE
uIssue a warning about XML being parsed as HTML.
a_first_processing_instruction
a_root_tag_name
uCall this method before parsing a document.
uCall this method when encountering an XML declaration, or a
"processing instruction" that might be an XML declaration.
This helps Beautiful Soup detect potential issues later, if
the XML document turns out to be a non-XHTML document that's
being parsed as XML.
html
T uxml
T l
uCall this when you encounter the document's root tag.
This is where we actually check whether an XML document is
being incorrectly parsed as HTML, and issue the warning.
modules
ubs4.builder
a__all__
aTreeBuilder
this_module
append
builder_registry
register
uCopy TreeBuilders from the given module into this module.
a__doc__
a__file__
path
dirname
join
environ
T aNUITKA_PACKAGE_bs4
u\not_existing
builder
T aNUITKA_PACKAGE_bs4_builder
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
a__annotations__
annotations
aMIT
a__license__
collections
T adefaultdict
re
aModuleType
aAny
aDict
aIterable
aList
aPattern
aSet
aTuple
aType
aTYPE_CHECKING
sys
ubs4.element
T
aAttributeDict
aAttributeValueList
aCharsetMetaAttributeValue
aContentMetaAttributeValue
aRubyParenthesisString
aRubyTextString
aStylesheet
aScript
aTemplateString
nonwhitespace_re
aAttributeValueList
aRubyParenthesisString
aRubyTextString
aStylesheet
aScript
aTemplateString
ubs4.exceptions
T aParserRejectedMarkup
aParserRejectedMarkup
ubs4._typing
T a_AttributeValues
a_RawAttributeValue
ubs4._warnings
T aXMLParsedAsHTMLWarning
L aHTMLTreeBuilder
aSAXTreeBuilder
aTreeBuilder
aTreeBuilderRegistry
fast
aFAST
permissive
aPERMISSIVE
strict
aSTRICT
xml
aXML
aHTML
html5
aHTML_5
L aTreeBuilderRegistry
aTreeBuilder
aHTMLTreeBuilder
aDetectsXMLParsedAsHTML
aParserRejectedMarkup
T Oobject
a__prepare__
aTreeBuilderRegistry
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
