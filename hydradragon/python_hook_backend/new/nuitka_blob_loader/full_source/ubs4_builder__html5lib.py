# Reconstructed from integrated Nuitka blob
# Module: ubs4.builder._html5lib

uUse `html5lib <https://github.com/html5lib/html5lib-python>`_ to
build a tree.
Note that `HTML5TreeBuilder` does not support some common HTML
`TreeBuilder` features. Some of these features could theoretically
be implemented, but at the very least it's quite difficult,
because html5lib moves the parse tree around as it's being built.
Specifically:
* This `TreeBuilder` doesn't use different subclasses of
`NavigableString` (e.g. `Script`) based on the name of the tag
in which the string was found.
* You can't use a `SoupStrainer` to parse only part of a document.
a__qualname__
a__annotations__
aNAME
str
features
aTRACKS_LINE_NUMBERS
bool
T nnnareturn
feed
uHTML5TreeBuilder.feed
namespaceHTMLElements
uHTML5TreeBuilder.create_treebuilder
fragment
test_fragment_to_document
uHTML5TreeBuilder.test_fragment_to_document
a__orig_bases__
aTreeBuilder
T ntakwargs
uTreeBuilderForHtml5lib.__init__
D areturn
aElement
documentClass
uTreeBuilderForHtml5lib.documentClass
token
insertDoctype
uTreeBuilderForHtml5lib.insertDoctype
elementClass
uTreeBuilderForHtml5lib.elementClass
data
commentClass
uTreeBuilderForHtml5lib.commentClass
fragmentClass
uTreeBuilderForHtml5lib.fragmentClass
getFragment
uTreeBuilderForHtml5lib.getFragment
D anode
return
aElement
nuTreeBuilderForHtml5lib.appendChild
D areturn
aBeautifulSoup
getDocument
uTreeBuilderForHtml5lib.getDocument
testSerializer
uTreeBuilderForHtml5lib.testSerializer
T Oobject
uRepresents a Tag's attributes in a way compatible with html5lib.
uAttrList.__init__
uAttrList.__iter__
value
a__setitem__
uAttrList.__setitem__
uAttrList.items
uAttrList.keys
int
a__len__
uAttrList.__len__
uAttrList.__getitem__
a__contains__
uAttrList.__contains__
aBeautifulSoupNode
property
nodeType
uBeautifulSoupNode.nodeType
cloneNode
uBeautifulSoupNode.cloneNode
uElement.__init__
D anode
return
aBeautifulSoupNode
nuElement.appendChild
getAttributes
uElement.getAttributes
a_Html5libAttributeName
a_Html5libAttributes
setAttributes
uElement.setAttributes
T nainsertText
uElement.insertText
D anode
refNode
return
aBeautifulSoupNode
aBeautifulSoupNode
nuElement.insertBefore
removeChild
uElement.removeChild
D anew_parent
return
aElement
nareparentChildren
uElement.reparentChildren
hasContent
uElement.hasContent
uElement.cloneNode
getNameTuple
uElement.getNameTuple
nameTuple
uTextNode.__init__
ubs4\builder\_html5lib.py
u<module bs4.builder._html5lib>
T a__class__
T aself
name
T aself
element
T aself
element
soup
namespace
T aself
element
soup
T aself
namespaceHTMLElements
soup
store_line_numbers
kwargs
aBeautifulSoup
a__class__
T aself
T aself
name
value
list_attr
T aself
node
string_child
child
old_element
new_element
most_recent_element
T aself
node
T aself
tag
node
key
value
T aself
data
T aself
namespaceHTMLElements
T aself
name
namespace
sourceline
sourcepos
tag
T aself
markup
parser
extra_kwargs
doc
original_encoding
T aself
node
refNode
index
old_node
new_str
T aself
token
name
publicId
systemId
doctype
T aself
data
insertBefore
text
T aself
markup
user_specified_encoding
document_declared_encoding
exclude_encodings
variable
name
T aself
new_parent
element
new_parent_element
final_next_element
new_parents_last_descendant
new_parents_last_child
new_parents_last_descendant_next_element
to_append
first_child
last_childs_last_descendant
child
T aself
attributes
name
value
new_name
normalized_attributes
value_or_values
T aself
fragment
a__spec__
.bs4.builder._htmlparser
soup
on_duplicate_attribute
builder
attribute_dict_class
aHTMLParser
a__init__
already_closed_empty_element
a_initialize_xml_detector
aParserRejectedMarkup
handle_starttag
D ahandle_empty_element
Fahandle_endtag
uHandle an incoming empty-element tag.
html.parser only calls this method when the markup looks like
<tag/>.

attr_dict
self
aIGNORE
aREPLACE
cast
a_DuplicateAttributeHandler
store_line_numbers
getpos
T asourceline
sourcepos
is_empty_element
D acheck_already_closed
Faappend
a_root_tag_name
a_root_tag_encountered
uHandle an opening tag, e.g. '<tag>'
:param handle_empty_element: True if this tag is known to be
n empty-element tag (i.e. there is not expected to be any
closing tag).
remove
uHandle a closing tag, e.g. '</tag>'
:param name: A tag name.
:param check_already_closed: True if this tag is expected to
be the closing portion of an empty-element tag,
e.g. '<tag></tag>'.
handle_data
uHandle some textual data that shows up between tags.
startswith
T wxalstrip
l T wXl  aoriginal_encoding
uwindows-1252
decode
data
T EValueError
EOverflowError

uHandle a numeric character reference by converting it to the
corresponding Unicode character and treating it as textual
data.
:param name: Character number, possibly in hexadecimal.
aEntitySubstitution
aHTML_ENTITY_TO_CHARACTER
get
u&%s
uHandle a named entity reference by converting it to the
corresponding Unicode character(s) and treating it as textual
data.
:param name: Name of the entity reference.
endData
aComment
uHandle an HTML comment.
:param data: The text of the comment.
:l nnaDoctype
uHandle a DOCTYPE declaration.
:param data: The text of the declaration.
upper
T uCDATA[
aCData
:l nnaDeclaration
uHandle a declaration of unknown type -- probably a CDATA block.
:param data: The text of the declaration.
a_document_might_be_xml
aProcessingInstruction
uHandle a processing instruction.
:param data: The text of the instruction.
T aon_duplicate_attribute
kwargs
extra_parser_kwargs
aHTMLParserTreeBuilder
update
convert_charrefs
parser_args
uConstructor.
:param parser_args: Positional arguments to pass into
the BeautifulSoupHTMLParser constructor, once it's
invoked.
:param parser_kwargs: Keyword arguments to pass into
the BeautifulSoupHTMLParser constructor, once it's
invoked.
:param kwargs: Keyword arguments for the superclass constructor.
uRun any preliminary steps necessary to make incoming markup
cceptable to the parser.
:param markup: Some markup -- probably a bytestring.
:param user_specified_encoding: The user asked to try this encoding.
:param document_declared_encoding: The markup itself claims to be
in this encoding.
:param exclude_encodings: The user asked _not_ to try any of
these encodings.
:yield: A series of 4-tuples: (markup, encoding, declared encoding,
has undergone character replacement)
Each 4-tuple represents a strategy for parsing the document.
This TreeBuilder uses Unicode, Dammit to convert the markup
into Unicode, so the ``markup`` element of the tuple will
lways be a string.
markup
user_specified_encoding
document_declared_encoding
aUnicodeDammit
exclude_encodings
T aknown_definite_encodings
user_encodings
is_html
exclude_encodings
unicode_markup
T uCould not convert input to Unicode, and html.parser will not accept bytestrings.
declared_html_encoding
contains_replacement_characters
prepare_markup
uHTMLParserTreeBuilder.prepare_markup
aBeautifulSoupHTMLParser
feed
close
uUse the HTMLParser library to parse HTML files that aren't too bad.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aMIT
a__license__
a__all__
uhtml.parser
T aHTMLParser
aAny
aCallable
aDict
aIterable
aList
aOptional
aTYPE_CHECKING
aTuple
aType
aUnion
ubs4.element
T aAttributeDict
aCData
aComment
aDeclaration
aDoctype
aProcessingInstruction
aAttributeDict
ubs4.dammit
T aEntitySubstitution
aUnicodeDammit
ubs4.builder
T aDetectsXMLParsedAsHTML
aHTML
aHTMLTreeBuilder
aSTRICT
aDetectsXMLParsedAsHTML
aHTML
aHTMLTreeBuilder
aSTRICT
ubs4.exceptions
T aParserRejectedMarkup
aHTMLPARSER
T Ostr
pa__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
