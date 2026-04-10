# Reconstructed from integrated Nuitka blob
# Module: ubs4.element

uA namespaced attribute (e.g. the 'xml:lang' in 'xml:lang="en"')
which remembers the namespace prefix ('xml') and the name ('lang')
that were used to create it.
a__qualname__
uOptional[str]
T nnD aprefix
name
namespace
return
uOptional[str]
uOptional[str]
uOptional[str]
aSelf
uNamespacedAttribute.__new__
a__orig_bases__
uAn abstract class standing in for a character encoding specified
inside an HTML ``<meta>`` tag.
Subclasses exist for each place such a character encoding might be
found: either inside the ``charset`` attribute
(`CharsetMetaAttributeValue`) or inside the ``content`` attribute
(`ContentMetaAttributeValue`)
This allows Beautiful Soup to replace that part of the HTML file
with a different encoding when ouputting a tree as a string.
D aeventual_encoding
return
str
puAttributeValueWithCharsetSubstitution.substitute_encoding
aCharsetMetaAttributeValue
uA generic stand-in for the value of a ``<meta>`` tag's ``charset``
ttribute.
When Beautiful Soup parses the markup ``<meta charset="utf8">``, the
value of the ``charset`` attribute will become one of these objects.
If the document is later encoded to an encoding other than UTF-8, its
``<meta>`` tag will mention the new encoding instead of ``utf8``.
D aoriginal_value
return
str
aSelf
uCharsetMetaAttributeValue.__new__
T uutf-8
D aeventual_encoding
return
a_Encoding
str
uCharsetMetaAttributeValue.substitute_encoding
uClass for the list used to hold the values of attributes which
have multiple values (such as HTML's 'class'). It's just a regular
list, but you can subclass it and pass it in to the TreeBuilder
constructor as attribute_value_list_class, to have your subclass
instantiated instead.
aAttributeDict
uSuperclass for the dictionary used to hold a tag's
ttributes. You can use this, but it's just a regular dict with no
special logic.
uA dictionary for holding a Tag's attributes, which processes
incoming values for consistency with the HTML spec.
D akey
value
return
str
aAny
aNone
uXMLAttributeDict.__setitem__
uA dictionary for holding a Tag's attributes, which processes
incoming values for consistency with the HTML spec, which says
'Attribute values are a mixture of text and character
references...'
Basically, this means converting common non-string values into
strings, like XMLAttributeDict, though HTML also has some rules
round boolean attributes that XML doesn't have.
uHTMLAttributeDict.__setitem__
aContentMetaAttributeValue
uA generic stand-in for the value of a ``<meta>`` tag's ``content``
ttribute.
When Beautiful Soup parses the markup:
``<meta http-equiv="content-type" content="text/html; charset=utf8">``
The value of the ``content`` attribute will become one of these objects.
If the document is later encoded to an encoding other than UTF-8, its
``<meta>`` tag will mention the new encoding instead of ``utf8``.
u((^|;)\s*charset=)([^;]*)
wMuContentMetaAttributeValue.__new__
uContentMetaAttributeValue.substitute_encoding
T Oobject
uAn abstract class representing a single element in the parse tree.
`NavigableString`, `Tag`, etc. are all subclasses of
`PageElement`. For this reason you'll see a lot of methods that
return `PageElement`, but you'll never see an actual `PageElement`
object. For the most part you can think of `PageElement` as
meaning "a `Tag` or a `NavigableString`."
uOptional[bool]
bool
uOptional[Tag]
a_AtMostOneElement
T nnnnnD aparent
previous_element
next_element
previous_sibling
next_sibling
return
uOptional[Tag]
a_AtMostOneElement
pppaNone
uPageElement.setup
D wsaformatter
return
str
uOptional[_FormatterOrName]
str
uPageElement.format_string
D aformatter_name
return
uUnion[_FormatterOrName, _EntitySubstitutionFunction]
aFormatter
uPageElement.formatter_for_name
property
D areturn
bool
uPageElement._is_xml
T anextSibling
next_sibling
u4.0.0
nextSibling
T apreviousSibling
previous_sibling
u4.0.0
previousSibling
D amemo
recursive
return
uDict[Any, Any]
bool
aSelf
uPageElement.__deepcopy__
D areturn
aSelf
a__copy__
uPageElement.__copy__
tuple
uIterable[type[NavigableString]]
D astrip
types
return
bool
uIterable[type[NavigableString]]
uIterator[str]
uPageElement._all_strings
D areturn
uIterator[str]
D aseparator
strip
types
return
str
bool
uIterable[Type[NavigableString]]
str
get_text
uPageElement.get_text
getText
D aargs
return
aPageElement
aSelf
uPageElement.replace_with
T areplaceWith
replace_with
u4.0.0
replaceWith
D awrap_inside
return
aTag
pawrap
uPageElement.wrap
T nD a_self_index
return
uOptional[int]
aSelf
uPageElement.extract
D areturn
aNone
uPageElement.decompose
T tpD ais_initialized
accept_self
return
bool
pa_AtMostOneElement
uPageElement._last_descendant
T a_lastRecursiveChild
a_last_descendant
u4.0.0
a_lastRecursiveChild
D aargs
return
a_InsertableElement
uList[PageElement]
insert_before
uPageElement.insert_before
insert_after
uPageElement.insert_after
D aname
attrs
string
kwargs
return
a_FindMethodName
a_StrainableAttributes
uOptional[_StrainableString]
a_StrainableAttribute
a_AtMostOneElement
find_next
uPageElement.find_next
T afindNext
find_next
u4.0.0
findNext
l D aname
attrs
string
limit
a_stacklevel
kwargs
return
a_FindMethodName
a_StrainableAttributes
uOptional[_StrainableString]
uOptional[int]
int
a_StrainableAttribute
a_QueryResults
uPageElement.find_all_next
T afindAllNext
find_all_next
u4.0.0
findAllNext
find_next_sibling
uPageElement.find_next_sibling
T afindNextSibling
find_next_sibling
u4.0.0
findNextSibling
uPageElement.find_next_siblings
T afindNextSiblings
find_next_siblings
u4.0.0
findNextSiblings
T afetchNextSiblings
find_next_siblings
u3.0.0
fetchNextSiblings
find_previous
uPageElement.find_previous
T afindPrevious
find_previous
u3.0.0
findPrevious
uPageElement.find_all_previous
T afindAllPrevious
find_all_previous
u4.0.0
findAllPrevious
T afetchAllPrevious
find_all_previous
u3.0.0
fetchAllPrevious
find_previous_sibling
uPageElement.find_previous_sibling
T afindPreviousSibling
find_previous_sibling
u4.0.0
findPreviousSibling
uPageElement.find_previous_siblings
T afindPreviousSiblings
find_previous_siblings
u4.0.0
findPreviousSiblings
T afetchPreviousSiblings
find_previous_siblings
u3.0.0
fetchPreviousSiblings
D aname
attrs
kwargs
return
a_FindMethodName
a_StrainableAttributes
a_StrainableAttribute
a_AtMostOneElement
find_parent
uPageElement.find_parent
T afindParent
find_parent
u4.0.0
findParent
D aname
attrs
limit
a_stacklevel
kwargs
return
a_FindMethodName
a_StrainableAttributes
uOptional[int]
int
a_StrainableAttribute
a_QueryResults
uPageElement.find_parents
T afindParents
find_parents
u4.0.0
findParents
T afetchParents
find_parents
u3.0.0
fetchParents
D areturn
a_AtMostOneElement
anext
uPageElement.next
previous
uPageElement.previous
D amethod
name
attrs
string
kwargs
return
aCallable
a_FindMethodName
a_StrainableAttributes
uOptional[_StrainableString]
a_StrainableAttribute
a_AtMostOneElement
uPageElement._find_one
T l D aname
attrs
string
limit
generator
a_stacklevel
kwargs
return
a_FindMethodName
a_StrainableAttributes
uOptional[_StrainableString]
uOptional[int]
uIterator[PageElement]
int
a_StrainableAttribute
a_QueryResults
uPageElement._find_all
D areturn
uIterator[PageElement]
self_and_next_elements
uPageElement.self_and_next_elements
self_and_next_siblings
uPageElement.self_and_next_siblings
self_and_previous_elements
uPageElement.self_and_previous_elements
self_and_previous_siblings
uPageElement.self_and_previous_siblings
D areturn
uIterator[Tag]
self_and_parents
uPageElement.self_and_parents
D aother_generator
return
uIterator[PageElement]
uIterator[PageElement]
decomposed
uPageElement.decomposed
T anext_elements
u4.0.0
nextGenerator
uPageElement.nextGenerator
T anext_siblings
u4.0.0
nextSiblingGenerator
uPageElement.nextSiblingGenerator
T aprevious_elements
u4.0.0
previousGenerator
uPageElement.previousGenerator
T aprevious_siblings
u4.0.0
previousSiblingGenerator
uPageElement.previousSiblingGenerator
T aparents
u4.0.0
parentGenerator
uPageElement.parentGenerator
uA Python string that is part of a parse tree.
When Beautiful Soup parses the markup ``<b>penguin</b>``, it will
create a `NavigableString` for the string "penguin".
D avalue
return
uUnion[str, bytes]
aSelf
uNavigableString.__new__
uNavigableString.__deepcopy__
D areturn
uTuple[str]
a__getnewargs__
uNavigableString.__getnewargs__
D areturn
str
uNavigableString.string
T aminimal
D aformatter
return
a_FormatterOrName
str
uNavigableString.output_ready
uSince a NavigableString is not a Tag, it has no .name.
This property is implemented so that code like this doesn't crash
when run on a mixture of Tag and NavigableString objects:
[x.name for x in tag.children]
:meta private:
uNavigableString.name
setter
D aname
return
str
aNone
D astrip
types
return
bool
a_OneOrMoreStringTypes
uIterator[str]
strings
uNavigableString.strings
uA `NavigableString` not subject to the normal formatting rules.
This is an abstract class used for special kinds of strings such
s comments (`Comment`) and CDATA blocks (`CData`).
D aformatter
return
uOptional[_FormatterOrName]
str
uPreformattedString.output_ready
aCData
uA `CDATA section <https://dev.w3.org/html5/spec-LC/syntax.html#cdata-sections>`_.
u<![CDATA[
u]]>
aProcessingInstruction
uA SGML processing instruction.
u<?
aXMLProcessingInstruction
uAn `XML processing instruction <https://www.w3.org/TR/REC-xml/#sec-pi>`_.
u?>
aComment
uAn `HTML comment <https://dev.w3.org/html5/spec-LC/syntax.html#comments>`_ or `XML comment <https://www.w3.org/TR/REC-xml/#sec-comments>`_.
u<!--
u-->
aDeclaration
uAn `XML declaration <https://www.w3.org/TR/REC-xml/#sec-prolog-dtd>`_.
uA `document type declaration <https://www.w3.org/TR/REC-xml/#dt-doctype>`_.
classmethod
D aname
pub_id
system_id
return
str
uOptional[str]
uOptional[str]
aDoctype
for_name_and_ids
uDoctype.for_name_and_ids
D aname
pub_id
system_id
return
str
uOptional[str]
uOptional[str]
str
uDoctype._string_for_name_and_ids
u<!DOCTYPE
u>
aStylesheet
uA `NavigableString` representing the contents of a `<style> HTML
tag <https://dev.w3.org/html5/spec-LC/Overview.html#the-style-element>`_
(probably CSS).
Used to distinguish embedded stylesheets from textual content.
aScript
uA `NavigableString` representing the contents of a `<script>
HTML tag
<https://dev.w3.org/html5/spec-LC/Overview.html#the-script-element>`_
(probably Javascript).
Used to distinguish executable code from textual content.
aTemplateString
uA `NavigableString` representing a string found inside an `HTML
<template> tag <https://html.spec.whatwg.org/multipage/scripting.html#the-template-element>`_
embedded in a larger document.
Used to distinguish such strings from the main body of the document.
aRubyTextString
uA NavigableString representing the contents of an `<rt> HTML
tag <https://dev.w3.org/html5/spec-LC/text-level-semantics.html#the-rt-element>`_.
Can be used to distinguish such strings from the strings they're
nnotating.
aRubyParenthesisString
uA NavigableString representing the contents of an `<rp> HTML
tag <https://dev.w3.org/html5/spec-LC/text-level-semantics.html#the-rp-element>`_.
uAn HTML or XML tag that is part of a parse tree, along with its
ttributes, contents, and relationships to other parts of the tree.
When Beautiful Soup parses the markup ``<b>penguin</b>``, it will
create a `Tag` object representing the ``<b>`` tag. You can
instantiate `Tag` objects directly, but it's not necessary unless
you're adding entirely new markup to a parsed document. Most of
the constructor arguments are intended for use by the `TreeBuilder`
that's parsing a document.
:param parser: A `BeautifulSoup` object representing the parse tree this
`Tag` will be part of.
:param builder: The `TreeBuilder` being used to build the tree.
:param name: The name of the tag.
:param namespace: The URI of this tag's XML namespace, if any.
:param prefix: The prefix for this tag's XML namespace, if any.
:param attrs: A dictionary of attribute values.
:param parent: The `Tag` to use as the parent of this `Tag`. May be
the `BeautifulSoup` object itself.
:param previous: The `PageElement` that was parsed immediately before
parsing this tag.
:param is_xml: If True, this is an XML tag. Otherwise, this is an
HTML tag.
:param sourceline: The line number where this tag was found in its
source document.
:param sourcepos: The character position within ``sourceline`` where this
tag was found.
:param can_be_empty_element: If True, this tag should be
represented as <tag/>. If False, this tag should be represented
s <tag></tag>.
:param cdata_list_attributes: A dictionary of attributes whose values should
be parsed as lists of strings if they ever show up on this tag.
:param preserve_whitespace_tags: Names of tags whose contents
should have their whitespace preserved if they are encountered inside
this tag.
:param interesting_string_types: When iterating over this tag's
string contents in methods like `Tag.strings` or
`PageElement.get_text`, these are the types of strings that are
interesting enough to be considered. By default,
`NavigableString` (normal strings) and `CData` (CDATA
sections) are the only interesting string subtypes.
:param namespaces: A dictionary mapping currently active
namespace prefixes to URIs, as of the point in the parsing process when
this tag was encountered. This can be used later to
construct CSS selectors.
T nnnnnnnnnnnnnnnnD aparser
builder
name
namespace
prefix
attrs
parent
previous
is_xml
sourceline
sourcepos
can_be_empty_element
cdata_list_attributes
preserve_whitespace_tags
interesting_string_types
namespaces
uOptional[BeautifulSoup]
uOptional[TreeBuilder]
uOptional[str]
uOptional[str]
uOptional[str]
uOptional[_RawOrProcessedAttributeValues]
uOptional[Union[BeautifulSoup, Tag]]
a_AtMostOneElement
uOptional[bool]
uOptional[int]
uOptional[int]
uOptional[bool]
uOptional[Dict[str, Set[str]]]
uOptional[Set[str]]
uOptional[Set[Type[NavigableString]]]
uOptional[Dict[str, str]]
uTag.__init__
uOptional[type[BeautifulSoup]]
a_AttributeValues
uOptional[int]
uList[PageElement]
uOptional[Set[Type[NavigableString]]]
uOptional[Dict[str, Set[str]]]
uOptional[Set[str]]
T aparserClass
parser_class
u4.0.0
parserClass
uTag.__deepcopy__
uTag.copy_self
uTag.is_empty_element
T ais_empty_element
u4.0.0
isSelfClosing
uTag.isSelfClosing
D areturn
uOptional[str]
uTag.string
D astring
return
str
aNone
D aposition
new_children
return
int
a_InsertableElement
uList[PageElement]
uTag.insert
D aposition
new_child
return
int
a_InsertableElement
uList[PageElement]
uTag._insert
uTag.unwrap
replace_with_children
T aunwrap
u4.0.0
D areturn
a_OneElement
replaceWithChildren
uTag.replaceWithChildren
D atag
return
a_InsertableElement
aPageElement
uTag.append
D atags
return
uUnion[Iterable[_InsertableElement], Tag]
uList[PageElement]
extend
uTag.extend
D adecompose
return
bool
aNone
uTag.clear
uTag.smooth
D aelement
return
aPageElement
int
uTag.index
D akey
default
return
str
uOptional[_AttributeValue]
uOptional[_AttributeValue]
uTag.get
D akey
default
return
str
uOptional[AttributeValueList]
aAttributeValueList
get_attribute_list
uTag.get_attribute_list
D akey
return
str
bool
uTag.has_attr
D areturn
int
uTag.__hash__
D akey
return
str
a_AttributeValue
uTag.__getitem__
a__iter__
uTag.__iter__
a__len__
uTag.__len__
D wxareturn
aAny
bool
a__contains__
uTag.__contains__
uA tag is non-None even if it has no contents.
a__bool__
uTag.__bool__
D akey
value
return
str
a_AttributeValue
aNone
uTag.__setitem__
D akey
return
str
aNone
a__delitem__
uTag.__delitem__
D aname
attrs
recursive
string
limit
a_stacklevel
kwargs
return
uOptional[_StrainableElement]
a_StrainableAttributes
bool
uOptional[_StrainableString]
uOptional[int]
int
a_StrainableAttribute
a_QueryResults
a__call__
uTag.__call__
D asubtag
return
str
uOptional[Tag]
uTag.__getattr__
D aother
return
aAny
bool
a__eq__
uTag.__eq__
a__ne__
uTag.__ne__
a__repr__
uTag.__repr__
a__str__
a__unicode__
minimal
xmlcharrefreplace
D aencoding
indent_level
formatter
errors
return
a_Encoding
uOptional[int]
a_FormatterOrName
str
bytes
uTag.encode
D aindent_level
eventual_encoding
formatter
iterator
return
uOptional[int]
a_Encoding
a_FormatterOrName
uOptional[Iterator[PageElement]]
str
uTag.decode
object
a_TreeTraversalEvent
uAn internal class representing an event in the process
of traversing a parse tree.
:meta private:
uTag._TreeTraversalEvent
D aiterator
return
uOptional[Iterator[PageElement]]
uIterator[Tuple[_TreeTraversalEvent, PageElement]]
D wsaindent_level
formatter
indent_before
indent_after
return
str
int
aFormatter
bool
pastr
uTag._indent_string
D aeventual_encoding
formatter
opening
return
str
aFormatter
bool
str
uTag._format_tag
D aindent_level
return
int
bool
uTag._should_pretty_print
T naminimal
D aencoding
formatter
return
uOptional[_Encoding]
a_FormatterOrName
uUnion[str, bytes]
prettify
uTag.prettify
D aindent_level
eventual_encoding
formatter
return
uOptional[int]
a_Encoding
a_FormatterOrName
str
uTag.decode_contents
D aindent_level
encoding
formatter
return
uOptional[int]
a_Encoding
a_FormatterOrName
bytes
uTag.encode_contents
T aencode_contents
u4.0.0
D aencoding
prettyPrint
indentLevel
return
a_Encoding
bool
uOptional[int]
bytes
renderContents
uTag.renderContents
D aname
attrs
recursive
string
kwargs
return
a_FindMethodName
a_StrainableAttributes
bool
uOptional[_StrainableString]
a_StrainableAttribute
a_AtMostOneElement
uTag.find
T afindChild
find
u3.0.0
findChild
D aname
attrs
recursive
string
limit
a_stacklevel
kwargs
return
a_FindMethodName
a_StrainableAttributes
bool
uOptional[_StrainableString]
uOptional[int]
int
a_StrainableAttribute
a_QueryResults
uTag.find_all
T afindAll
find_all
u4.0.0
findAll
T afindChildren
find_all
u3.0.0
findChildren
uTag.children
uTag.self_and_descendants
D aselector
namespaces
kwargs
return
str
uOptional[Dict[str, str]]
aAny
uOptional[Tag]
uTag.select_one
T nl
D aselector
namespaces
limit
kwargs
return
str
uOptional[Dict[str, str]]
int
aAny
uResultSet[Tag]
uTag.select
D areturn
aCSS
uTag.css
T achildren
u4.0.0
childGenerator
uTag.childGenerator
T adescendants
u4.0.0
recursiveChildGenerator
uTag.recursiveChildGenerator
T ahas_attr
u4.0.0
has_key
uTag.has_key
T a_PageElementT
T abound
a_PageElementT
uA ResultSet is a list of `PageElement` objects, gathered as the result
of matching an :py:class:`ElementFilter` against a parse tree. Basically, a list of
search results.
uOptional[ElementFilter]
T T
D asource
result
return
uOptional[ElementFilter]
uIterable[_PageElementT]
aNone
uResultSet.__init__
uResultSet.__getattr__
T aSoupStrainer
ubs4\element.py
T a.0
element
T a.0
wxaself
T a.0
wxu<module bs4.element>
T a__class__
T aself
T aself
name
attrs
recursive
string
limit
a_stacklevel
kwargs
T aself
wxT aself
memo
recursive
T aself
memo
recursive
tag_stack
clone
event
element
descendant_clone
T aself
key
T aself
other
wiamy_child
T aself
subtag
result
tag_name
T aname
message
T aself
source
result
a__class__
T aself
parser
builder
name
namespace
prefix
attrs
parent
previous
is_xml
sourceline
sourcepos
can_be_empty_element
cdata_list_attributes
preserve_whitespace_tags
interesting_string_types
namespaces
attr_dict_class
attribute_value_list_class
wkwvT aself
other
T acls
original_value
obj
T acls
prefix
name
namespace
obj
T acls
value
wuT aself
key
value
a__class__
T aself
key
value
T aself
strip
types
my_type
value
final_value
T aself
strip
types
T aself
strip
types
descendant
descendant_type
stripped
T aself
iterator
tag_stack
wcanow_closed_tag
T aself
name
attrs
string
limit
generator
a_stacklevel
kwargs
result
aElementFilter
matcher
prefix
local_name
element
T aself
method
name
attrs
string
kwargs
wraresults
T aself
eventual_encoding
formatter
opening
closing_slash
prefix
attribute_string
attributes
attrs
key
val
decoded
text
void_element_closing_slash
T aself
wsaindent_level
formatter
indent_before
indent_after
space_before
space_after
T
self
position
new_child
parent
aBeautifulSoup
current_index
previous_child
new_childs_last_element
parents_next_sibling
next_child
T aself
is_initialized
accept_self
last_child
T aself
other_generator
wiT aself
indent_level
T aself
name
pub_id
system_id
value
T aself
tag
T aself
decompose
element
T aself
clone
attr
T aself
indent_level
eventual_encoding
formatter
iterator
pieces
string_literal_tag
event
element
piece
indent_before
indent_after
T aself
indent_level
eventual_encoding
formatter
T aself
weanext_up
T aself
current
last_descendant
stopNode
successor
T aself
encoding
indent_level
formatter
errors
wuT aself
indent_level
encoding
formatter
contents
T aself
tags
tag_list
results
tag
T aself
a_self_index
last_child
next_element
T aself
name
attrs
recursive
string
kwargs
wraresults
T	aself
name
attrs
recursive
string
limit
a_stacklevel
kwargs
generator
T aself
name
attrs
string
limit
a_stacklevel
kwargs
T aself
name
attrs
string
kwargs
T aself
name
attrs
kwargs
wraresults
T aself
name
attrs
limit
a_stacklevel
kwargs
iterator
T acls
name
pub_id
system_id
T aself
wsaformatter
output
T aself
formatter_name
wcaregistry
T aself
key
default
T aself
key
default
list_value
value
T aself
separator
strip
types
T aself
element
wiachild
T aself
position
new_children
inserted
new_child
T aself
args
results
parent
offset
successor
index
T aself
args
results
parent
predecessor
index
T aself
name
T aself
wiasuccessor
T aself
formatter
output
T aself
formatter
T aself
encoding
formatter
T aself
encoding
prettyPrint
indentLevel
T aself
args
old_parent
my_index
idx
replace_with
T amatch
eventual_encoding
T aeventual_encoding
T aself
selector
namespaces
limit
kwargs
T aself
selector
namespaces
kwargs
T aself
parent
previous_element
next_element
previous_sibling
next_sibling
T aself
marked
wiwawbwnT aself
child
T aself
string
new_class
T aself
string
T aself
eventual_encoding
T aself
eventual_encoding
rewrite
T aself
my_parent
my_index
child
T aself
wrap_inside
me
a__spec__
.bs4.exceptions
%
u%s: %s
a__name__
aParserRejectedMarkup
a__init__
uExplain why the parser rejected the given markup, either
with a textual explanation or another exception.
uExceptions defined by Beautiful Soup itself.
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
T EException
a__prepare__
aStopParsing
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
