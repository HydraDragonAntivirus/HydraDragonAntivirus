# Reconstructed from integrated Nuitka blob
# Module: ubs4.dammit

uThe ability to substitute XML or HTML entities for certain characters.
a__qualname__
str
classmethod
D areturn
na_populate_class_variables
uEntitySubstitution._populate_class_variables
D w'w"w&w<w>aapos
quot
amp
lt
gt
u&(#\d+|#x[0-9a-fA-F]+|\w+);
T u([<>]|&(?!#\d+;|#x[0-9a-fA-F]+;|\w+;))
T u([<>&])
matchobj
aMatch
uEntitySubstitution._substitute_html_entity
uEntitySubstitution._substitute_xml_entity
uEntitySubstitution._escape_entity_name
uEntitySubstitution._escape_unrecognized_entity_name
value
uEntitySubstitution.quoted_attribute_value
T Famake_quoted_attribute
bool
substitute_xml
uEntitySubstitution.substitute_xml
substitute_xml_containing_entities
uEntitySubstitution.substitute_xml_containing_entities
substitute_html
uEntitySubstitution.substitute_html
substitute_html5
uEntitySubstitution.substitute_html5
substitute_html5_raw
uEntitySubstitution.substitute_html5_raw
a__orig_bases__
uThis class is capable of guessing a number of possible encodings
for a bytestring.
Order of precedence:
1. Encodings you specifically tell EncodingDetector to try first
(the ``known_definite_encodings`` argument to the constructor).
2. An encoding determined by sniffing the document's byte-order mark.
3. Encodings you specifically tell EncodingDetector to try if
byte-order mark sniffing fails (the ``user_encodings`` argument to the
constructor).
4. An encoding declared within the bytestring itself, either in an
XML declaration (if the bytestring is to be interpreted as an XML
document), or in a <meta> tag (if the bytestring is to be
interpreted as an HTML document.)
5. An encoding detected through textual analysis by chardet,
cchardet, or a similar external library.
6. UTF-8.
7. Windows-1252.
:param markup: Some markup in an unknown encoding.
:param known_definite_encodings: When determining the encoding
of ``markup``, these encodings will be tried first, in
order. In HTML terms, this corresponds to the "known
definite encoding" step defined in `section 13.2.3.1 of the HTML standard <https://html.spec.whatwg.org/multipage/parsing.html#parsing-with-a-known-character-encoding>`_.
:param user_encodings: These encodings will be tried after the
``known_definite_encodings`` have been tried and failed, and
fter an attempt to sniff the encoding by looking at a
byte order mark has failed. In HTML terms, this
corresponds to the step "user has explicitly instructed
the user agent to override the document's character
encoding", defined in `section 13.2.3.2 of the HTML standard <https://html.spec.whatwg.org/multipage/parsing.html#determining-the-character-encoding>`_.
:param override_encodings: A **deprecated** alias for
``known_definite_encodings``. Any encodings here will be tried
immediately after the encodings in
``known_definite_encodings``.
:param is_html: If True, this markup is considered to be
HTML. Otherwise it's assumed to be XML.
:param exclude_encodings: These encodings will not be tried,
even if they otherwise would be.
T nFnnnaoverride_encodings
a__init__
uEncodingDetector.__init__
uEncodingDetector._usable
uEncodingDetector.strip_byte_order_mark
T FpT Obytes
Ostr
search_entire_document
uEncodingDetector.find_declared_encoding
uA class for detecting the encoding of a bytestring containing an
HTML or XML document, and decoding it to Unicode. If the source
encoding is windows-1252, `UnicodeDammit` can also replace
Microsoft smart quotes with their HTML or XML equivalents.
:param markup: HTML or XML markup in an unknown encoding.
:param known_definite_encodings: When determining the encoding
of ``markup``, these encodings will be tried first, in
order. In HTML terms, this corresponds to the "known
definite encoding" step defined in `section 13.2.3.1 of the HTML standard <https://html.spec.whatwg.org/multipage/parsing.html#parsing-with-a-known-character-encoding>`_.
:param user_encodings: These encodings will be tried after the
``known_definite_encodings`` have been tried and failed, and
fter an attempt to sniff the encoding by looking at a
byte order mark has failed. In HTML terms, this
corresponds to the step "user has explicitly instructed
the user agent to override the document's character
encoding", defined in `section 13.2.3.2 of the HTML standard <https://html.spec.whatwg.org/multipage/parsing.html#determining-the-character-encoding>`_.
:param override_encodings: A **deprecated** alias for
``known_definite_encodings``. Any encodings here will be tried
immediately after the encodings in
``known_definite_encodings``.
:param smart_quotes_to: By default, Microsoft smart quotes will,
like all other characters, be converted to Unicode
characters. Setting this to ``ascii`` will convert them to ASCII
quotes instead.  Setting it to ``xml`` will convert them to XML
entity references, and setting it to ``html`` will convert them
to HTML entity references.
:param is_html: If True, ``markup`` is treated as an HTML
document. Otherwise it's treated as an XML document.
:param exclude_encodings: These encodings will not be considered,
even if the sniffing code thinks they might make sense.
aUnicodeDammit
T aascii
xml
html
uUnicodeDammit.__init__
match
uUnicodeDammit._sub_ms_char
D amacintosh
ux-sjis
umac-roman
ushift-jis
uwindows-1252
uiso-8859-1
uiso-8859-2
T astrict
proposed
errors
uUnicodeDammit._convert_from
uUnicodeDammit._to_unicode
declared_html_encoding
uUnicodeDammit.declared_html_encoding
charset
uUnicodeDammit.find_codec
uUnicodeDammit._codec
D d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d T aeuro
u20AC
w T asbquo
u201A
T afnof
u192
T abdquo
u201E
T ahellip
u2026
T adagger
u2020
T aDagger
u2021
T acirc
u2C6
T apermil
u2030
T aScaron
u160
T alsaquo
u2039
T aOElig
u152
w?T u#x17D
u17D
w?pT alsquo
u2018
T arsquo
u2019
T aldquo
u201C
T ardquo
u201D
T abull
u2022
T andash
u2013
T amdash
u2014
T atilde
u2DC
T atrade
u2122
T ascaron
u161
T arsaquo
u203A
T aoelig
u153
w?T u#x17E
u17E
T aYuml

T Ostr
pD  d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d d aEUR
w w,wfu,,
u...
w+u++
w^w%wSw<aOE
w?wZw?pw'pw"pw*w-u--
w~u(TM)
wsw>aoe
w?wzwYw w!wcaGBP
w$aYEN
w|wSu..

u(th)
u<<
w!w u(R)
w-wou+-
w2w3w'wuwPw*w,w1u(th)
u>>
u1/4
u1/2
u3/4
w?wApppppaAE
wCwEpppwIpppwDwNwOppppw*wOwUpppwYwbwBwapppppaae
wcwepppwipppwownwoppppw/wowupppwywbwyDzl  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
d c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
c
T Oint
Obytes
T l  l  l T l  l  l T l  l  l T Oint
ppT autf8
uwindows-1252
in_bytes
main_encoding
embedded_encoding
detwingle
uUnicodeDammit.detwingle
ubs4\dammit.py
T a.0
wxu<module bs4.dammit>
T a__class__
T aself
markup
known_definite_encodings
is_html
exclude_encodings
user_encodings
override_encodings
T
self
markup
known_definite_encodings
smart_quotes_to
is_html
exclude_encodings
user_encodings
override_encodings
wuaencoding
T wsamodule
T aself
charset
codec
T aself
proposed
errors
lookup_result
markup
smart_quotes_re
smart_quotes_compiled
wuT acls
matchobj
T acls
matchobj
possible_entity
T acls
unicode_to_name
name_to_unicode
short_entities
long_entities_by_first_character
name_with_semicolon
character
name
particles
short
long_versions
ignore
long_entities
long_entity
re_definition
re_definition_with_ampersand
codepoint
T aself
match
orig
sub
substitutions
T acls
matchobj
original_entity
entity
T acls
matchobj
entity
T aself
data
encoding
errors
T aself
encoding
tried
T aself
T acls
in_bytes
main_encoding
embedded_encoding
byte_chunks
chunk_start
pos
byte
start
end
size
T aself
tried
weT aself
charset
value
T acls
markup
is_html
search_entire_document
declared_encoding
xml_endpos
html_endpos
res
xml_re
html_re
declared_encoding_match
T acls
value
quote_with
replace_with
T acls
data
encoding
T acls
wsT acls
value
make_quoted_attribute
a__spec__
.bs4.element
'
a_deprecated_names
warnings
warn
format
T aname
aDeprecationWarning
D astacklevel
l a_deprecated_

umodule 'bs4.element' has no attribute
a__new__
w:aprefix
name
namespace
uDo whatever's necessary in this implementation-specific
portion an HTML document to substitute in a specific encoding.
original_value
aPYTHON_SPECIFIC_ENCODINGS
uWhen an HTML document is being encoded to a given encoding, the
value of a ``<meta>`` tag's ``charset`` becomes the name of
the encoding.
T Oint
Ofloat
a__class__
a__setitem__
uSet an attribute value, possibly modifying it to comply with
the XML spec.
This just means converting common non-string values to
strings: XML attributes may have "any literal string as a
value."
T FnaNamespacedAttribute
key
uSet an attribute value, possibly modifying it to comply
with the HTML spec,
aCHARSET_RE
search
sub
D amatch
return
ure.Match[str]
str
rewrite
uContentMetaAttributeValue.substitute_encoding.<locals>.rewrite
uWhen an HTML document is being encoded to a given encoding, the
value of the ``charset=`` in a ``<meta>`` tag's ``content`` becomes
the name of the encoding.
group
T l aeventual_encoding
parent
previous_element
next_element
next_sibling
previous_sibling
contents
uSets up the initial relations between this element and
other elements.
:param parent: The parent of this element.
:param previous_element: The element parsed immediately before
this one.
:param next_element: The element parsed immediately before
this one.
:param previous_sibling: The most recently encountered element
on the same level of the parse tree as this one.
:param previous_sibling: The next element to be encountered
on the same level of the parse tree as this one.
aFormatter
formatter_for_name
substitute
uFormat the given string using the given formatter.
:param s: A string.
:param formatter: A Formatter object, or a string naming one of the standard formatters.
a_is_xml
aXMLFormatter
aREGISTRY
aHTMLFormatter
callable
T aentity_substitution
uLook up or create a Formatter for the given identifier,
if necessary.
:param formatter: Can be a `Formatter` object (used as-is), a
function (used as the entity substitution hook for an
`bs4.formatter.XMLFormatter` or
`bs4.formatter.HTMLFormatter`), or a string (used to look
up an `bs4.formatter.XMLFormatter` or
`bs4.formatter.HTMLFormatter` in the appropriate registry.
known_xml
is_xml
uIs this element part of an XML tree or an HTML tree?
This is used in formatter_for_name, when deciding whether an
XMLFormatter or HTMLFormatter is more appropriate. It can be
inefficient, but it should be called very rarely.
a__deepcopy__
uA copy of a PageElement can only be a deep copy, because
only one PageElement can occupy a given place in a parse tree.
uYield all strings of certain classes, possibly stripping them.
This is implemented differently in `Tag` and `NavigableString`.
uYield all interesting strings in this PageElement, stripping them
first.
See `Tag` for information on which strings are considered
interesting in a given context.
self
a_all_strings
T tastripped_strings
uPageElement.stripped_strings
join
T atypes
uGet all child strings of this PageElement, concatenated using the
given separator.
:param separator: Strings will be concatenated using this separator.
:param strip: If True, strings will be stripped before being
concatenated.
:param types: A tuple of NavigableString subclasses. Any
strings of a subclass not found in this list will be
ignored. Although there are exceptions, the default
behavior in most cases is to consider only NavigableString
nd CData objects. That means no comments, processing
instructions, etc.
:return: A string.
uCannot replace one element with another when the element to be replaced is not part of a tree.
uCannot replace a Tag with its parent.
index
extract
T a_self_index
T astart
old_parent
insert
uReplace this `PageElement` with one or more other `PageElement`,
objects, keeping the rest of the tree the same.
:return: This `PageElement`, no longer part of the tree.
u<genexpr>
uPageElement.replace_with.<locals>.<genexpr>
replace_with
append
uWrap this `PageElement` inside a `Tag`.
:return: ``wrap_inside``, occupying the position in the tree that used
to be occupied by this object, and with this object now inside it.
a_last_descendant
cast
aPageElement
uDestructively rips this element out of the tree.
:param _self_index: The location of this element in its parent's
.contents, if known. Passing this in allows for a performance
optimization.
:return: this `PageElement`, no longer part of the tree.
weaclear
aTag
a_decomposed
uRecursively destroys this `PageElement` and its children.
The element will be removed from the tree and wiped out; so
will everything beneath it.
The behavior of a decomposed `PageElement` is undefined and you
should never use one for anything, but if you need to *check*
whether an element has been decomposed, you can use the
`PageElement.decomposed` property.
last_child
uFinds the last element beneath this object to be parsed.
Special note to help you figure things out if your type
checking is tripped up by the fact that this method returns
_AtMostOneElement instead of PageElement: the only time
this method returns None is if `accept_self` is False and the
`PageElement` has no children--either it's a NavigableString
or an empty Tag.
:param is_initialized: Has `PageElement.setup` been called on
this `PageElement` yet?
:param accept_self: Is ``self`` an acceptable answer to the
question?
uElement has no parent, so 'before' has no meaning.
uCan't insert an element before itself.
results
uMakes the given element(s) the immediate predecessor of this one.
All the elements will have the same `PageElement.parent` as
this one, and the given elements will occur immediately before
this one.
:param args: One or more PageElements.
:return The list of PageElements that were inserted.
uPageElement.insert_before.<locals>.<genexpr>
uElement has no parent, so 'after' has no meaning.
uCan't insert an element after itself.
offset
uMakes the given element(s) the immediate successor of this one.
The elements will have the same `PageElement.parent` as this
one, and the given elements will occur immediately after this
one.
:param args: One or more PageElements.
:return The list of PageElements that were inserted.
uPageElement.insert_after.<locals>.<genexpr>
a_find_one
find_all_next
uFind the first PageElement that matches the given criteria and
ppears later in the document than this PageElement.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a NavigableString with specific text.
:kwargs: Additional filters on attribute values.
a_find_all
next_elements
a_stacklevel
uFind all `PageElement` objects that match the given criteria and
ppear later in the document than this `PageElement`.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a NavigableString with specific text.
:param limit: Stop looking after finding this many results.
:param _stacklevel: Used internally to improve warning messages.
:kwargs: Additional filters on attribute values.
find_next_siblings
uFind the closest sibling to this PageElement that matches the
given criteria and appears later in the document.
All find_* methods take a common set of arguments. See the
online documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a `NavigableString` with specific text.
:kwargs: Additional filters on attribute values.
next_siblings
uFind all siblings of this `PageElement` that match the given criteria
nd appear later in the document.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a `NavigableString` with specific text.
:param limit: Stop looking after finding this many results.
:param _stacklevel: Used internally to improve warning messages.
:kwargs: Additional filters on attribute values.
find_all_previous
uLook backwards in the document from this `PageElement` and find the
first `PageElement` that matches the given criteria.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a `NavigableString` with specific text.
:kwargs: Additional filters on attribute values.
previous_elements
uLook backwards in the document from this `PageElement` and find all
`PageElement` that match the given criteria.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a `NavigableString` with specific text.
:param limit: Stop looking after finding this many results.
:param _stacklevel: Used internally to improve warning messages.
:kwargs: Additional filters on attribute values.
find_previous_siblings
uReturns the closest sibling to this `PageElement` that matches the
given criteria and appears earlier in the document.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a `NavigableString` with specific text.
:kwargs: Additional filters on attribute values.
previous_siblings
uReturns all siblings to this PageElement that match the
given criteria and appear earlier in the document.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param string: A filter for a NavigableString with specific text.
:param limit: Stop looking after finding this many results.
:param _stacklevel: Used internally to improve warning messages.
:kwargs: Additional filters on attribute values.
find_parents
D a_stacklevel
l uFind the closest parent of this PageElement that matches the given
criteria.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param self: Whether the PageElement itself should be considered
s one of its 'parents'.
:kwargs: Additional filters on attribute values.
parents
uFind all parents of this `PageElement` that match the given criteria.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param limit: Stop looking after finding this many results.
:param _stacklevel: Used internally to improve warning messages.
:kwargs: Additional filters on attribute values.
uThe `PageElement`, if any, that was parsed just after this one.
uThe `PageElement`, if any, that was parsed just before this one.
D a_stacklevel
l atext
uThe 'text' argument to find()-type methods is deprecated. Use 'string' instead.
T astacklevel
a_class
aAttributeResemblesVariableWarning
aMESSAGE
D aoriginal
autocorrect
a_class
class_
ubs4.filter
T aElementFilter
aElementFilter
aSoupStrainer
aResultSet
count
T w:asplit
T w:l aresult
find_all
uIterates over a generator looking for things that match.
uPageElement._find_all.<locals>.<genexpr>
uAll PageElements that were parsed after this one.
wiuPageElement.next_elements
a_self_and
uThis PageElement, then all PageElements that were parsed after it.
uAll PageElements that are siblings of this one but were parsed
later.
uPageElement.next_siblings
uThis PageElement, then all of its siblings.
uAll PageElements that were parsed before this one.
:yield: A sequence of PageElements.
uPageElement.previous_elements
uThis PageElement, then all elements that were parsed
earlier.
uAll PageElements that are siblings of this one but were parsed
earlier.
:yield: A sequence of PageElements.
uPageElement.previous_siblings
uThis PageElement, then all of its siblings that were parsed
earlier.
uAll elements that are parents of this PageElement.
:yield: A sequence of Tags, ending with a BeautifulSoup object.
uPageElement.parents
uThis element, then all of its parents.
:yield: A sequence of PageElements, ending with a BeautifulSoup object.
uModify a generator by yielding this element, then everything
yielded by the other generator.
hidden
other_generator
uPageElement._self_and
uCheck whether a PageElement has been decomposed.
u:meta private:
aDEFAULT_OUTPUT_ENCODING
setup
uCreate a new NavigableString.
When unpickling a NavigableString, this method is called with
the string in DEFAULT_OUTPUT_ENCODING. That encoding needs to be
passed in to the superclass's __new__ or the superclass won't know
how to handle non-ASCII characters.
uA copy of a NavigableString has the same contents and class
s the original, but it is not connected to the parse tree.
:param recursive: This parameter is ignored; it's only defined
so that NavigableString.__deepcopy__ implements the same
signature as Tag.__deepcopy__.
uConvenience property defined to match `Tag.string`.
:return: This property always returns the `NavigableString` it was
called on.
:meta private:
format_string
aPREFIX
aSUFFIX
uRun the string through the provided formatter, making it
ready for output as part of an HTML or XML document.
:param formatter: A `Formatter` object, or a string naming one
of the standard formatters.
uA NavigableString cannot be given a name.
uPrevent NavigableString.name from ever being set.
:meta private:
uYield all strings of certain classes, possibly stripping them.
This makes it easy for NavigableString to implement methods
like get_text() as conveniences, creating a consistent
text-extraction API across all PageElements.
:param strip: If True, all strings will be stripped before being
yielded.
:param types: A tuple of NavigableString subclasses. If this
NavigableString isn't one of those subclasses, the
sequence will be empty. By default, the subclasses
considered are NavigableString and CData objects. That
means no comments, processing instructions, etc.
:yield: A sequence that either contains this string, or is empty.
types
default
aMAIN_CONTENT_STRING_TYPES
strip
uNavigableString._all_strings
uYield this string, but only if it is interesting.
This is defined the way it is for compatibility with
`Tag.strings`. See `Tag` for information on which strings are
interesting in a given context.
:yield: A sequence that either contains this string, or is empty.
uMake this string ready for output by adding any subclass-specific
prefix or suffix.
:param formatter: A `Formatter` object, or a string naming one
of the standard formatters. The string will be passed into the
`Formatter`, but only to trigger any side effects: the return
value is ignored.
:return: The string, with any subclass-specific prefix and
suffix added on.
aDoctype
a_string_for_name_and_ids
uGenerate an appropriate document type declaration for a given
public ID and system ID.
:param name: The name of the document's root element, e.g. 'html'.
:param pub_id: The Formal Public Identifier for this document type,
e.g. '-//W3C//DTD XHTML 1.1//EN'
:param system_id: The system identifier for this document type,
e.g. 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'
u PUBLIC "%s"
u "%s"
u SYSTEM "%s"
uGenerate a string to be used as the basis of a Doctype object.
This is a separate method from for_name_and_ids() because the lxml
TreeBuilder needs to call it.
parser_class
uNo value provided for new tag's name.
a_namespaces
store_line_numbers
sourceline
sourcepos
aXMLAttributeDict
aHTMLAttributeDict
aAttributeValueList
attribute_dict_class
attribute_value_list_class
attrs
cdata_list_attributes
a_replace_cdata_list_attribute_values
items
can_be_empty_element
preserve_whitespace_tags
interesting_string_types
set_up_substitutions
string_containers
copy_self
a_event_stream
descendants
aEND_ELEMENT_EVENT
tag_stack
memo
D arecursive
FaSTART_ELEMENT_EVENT
uA deepcopy of a Tag is a new Tag, unconnected to the parse tree.
Its contents are a copy of the old Tag's contents.
T ais_xml
sourceline
sourcepos
can_be_empty_element
cdata_list_attributes
preserve_whitespace_tags
interesting_string_types
namespaces
T acan_be_empty_element
hidden
uCreate a new Tag just like this one, but with no
contents and unattached to any parse tree.
This is the first step in the deepcopy process, but you can
call it on its own to create a copy of a Tag without copying its
contents.
uIs this tag an empty-element tag? (aka a self-closing tag)
A tag that has contents is never an empty-element tag.
A tag that has no contents may or may not be an empty-element
tag. It depends on the `TreeBuilder` used to create the
tag. If the builder has a designated list of empty-element
tags, then only a tag whose name shows up in that list is
considered an empty-element tag. This is usually the case
for HTML documents.
If the builder has no designated list of empty-element, then
ny tag with no contents is an empty-element tag. This is usually
the case for XML documents.
is_empty_element
u: :meta private:
aNavigableString
string
uConvenience property to get the single string within this
`Tag`, assuming there is just one.
:return: If this `Tag` has a single child that's a
`NavigableString`, the return value is that string. If this
element has one child `Tag`, the return value is that child's
`Tag.string`, recursively. If this `Tag` has no children,
or has more than one child, the return value is ``None``.
If this property is unexpectedly returning ``None`` for you,
it's probably because your `Tag` has more than one thing
inside it.
uReplace the `Tag.contents` of this `Tag` with a single string.
uYield all strings of certain classes, possibly stripping them.
:param strip: If True, all strings will be stripped before being
yielded.
:param types: A tuple of NavigableString subclasses. Any strings of
a subclass not found in this list will be ignored. By
default, the subclasses considered are the ones found in
self.interesting_string_types. If that's not specified,
only NavigableString and CData objects will be
considered. That means no comments, processing
instructions, etc.
uTag._all_strings
inserted
a_insert
position
uInsert one or more new PageElements as a child of this `Tag`.
This works similarly to :py:meth:`list.insert`, except you can insert
multiple elements at once.
:param position: The numeric position that should be occupied
in this Tag's `Tag.children` by the first new `PageElement`.
:param new_children: The PageElements to insert.
:return The newly inserted PageElements.
uCannot insert None into a tag.
uCannot insert a tag into itself.
bs4
T aBeautifulSoup
aBeautifulSoup
min
T FT FtT ais_initialized
accept_self
parents_next_sibling
new_childs_last_element
uCannot replace an element with its contents when that element is not part of a tree.
:nnnamy_parent
my_index
uReplace this `PageElement` with its contents.
:return: This object, no longer part of the tree.
unwrap

Appends the given `PageElement` to the contents of this `Tag`.
:param tag: A PageElement.
:return The newly appended PageElement.
uA single non-Tag item was passed into Tag.extend. Use Tag.append instead.
aUserWarning
aIterable
tag_list
uAppends one or more objects to the contents of this
`Tag`.
:param tags: If a list of `PageElement` objects is provided,
they will be appended to this tag's contents, one at a time.
If a single `Tag` is provided, its `Tag.contents` will be
used to extend this object's `Tag.contents`.
:return The list of PageElements that were appended.
decompose
uDestroy all children of this `Tag` by calling
`PageElement.extract` on them.
:param decompose: If this is True, `PageElement.decompose` (a
more destructive method) will be called instead of
`PageElement.extract`.
smooth
aPreformattedString
marked
uSmooth out the children of this `Tag` by consolidating consecutive
strings.
If you perform a lot of operations that modify the tree,
calling this method afterwards can make pretty-printed output
look more natural.
uTag.index: element not in tag
uFind the index of a child of this `Tag` (by identity, not value).
Doing this by identity avoids issues when a `Tag` contains two
children that have string equality.
:param element: Look for this `PageElement` in this object's contents.
get
uReturns the value of the 'key' attribute for the tag, or
the value given for 'default' if it doesn't have that
ttribute.
:param key: The attribute to look for.
:param default: Use this value if the attribute is not present
on this `Tag`.
uThe same as get(), but always returns a (possibly empty) list.
:param key: The attribute to look for.
:param default: Use this value if the attribute is not present
on this `Tag`.
:return: A list of strings, usually empty or containing only a single
value.
uDoes this `Tag` have an attribute with the given name?
a__hash__
utag[key] returns the value of the 'key' attribute for the Tag,
nd throws an exception if it's not there.
uIterating over a Tag iterates over its contents.
uThe length of a Tag is the length of its list of contents.
uSetting tag[key] sets the value of the 'key' attribute for the
tag.
pop
uDeleting tag[key] deletes all 'key' attributes for the tag.
uCalling a Tag like a function is the same as calling its
find_all() method. Eg. tag('a') returns a list of all the A tags
found within this tag.
endswith
T aTag
:nq nu.%(name)sTag is deprecated, use .find("%(name)s") instead. If you really were looking for a tag called %(name)sTag, use .find("%(name)sTag")
find
startswith
T a__
u'%s' object has no attribute '%s'
aOptional
uCalling tag.subtag is the same as calling tag.find(name="subtag")
other
uReturns true iff this Tag has the same name, the same attributes,
nd the same contents (recursively) as `other`.
uReturns true iff this Tag is not identical to `other`,
s defined in __eq__.
decode
uRenders this `Tag` as a string.
encode
uRender this `Tag` and its contents as a bytestring.
:param encoding: The encoding to use when converting to
a bytestring. This may also affect the text of the document,
specifically any encoding declarations within the document.
:param indent_level: Each line of the rendering will be
indented this many levels. (The ``formatter`` decides what a
'level' means, in terms of spaces or other characters
output.) This is used internally in recursive calls while
pretty-printing.
:param formatter: Either a `Formatter` object, or a string naming one of
the standard formatters.
:param errors: An error handling strategy such as
'xmlcharrefreplace'. This value is passed along into
:py:meth:`str.encode` and its value should be one of the `error
handling constants defined by Python's codecs module
<https://docs.python.org/3/library/codecs.html#error-handlers>`_.
aEMPTY_ELEMENT_EVENT
a_format_tag
formatter
D aopening
tD aopening
Faindent_level
output_ready
string_literal_tag
element
a_should_pretty_print
a_indent_string
pieces
uRender this `Tag` and its contents as a Unicode string.
:param indent_level: Each line of the rendering will be
indented this many levels. (The ``formatter`` decides what a
'level' means, in terms of spaces or other characters
output.) This is used internally in recursive calls while
pretty-printing.
:param encoding: The encoding you intend to use when
converting the string to a bytestring. decode() is *not*
responsible for performing that encoding. This information
is needed so that a real encoding can be substituted in if
the document contains an encoding declaration (e.g. in a
<meta> tag).
:param formatter: Either a `Formatter` object, or a string
naming one of the standard formatters.
:param iterator: The iterator to use when navigating over the
parse tree. This is only used by `Tag.decode_contents` and
you probably won't need to use it.
uYield a sequence of events that can be used to reconstruct the DOM
for this element.
This lets us recreate the nested structure of this element
(e.g. when formatting it as a string) without using recursive
method calls.
This is similar in concept to the SAX API, but it's a simpler
interface designed for internal use. The events are different
from SAX and the arguments associated with the events are Tags
nd other Beautiful Soup objects.
:param iterator: An alternate iterator to use when traversing
the tree.
iterator
self_and_descendants
wcaSTRING_ELEMENT_EVENT
uTag._event_stream
indent
w
uAdd indentation whitespace before and/or after a string.
:param s: The string to amend with whitespace.
:param indent_level: The indentation level; affects how much
whitespace goes before the string.
:param indent_before: Whether or not to add whitespace
before the string.
:param indent_after: Whether or not to add whitespace
(a newline) after the string.
w/aattributes
w aAttributeValueWithCharsetSubstitution
substitute_encoding
attribute_value
w=aquoted_attribute_value
void_element_close_prefix
w<w>uShould this tag be pretty-printed?
Most of them should, but some (such as <pre> in HTML
documents) should not.
T aindent_level
formatter
T aencoding
indent_level
formatter
uPretty-print this `Tag` as a string or bytestring.
:param encoding: The encoding of the bytestring, or None if you want Unicode.
:param formatter: A Formatter object, or a string naming one of
the standard formatters.
:return: A string (if no ``encoding`` is provided) or a bytestring
(otherwise).
T aiterator
uRenders the contents of this tag as a Unicode string.
:param indent_level: Each line of the rendering will be
indented this many levels. (The formatter decides what a
'level' means in terms of spaces or other characters
output.) Used internally in recursive calls while
pretty-printing.
:param eventual_encoding: The tag is destined to be
encoded into this encoding. decode_contents() is *not*
responsible for performing that encoding. This information
is needed so that a real encoding can be substituted in if
the document contains an encoding declaration (e.g. in a
<meta> tag).
:param formatter: A `Formatter` object, or a string naming one of
the standard Formatters.
decode_contents
uRenders the contents of this PageElement as a bytestring.
:param indent_level: Each line of the rendering will be
indented this many levels. (The ``formatter`` decides what a
'level' means, in terms of spaces or other characters
output.) This is used internally in recursive calls while
pretty-printing.
:param formatter: Either a `Formatter` object, or a string naming one of
the standard formatters.
:param encoding: The bytestring will be in this encoding.
encode_contents
T aindent_level
encoding
uDeprecated method for BS3 compatibility.
:meta private:
uLook in the children of this PageElement and find the first
PageElement that matches the given criteria.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param recursive: If this is True, find() will perform a
recursive search of this Tag's children. Otherwise,
only the direct children will be considered.
:param string: A filter on the `Tag.string` attribute.
:param limit: Stop looking after finding this many results.
:kwargs: Additional filters on attribute values.
children
uLook in the children of this `PageElement` and find all
`PageElement` objects that match the given criteria.
All find_* methods take a common set of arguments. See the online
documentation for detailed explanations.
:param name: A filter on tag name.
:param attrs: Additional filters on attribute values.
:param recursive: If this is True, find_all() will perform a
recursive search of this PageElement's children. Otherwise,
only the direct children will be considered.
:param limit: Stop looking after finding this many results.
:param _stacklevel: Used internally to improve warning messages.
:kwargs: Additional filters on attribute values.
uIterate over all direct children of this `PageElement`.
uTag.children.<locals>.<genexpr>
uIterate over this `Tag` and its children in a
breadth-first sequence.
uIterate over all children of this `Tag` in a
breadth-first sequence.
T aaccept_self
current
uTag.descendants
css
select_one
uPerform a CSS selection operation on the current element.
:param selector: A CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will use the prefixes it encountered while
parsing the document.
:param kwargs: Keyword arguments to be passed into Soup Sieve's
soupsieve.select() method.
select
uPerform a CSS selection operation on the current element.
This uses the SoupSieve library.
:param selector: A string containing a CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will use the prefixes it encountered while
parsing the document.
:param limit: After finding this number of results, stop looking.
:param kwargs: Keyword arguments to be passed into SoupSieve's
soupsieve.select() method.
aCSS
uReturn an interface to the CSS selector API.
uDeprecated generator.
:meta private:
has_attr
uDeprecated method. This was kind of misleading because has_key()
(attributes) was different from __in__ (contents).
has_key() is gone in Python 3, anyway.
:meta private:
a__init__
source
uResultSet object has no attribute "
u". You're probably treating a list of elements like a single element. Did you call find_all() when you meant to call find()?
uRaise a helpful exception to explain a common code fix.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
aMIT
a__license__
re
ubs4.css
T aCSS
ubs4._deprecation
T a_deprecated
a_deprecated_alias
a_deprecated_function_alias
a_deprecated
a_deprecated_alias
a_deprecated_function_alias
ubs4.formatter
T aFormatter
aHTMLFormatter
aXMLFormatter
ubs4._warnings
T aAttributeResemblesVariableWarning
aAny
aCallable
aDict
aGeneric
aIterator
aList
aMapping
aPattern
aSet
aTYPE_CHECKING
aTuple
aType
aTypeVar
aUnion
typing_extensions
T aSelf
aTypeAlias
aSelf
aTypeAlias
a_OneOrMoreStringTypes
T a_StrainableElement
aElementFilter
a_FindMethodName
D awhitespace_re
uThe {name} attribute was deprecated in version 4.7.0. If you need it, make your own copy.
compile
T u\s+
a_deprecated_whitespace_re
uPattern[str]
D aname
return
str
aAny
a__getattr__
uutf-8
str
T u\S+
nonwhitespace_re
S apalmos
unicode_escape
string_escape
uraw-unicode-escape
idna
ustring-escape
mbcs
punycode
oem
uunicode-escape
raw_unicode_escape
undefined
uSet[_Encoding]
T Ostr
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
