# Reconstructed from integrated Nuitka blob
# Module: ubs4.filter

u`ElementFilter` encapsulates the logic necessary to decide:
1. whether a `PageElement` (a `Tag` or a `NavigableString`) matches a
user-specified query.
2. whether a given sequence of markup found during initial parsing
should be turned into a `PageElement` at all, or simply discarded.
The base class is the simplest `ElementFilter`. By default, it
matches everything and allows all markup to become `PageElement`
objects. You can make it more selective by passing in a
user-defined match function, or defining a subclass.
Most users of Beautiful Soup will never need to use
`ElementFilter`, or its more capable subclass
`SoupStrainer`. Instead, they will use methods like
:py:meth:`Tag.find`, which will convert their arguments into
`SoupStrainer` objects and run them against the tree.
However, if you find yourself wanting to treat the arguments to
Beautiful Soup's find_*() methods as first-class objects, those
objects will be `SoupStrainer` objects. You can create them
yourself and then make use of functions like
`ElementFilter.filter()`.
a__qualname__
a__annotations__
uOptional[_PageElementMatchFunction]
T nD amatch_function
uOptional[_PageElementMatchFunction]
a__init__
uElementFilter.__init__
property
D areturn
bool
uElementFilter.includes_everything
uDoes this `ElementFilter` obviously exclude everything? If
so, Beautiful Soup will issue a warning if you try to use it
when parsing a document.
The `ElementFilter` might turn out to exclude everything even
if this returns `False`, but it won't exclude everything in an
obvious way.
The base `ElementFilter` implementation excludes things based
on a match function we can't inspect, so excludes_everything
is always false.
excludes_everything
uElementFilter.excludes_everything
T FD aelement
a_known_rules
return
aPageElement
bool
puElementFilter.match
D agenerator
return
uIterator[PageElement]
uIterator[_OneElement]
D agenerator
return
uIterator[PageElement]
a_AtMostOneElement
find
uElementFilter.find
D agenerator
limit
return
uIterator[PageElement]
uOptional[int]
a_QueryResults
find_all
uElementFilter.find_all
D ansprefix
name
attrs
return
uOptional[str]
str
uOptional[_RawAttributeValues]
bool
uBased on the name and attributes of a tag, see whether this
`ElementFilter` will allow a `Tag` object to even be created.
By default, all tags are parsed. To change this, subclass
`ElementFilter`.
:param name: The name of the prospective tag.
:param attrs: The attributes of the prospective tag.
uElementFilter.allow_tag_creation
D astring
return
str
bool
uBased on the content of a string, see whether this
`ElementFilter` will allow a `NavigableString` object based on
this string to be added to the parse tree.
By default, all strings are processed into `NavigableString`
objects. To change this, subclass `ElementFilter`.
:param str: The string under consideration.
allow_string_creation
uElementFilter.allow_string_creation
a__orig_bases__
uEach MatchRule encapsulates the logic behind a single argument
passed in to one of the Beautiful Soup find* methods.
uOptional[str]
uOptional[_RegularExpressionProtocol]
uOptional[bool]
T nnnnnD astring
pattern
function
present
exclude_everything
uOptional[Union[str, bytes]]
uOptional[_RegularExpressionProtocol]
uOptional[Callable]
uOptional[bool]
uOptional[bool]
uMatchRule.__init__
D astring
return
uOptional[str]
uOptional[bool]
uMatchRule._base_match
D astring
return
uOptional[str]
bool
uMatchRule.matches_string
D areturn
str
a__repr__
uMatchRule.__repr__
D aother
return
aAny
bool
a__eq__
uMatchRule.__eq__
uA MatchRule implementing the rules for matches against tag name.
uOptional[_TagMatchFunction]
D atag
return
aTag
bool
uTagNameMatchRule.matches_tag
uA MatchRule implementing the rules for matches against attribute value.
uOptional[_StringMatchFunction]
uA MatchRule implementing the rules for matches against a NavigableString.
aSoupStrainer
uThe `ElementFilter` subclass used internally by Beautiful Soup.
A `SoupStrainer` encapsulates the logic necessary to perform the
kind of matches supported by methods such as
:py:meth:`Tag.find`. `SoupStrainer` objects are primarily created
internally, but you can create one yourself and pass it in as
``parse_only`` to the `BeautifulSoup` constructor, to parse a
subset of a large document.
Internally, `SoupStrainer` objects work by converting the
constructor arguments into `MatchRule` objects. Incoming
tags/markup are matched against those rules.
:param name: One or more restrictions on the tags found in a document.
:param attrs: A dictionary that maps attribute names to
restrictions on tags that use those attributes.
:param string: One or more restrictions on the strings found in a
document.
:param kwargs: A dictionary that maps attribute names to restrictions
on tags that use those attributes. These restrictions are additive to
ny specified in ``attrs``.
uList[TagNameMatchRule]
uDict[str, List[AttributeValueMatchRule]]
uList[StringMatchRule]
D aname
attrs
string
kwargs
uOptional[_StrainableElement]
uDict[str, _StrainableAttribute]
uOptional[_StrainableString]
a_StrainableAttribute
uSoupStrainer.__init__
uSoupStrainer.includes_everything
uSoupStrainer.excludes_everything
D areturn
uOptional[_StrainableString]
uSoupStrainer.string
uSoupStrainer.text
uSoupStrainer.__repr__
classmethod
D aobj
rule_class
return
uOptional[Union[_StrainableElement, _StrainableAttribute]]
uType[MatchRule]
uIterator[MatchRule]
uSoupStrainer.matches_tag
D aattr_value
rules
return
uOptional[_AttributeValue]
uIterable[AttributeValueMatchRule]
bool
uSoupStrainer._attribute_match
uSoupStrainer.allow_tag_creation
uSoupStrainer.allow_string_creation
uSoupStrainer.matches_any_string_rule
uSoupStrainer.match
T aallow_tag_creation
u4.13.0
D aname
attrs
return
str
uOptional[_RawAttributeValues]
bool
search_tag
uSoupStrainer.search_tag
T amatch
u4.13.0
D aelement
return
aPageElement
uOptional[PageElement]
uSoupStrainer.search
ubs4\filter.py
T a.0
wxu<module bs4.filter>
T a__class__
T aself
other
T aself
match_function
T aself
string
pattern
function
present
exclude_everything
values
T	aself
name
attrs
string
kwargs
attrdict
attr
value
rule_obj
T aself
cls
T aself
T aself
attr_value
rules
attr_values
a_match_attribute_value_helper
this_attr_match
joined_attr_value
T aself
string
T acls
obj
rule_class
wowxT aattr_values
rule
attr_value
rules
T arules
T aself
nsprefix
name
attrs
T aself
nsprefix
name
attrs
prefixed_name
name_match
rule
wxaattr
rules
attr_value
T aself
ruleset
T aself
generator
wiT aself
generator
match
T aself
generator
limit
results
match
T aself
element
a_known_rules
T aself
string
string_rule
T aself
string
a_base_result
T
self
tag
prefixed_name
name_matches
rule
attr
rules
attr_value
this_attr_match
a_str
T aself
tag
base_value
function
T aself
element
T aself
name
attrs
a__spec__
.bs4.formatter
{
aXML
aHTML_DEFAULTS
aHTML
language
entity_substitution
void_element_close_prefix
a_default
cdata_containing_tags
empty_attributes_are_booleans
w aindent
uConstructor.
:param language: This should be `Formatter.XML` if you are formatting
XML markup and `Formatter.HTML` if you are formatting HTML markup.
:param entity_substitution: A function to call to replace special
characters with XML/HTML entities. For examples, see
bs4.dammit.EntitySubstitution.substitute_html and substitute_xml.
:param void_element_close_prefix: By default, void elements
re represented as <tag/> (XML rules) rather than <tag>
(HTML rules). To get <tag>, pass in the empty string.
:param cdata_containing_tags: The set of tags that are defined
s containing CDATA in this dialect. For example, in HTML,
<script> and <style> tags are defined as containing CDATA,
nd their contents should not be formatted.
:param empty_attributes_are_booleans: If this is set to true,
then attributes whose values are sent to the empty string
will be treated as `HTML boolean
ttributes<https://dev.w3.org/html5/spec-LC/common-microsyntaxes.html#boolean-attributes>`_. (Attributes
whose value is None are always rendered this way.)
:param indent: If indent is a non-negative integer or string,
then the contents of elements will be indented
ppropriately when pretty-printing. An indent level of 0,
negative, or "" will only insert newlines. Using a
positive integer indent indents that many spaces per
level. If indent is a string (such as "\t"), that string
is used to indent each level. The default behavior is to
indent one space per level.
element
T aNavigableString
aNavigableString
parent
name
uProcess a string that needs to undergo entity substitution.
This may be a string encountered in an attribute value or as
text.
:param ns: A string.
:return: The same string but with certain characters replaced by named
or numeric entities.
substitute
uProcess the value of an attribute.
:param ns: A string.
:return: A string with certain characters replaced by named
or numeric entities.
attrs
items
sorted
uReorder a tag's attributes however you want.
By default, attributes are sorted alphabetically. This makes
behavior consistent between Python 2 and Python 3, and preserves
backwards compatibility with older versions of Beautiful Soup.
If `empty_attributes_are_booleans` is True, then
ttributes whose values are set to the empty string will be
treated as boolean attributes.
self

u<genexpr>
uFormatter.attributes.<locals>.<genexpr>
aHTMLFormatter
a__init__
T aindent
aXMLFormatter
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
aCallable
aDict
aIterable
aOptional
aSet
aTuple
aTYPE_CHECKING
aUnion
typing_extensions
T aTypeAlias
aTypeAlias
ubs4.dammit
T aEntitySubstitution
aEntitySubstitution
a__prepare__
aFormatter
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
