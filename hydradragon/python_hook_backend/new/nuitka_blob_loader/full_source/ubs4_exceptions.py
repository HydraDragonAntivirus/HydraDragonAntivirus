# Reconstructed from integrated Nuitka blob
# Module: ubs4.exceptions

uException raised by a TreeBuilder if it's unable to continue parsing.
a__qualname__
a__orig_bases__
T EValueError
aFeatureNotFound
uException raised by the BeautifulSoup constructor if no parser with the
requested features is found.
uAn Exception to be raised when the underlying parser simply
refuses to parse the given markup.
message_or_exception
str
aException
uParserRejectedMarkup.__init__
ubs4\exceptions.py
u<module bs4.exceptions>
T a__class__
T aself
message_or_exception
wea__class__

a__spec__
.bs4.filter
9
match_function
uPass in a match function to easily customize the behavior of
`ElementFilter.match` without needing to subclass.
:param match_function: A function that takes a `PageElement`
nd returns `True` if that `PageElement` matches some criteria.
uDoes this `ElementFilter` obviously include everything? If so,
the filter process can be made much faster.
The `ElementFilter` might turn out to include everything even
if this returns `False`, but it won't include everything in an
obvious way.
The base `ElementFilter` implementation includes things based on
the match function, so includes_everything is only true if
there is no match function.
includes_everything
uDoes the given PageElement match the rules set down by this
ElementFilter?
The base implementation delegates to the function passed in to
the constructor.
:param _known_rules: Defined for compatibility with
SoupStrainer._match(). Used more for consistency than because
we need the performance optimization.
uThe most generic search method offered by Beautiful Soup.
Acts like Python's built-in `filter`, using
`ElementFilter.match` as the filtering function.
self
generator
match
D a_known_rules
tacast
a_OneElement
filter
uElementFilter.filter
uA lower-level equivalent of :py:meth:`Tag.find`.
You can pass in your own generator for iterating over
`PageElement` objects. The first one that matches this
`ElementFilter` will be returned.
:param generator: A way of iterating over `PageElement`
objects.
aResultSet
results
append
uA lower-level equivalent of :py:meth:`Tag.find_all`.
You can pass in your own generator for iterating over
`PageElement` objects. Only elements that match this
`ElementFilter` will be returned in the :py:class:`ResultSet`.
:param generator: A way of iterating over `PageElement`
objects.
:param limit: Stop looking after finding this many results.
decode
T autf8
string
re
compile
pattern
function
present
exclude_everything
uEither string, pattern, function, present, or exclude_everything must be provided.
uAt most one of string, pattern, function, present, and exclude_everything must be provided.
search
uRun the 'cheap' portion of a match, trying to get an answer without
calling a potentially expensive custom function.
:return: True or False if we have a (positive or negative)
match; None if we need to keep trying.
a_base_match
a__name__
w<u
u string=
u pattern=
u function=
u present=
w>aMatchRule
name
a_TagMatchFunction
text
aOptional
a_StrainableString
warnings
warn
uAs of version 4.11.0, the 'text' argument to the SoupStrainer constructor is deprecated. Use 'string' instead.
aDeprecationWarning
D astacklevel
l aTagNameMatchRule
T tT apresent
name_rules
aList
a_make_match_rules
defaultdict
T Olist
attribute_rules
class
items
class_
aAttributeValueMatchRule
aStringMatchRule
string_rules
a_SoupStrainer__string
uCheck whether the provided rules will obviously include
everything. (They might include everything even if this returns `False`,
but not in an obvious way.)
values
uCheck whether the provided rules will obviously exclude
everything. (They might exclude everything even if this returns `False`,
but not in an obvious way.)
u<genexpr>
uSoupStrainer.excludes_everything.<locals>.<genexpr>
uAccess to deprecated property string. (Look at .string_rules instead) -- Deprecated since version 4.13.0.
u:meta private:
uAccess to deprecated property text. (Look at .string_rules instead) -- Deprecated since version 4.13.0.
u name=
u attrs=
uConvert a vaguely-specific 'object' into one or more well-defined
`MatchRule` objects.
:param obj: Some kind of object that corresponds to one or more
matching rules.
:param rule_class: Create instances of this `MatchRule` subclass.
obj
T Ostr
Obytes
rule_class
T astring
callable
T afunction
a_RegularExpressionProtocol
T apattern
a__iter__
T aexclude_everything
T Obytes
Ostr
uIgnoring nested list
u to avoid the possibility of infinite recursion.
D astacklevel
l acls
uSoupStrainer._make_match_rules
prefix
w:amatches_tag
tag
prefixed_name
matches_string
get
a_attribute_match
matches_any_string_rule
uDo the rules of this `SoupStrainer` trigger a match against the
given `Tag`?
If the `SoupStrainer` has any `TagNameMatchRule`, at least one
must match the `Tag` or its `Tag.name`.
If there are any `AttributeValueMatchRule` for a given
ttribute, at least one of them must match the attribute
value.
If there are any `StringMatchRule`, at least one must match,
but a `SoupStrainer` that *only* contains `StringMatchRule`
cannot match a `Tag`, only a `NavigableString`.
D aattr_values
return
uSequence[Optional[str]]
bool
a_match_attribute_value_helper
uSoupStrainer._attribute_match.<locals>._match_attribute_value_helper
aSequence
w arules
attr_values
rule
name_match
aAttributeDict
attrs
uBased on the name and attributes of a tag, see whether this
`SoupStrainer` will allow a `Tag` object to even be created.
:param name: The name of the prospective tag.
:param attrs: The attributes of the prospective tag.
uBased on the content of a markup string, see whether this
`SoupStrainer` will allow it to be instantiated as a
`NavigableString` object, or whether it should be ignored.
uSee whether the content of a string matches any of
this `SoupStrainer`'s string rules.
aTag
aNavigableString
uDoes the given `PageElement` match the rules set down by this
`SoupStrainer`?
The find_* methods rely heavily on this method to find matches.
:param element: A `PageElement`.
:param _known_rules: Set to true in the common case where
we already checked and found at least one rule in this SoupStrainer
that might exclude a PageElement. Without this, we need
to check .includes_everything every time, just to be safe.
:return: `True` if the element matches this `SoupStrainer`'s rules; `False` otherwise.
allow_tag_creation
uA less elegant version of `allow_tag_creation`. Deprecated as of 4.13.0
uA less elegant version of match(). Deprecated as of 4.13.0.
:meta private:
a__doc__
a__file__
origin
has_location
a__cached__
annotations
collections
T adefaultdict
aAny
aCallable
aDict
aIterator
aIterable
aType
aUnion
ubs4._deprecation
T a_deprecated
a_deprecated
ubs4.element
T aAttributeDict
aNavigableString
aPageElement
aResultSet
aTag
aPageElement
ubs4._typing
T a_AtMostOneElement
a_AttributeValue
a_OneElement
a_PageElementMatchFunction
a_QueryResults
a_RawAttributeValues
a_RegularExpressionProtocol
a_StrainableAttribute
a_StrainableElement
a_StrainableString
a_StringMatchFunction
a_TagMatchFunction
a_AtMostOneElement
a_AttributeValue
a_PageElementMatchFunction
a_QueryResults
a_RawAttributeValues
a_StrainableAttribute
a_StrainableElement
a_StringMatchFunction
T Oobject
a__prepare__
aElementFilter
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
