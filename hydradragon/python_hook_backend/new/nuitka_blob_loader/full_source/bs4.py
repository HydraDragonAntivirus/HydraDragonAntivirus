# Reconstructed from integrated Nuitka blob
# Module: bs4

uA data structure representing a parsed HTML or XML document.
Most of the methods you'll call on a BeautifulSoup object are inherited from
PageElement or Tag.
Internally, this class defines the basic interface called by the
tree builders when converting an HTML/XML document into a data
structure. The interface abstracts away the differences between
parsers. To write a new tree builder, you'll need to understand
these methods as a whole.
These methods will be called by the BeautifulSoup constructor:
* reset()
* feed(markup)
The tree builder may call these methods from its feed() implementation:
* handle_starttag(name, attrs) # See note about return value
* handle_endtag(name)
* handle_data(data) # Appends to the current data node
* endData(containerClass) # Ends the current data node
No matter how complicated the underlying parser is, you should be
ble to build a tree using 'start tag' events, 'end tag' events,
'data' events, and "done with data" events.
If you encounter an empty-element tag (aka a self-closing tag,
like HTML's <br> tag), call handle_starttag and then
handle_endtag.
a__qualname__
a__annotations__
u[document]
str
html
fast

bool
T u
nnnnnnafrom_encoding
exclude_encodings
uBeautifulSoup.__init__
D areturn
aBeautifulSoup
copy_self
uBeautifulSoup.copy_self
a__getstate__
uBeautifulSoup.__getstate__
state
a__setstate__
uBeautifulSoup.__setstate__
classmethod
T unothing (private method, will be removed)
u4.13.0
T areplaced_by
version
a_decode_markup
uBeautifulSoup._decode_markup
uBeautifulSoup._markup_is_url
uBeautifulSoup._markup_resembles_filename
D areturn
nuBeautifulSoup._feed
uBeautifulSoup.reset
T nnnnnnanamespace
nsprefix
attrs
sourceline
int
sourcepos
kwattrs
new_tag
uBeautifulSoup.new_tag
T nabase_class
uBeautifulSoup.string_container
wsasubclass
new_string
uBeautifulSoup.new_string
args
insert_before
uBeautifulSoup.insert_before
insert_after
uBeautifulSoup.insert_after
uBeautifulSoup.popTag
tag
uBeautifulSoup.pushTag
containerClass
uBeautifulSoup.endData
T nnwoamost_recent_element
uBeautifulSoup.object_was_parsed
el
uBeautifulSoup._linkage_fixer
T ntainclusivePop
uBeautifulSoup._popToTag
T nnnanamespaces
handle_starttag
uBeautifulSoup.handle_starttag
handle_endtag
uBeautifulSoup.handle_endtag
data
handle_data
uBeautifulSoup.handle_data
minimal
indent_level
eventual_encoding
iterator
uBeautifulSoup.decode
a__orig_bases__
a_s
a_soup
uDeprecated interface to an XML parser.
uBeautifulStoneSoup.__init__
ubs4\__init__.py
T a.0
prefix
markup
T a.0
ext
lower
u<module bs4>
T a__class__
T aself
wdT aself
markup
features
builder
parse_only
from_encoding
exclude_encodings
element_classes
kwargs
builder_class
deprecated_argument
original_builder
original_features
possible_builder_class
markup_type
caller
globals
line_number
filename
fnl
values
rejections
success
weaother_exceptions
T aself
args
kwargs
a__class__
T aself
state
T acls
markup
decoded
T aself
T aself
el
descendant
target
first
child
prev_el
T acls
markup
problem
T acls
markup
markup_b
filelike
lower
extensions
byte
colon_i
T aself
name
nsprefix
inclusivePop
most_recently_popped
stack_size
wiwtT aself
clone
T aself
indent_level
eventual_encoding
formatter
iterator
kwargs
declared_encoding
warning
encoding_part
prefix
pretty_print
a__class__
T aold_name
new_name
kwargs
T akwargs
T aself
containerClass
current_data
strippable
wiwoT aself
data
T aself
name
nsprefix
T
self
name
namespace
nsprefix
attrs
sourceline
sourcepos
namespaces
tag_class
tag
T aself
args
T aself
wsasubclass
container
T aself
name
namespace
nsprefix
attrs
sourceline
sourcepos
string
kwattrs
attr_container
tag_class
tag
T	aself
woaparent
most_recent_element
previous_element
next_element
previous_sibling
next_sibling
fix
T aself
tag
T aself
base_class
container
a__spec__
.bs4.css
])
e
soupsieve
uCannot execute CSS selectors because the soupsieve package is not installed.
api
tag
uCannot escape CSS identifiers because the soupsieve package is not installed.
cast
escape
uEscape a CSS identifier.
This is a simple wrapper around `soupsieve.escape() <https://facelessuser.github.io/soupsieve/api/#soupsieveescape>`_. See the
documentation for that function for more information.
aSoupSieve
a_namespaces
uNormalize a dictionary of namespaces.
bs4
T aResultSet
aResultSet
uNormalize a list of results to a py:class:`ResultSet`.
A py:class:`ResultSet` is more consistent with the rest of
Beautiful Soup's API, and :py:meth:`ResultSet.__getattr__` has
a helpful error message if you try to treat a list of results
s a single result (a common mistake).
compile
a_ns
uPre-compile a selector and return the compiled object.
:param selector: A CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will use the prefixes it encountered while
parsing the document.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.compile() <https://facelessuser.github.io/soupsieve/api/#soupsievecompile>`_ method.
:param kwargs: Keyword arguments to be passed into Soup Sieve's
`soupsieve.compile() <https://facelessuser.github.io/soupsieve/api/#soupsievecompile>`_ method.
:return: A precompiled selector object.
:rtype: soupsieve.SoupSieve
select_one
uPerform a CSS selection operation on the current Tag and return the
first result, if any.
This uses the Soup Sieve library. For more information, see
that library's documentation for the `soupsieve.select_one() <https://facelessuser.github.io/soupsieve/api/#soupsieveselect_one>`_ method.
:param selector: A CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will use the prefixes it encountered while
parsing the document.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.select_one() <https://facelessuser.github.io/soupsieve/api/#soupsieveselect_one>`_ method.
:param kwargs: Keyword arguments to be passed into Soup Sieve's
`soupsieve.select_one() <https://facelessuser.github.io/soupsieve/api/#soupsieveselect_one>`_ method.
a_rs
select
uPerform a CSS selection operation on the current `element.Tag`.
This uses the Soup Sieve library. For more information, see
that library's documentation for the `soupsieve.select() <https://facelessuser.github.io/soupsieve/api/#soupsieveselect>`_ method.
:param selector: A CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will pass in the prefixes it encountered while
parsing the document.
:param limit: After finding this number of results, stop looking.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.select() <https://facelessuser.github.io/soupsieve/api/#soupsieveselect>`_ method.
:param kwargs: Keyword arguments to be passed into Soup Sieve's
`soupsieve.select() <https://facelessuser.github.io/soupsieve/api/#soupsieveselect>`_ method.
iselect
uPerform a CSS selection operation on the current `element.Tag`.
This uses the Soup Sieve library. For more information, see
that library's documentation for the `soupsieve.iselect()
<https://facelessuser.github.io/soupsieve/api/#soupsieveiselect>`_
method. It is the same as select(), but it returns a generator
instead of a list.
:param selector: A string containing a CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will pass in the prefixes it encountered while
parsing the document.
:param limit: After finding this number of results, stop looking.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.iselect() <https://facelessuser.github.io/soupsieve/api/#soupsieveiselect>`_ method.
:param kwargs: Keyword arguments to be passed into Soup Sieve's
`soupsieve.iselect() <https://facelessuser.github.io/soupsieve/api/#soupsieveiselect>`_ method.
closest
uFind the `element.Tag` closest to this one that matches the given selector.
This uses the Soup Sieve library. For more information, see
that library's documentation for the `soupsieve.closest()
<https://facelessuser.github.io/soupsieve/api/#soupsieveclosest>`_
method.
:param selector: A string containing a CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will pass in the prefixes it encountered while
parsing the document.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.closest() <https://facelessuser.github.io/soupsieve/api/#soupsieveclosest>`_ method.
:param kwargs: Keyword arguments to be passed into Soup Sieve's
`soupsieve.closest() <https://facelessuser.github.io/soupsieve/api/#soupsieveclosest>`_ method.
match
uCheck whether or not this `element.Tag` matches the given CSS selector.
This uses the Soup Sieve library. For more information, see
that library's documentation for the `soupsieve.match()
<https://facelessuser.github.io/soupsieve/api/#soupsievematch>`_
method.
:param: a CSS selector.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will pass in the prefixes it encountered while
parsing the document.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.match()
<https://facelessuser.github.io/soupsieve/api/#soupsievematch>`_
method.
:param kwargs: Keyword arguments to be passed into SoupSieve's
`soupsieve.match()
<https://facelessuser.github.io/soupsieve/api/#soupsievematch>`_
method.
filter
uFilter this `element.Tag`'s direct children based on the given CSS selector.
This uses the Soup Sieve library. It works the same way as
passing a `element.Tag` into that library's `soupsieve.filter()
<https://facelessuser.github.io/soupsieve/api/#soupsievefilter>`_
method. For more information, see the documentation for
`soupsieve.filter()
<https://facelessuser.github.io/soupsieve/api/#soupsievefilter>`_.
:param namespaces: A dictionary mapping namespace prefixes
used in the CSS selector to namespace URIs. By default,
Beautiful Soup will pass in the prefixes it encountered while
parsing the document.
:param flags: Flags to be passed into Soup Sieve's
`soupsieve.filter()
<https://facelessuser.github.io/soupsieve/api/#soupsievefilter>`_
method.
:param kwargs: Keyword arguments to be passed into SoupSieve's
`soupsieve.filter()
<https://facelessuser.github.io/soupsieve/api/#soupsievefilter>`_
method.
uIntegration code for CSS selectors using `Soup Sieve <https://facelessuser.github.io/soupsieve/>`_ (pypi: ``soupsieve``).
Acquire a `CSS` object through the `element.Tag.css` attribute of
the starting point of your CSS selector, or (if you want to run a
selector against the entire document) of the `BeautifulSoup` object
itself.
The main advantage of doing this instead of using ``soupsieve``
functions is that you don't need to keep passing the `element.Tag` to be
selected against, since the `CSS` object is permanently scoped to that
`element.Tag`.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
aModuleType
aAny
aIterable
aIterator
aOptional
aTYPE_CHECKING
warnings
ubs4._typing
T a_NamespaceMapping
a_NamespaceMapping
uOptional[ModuleType]
warn
T uThe soupsieve package is not installed. CSS selectors cannot be used.
T Oobject
a__prepare__
aCSS
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
