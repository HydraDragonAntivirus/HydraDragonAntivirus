# Reconstructed from integrated Nuitka blob
# Module: ubs4._warnings

uThe warning issued when BeautifulSoup has to guess what parser to
use -- probably because no parser was specified in the constructor.
a__qualname__
a__annotations__
uNo parser was explicitly specified, so I'm using the best available %(markup_type)s parser for this system ("%(parser)s"). This usually isn't a problem, but if you run this code on another system, or in a different virtual environment, it may use a different parser and behave differently.
The code that caused this warning is on line %(line_number)s of the file %(filename)s. To get rid of this warning, pass the additional argument 'features="%(parser)s"' to the BeautifulSoup constructor.
aMESSAGE
str
a__orig_bases__
aUnusualUsageWarning
uA superclass for warnings issued when Beautiful Soup sees
something that is typically the result of a mistake in the calling
code, but might be intentional on the part of the user. If it is
in fact intentional, you can filter the individual warning class
to get rid of the warning. If you don't like Beautiful Soup
second-guessing what you are doing, you can filter the
UnusualUsageWarningclass itself and get rid of these entirely.
aMarkupResemblesLocatorWarning
uThe warning issued when BeautifulSoup is given 'markup' that
ctually looks like a resource locator -- a URL or a path to a file
on disk.

However, if you want to parse some data that happens to look like a %(what)s, then nothing has gone wrong: you are using Beautiful Soup correctly, and this warning is spurious and can be filtered. To make this warning go away, run this code before calling the BeautifulSoup constructor:
from bs4 import MarkupResemblesLocatorWarning
import warnings
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
aGENERIC_MESSAGE
uThe input passed in on this line looks more like a URL than HTML or XML.
If you meant to use Beautiful Soup to parse the web page found at a certain URL, then something has gone wrong. You should use an Python package like 'requests' to fetch the content behind the URL. Once you have the content as a string, you can feed that string into Beautiful Soup.
aURL_MESSAGE
uThe input passed in on this line looks more like a filename than HTML or XML.
If you meant to use Beautiful Soup to parse the contents of a file on disk, then something has gone wrong. You should open the file first, using code like this:
filehandle = open(your filename)
You can then feed the open filehandle into Beautiful Soup instead of using the filename.
aFILENAME_MESSAGE
aSyntaxWarning
aAttributeResemblesVariableWarning
uThe warning issued when Beautiful Soup suspects a provided
ttribute name may actually be the misspelled name of a Beautiful
Soup variable. Generally speaking, this is only used in cases like
"_class" where it's very unlikely the user would be referencing an
XML attribute with that name.
u%(original)r is an unusual attribute name and is a common misspelling for %(autocorrect)r.
If you meant %(autocorrect)r, change your code to use it, and this warning will go away.
If you really did mean to check the %(original)r attribute, this warning is spurious and can be filtered. To make it go away, run this code before creating your BeautifulSoup object:
from bs4 import AttributeResemblesVariableWarning
import warnings
warnings.filterwarnings("ignore", category=AttributeResemblesVariableWarning)
aXMLParsedAsHTMLWarning
uThe warning issued when an HTML parser is used to parse
XML that is not (as far as we can tell) XHTML.
uIt looks like you're using an HTML parser to parse an XML document.
Assuming this really is an XML document, what you're doing might work, but you should know that using an XML parser will be more reliable. To parse this document as XML, make sure you have the Python package 'lxml' installed, and pass the keyword argument `features="xml"` into the BeautifulSoup constructor.
If you want or need to use an HTML parser on this document, you can make this warning go away by filtering it. To do that, run this code before calling the BeautifulSoup constructor:
from bs4 import XMLParsedAsHTMLWarning
import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
ubs4\_warnings.py
u<module bs4._warnings>
T a__class__

a__spec__
.bs4.builder._html5lib
user_specified_encoding
self
document_declared_encoding
exclude_encodings
warnings
warn
uYou provided a value for

u, but the html5lib tree builder doesn't support
w.D astacklevel
l aDetectsXMLParsedAsHTML
warn_if_markup_looks_like_xml
markup
prepare_markup
uHTML5TreeBuilder.prepare_markup
soup
parse_only
T uYou provided a value for parse_only, but the html5lib tree builder doesn't support parse_only. The entire document will be parsed.
l T astacklevel
html5lib
aHTMLParser
create_treebuilder
T atree
underlying_builder
parser
override_encoding
parse
original_encoding
tokenizer
stream
charEncoding
name
uRun some incoming markup through some parsing process,
populating the `BeautifulSoup` object in `HTML5TreeBuilder.soup`.
aTreeBuilderForHtml5lib
store_line_numbers
T astore_line_numbers
uCalled by html5lib to instantiate the kind of class it
calls a 'TreeBuilder'.
:param namespaceHTMLElements: Whether or not to namespace HTML elements.
:meta private:
u<html><head></head><body>%s</body></html>
uSee `TreeBuilder`.
uThe optionality of the 'soup' argument to the TreeBuilderForHtml5lib constructor is deprecated as of Beautiful Soup 4.13.0: 'soup' is now required. If you can't pass in a BeautifulSoup object here, or you get this warning and it seems mysterious to you, please contact the Beautiful Soup developer team for possible un-deprecation.
aDeprecationWarning
D astacklevel
l abs4
T aBeautifulSoup
aBeautifulSoup
T u
uhtml.parser
a__init__
reset
aElement
cast
aOptional
publicId
systemId
aDoctype
for_name_and_ids
object_was_parsed
position
new_tag
T asourceline
sourcepos
aTextNode
aComment
uThis is only used by html5lib HTMLParser.parseFragment(),
which is never used by Beautiful Soup, only by the html5lib
unit tests. Since we don't currently hook into those tests,
the implementation is left blank.
uThis is only used by the html5lib unit tests. Since we
don't currently hook into those tests, the implementation is
left blank.
append
element
attrs
items
a__iter__
cdata_list_attributes
get
w*aattribute_value_list_class
nonwhitespace_re
findall
keys
uReturn the html5lib constant corresponding to the type of
the underlying DOM object.
NOTE: This property is only accessed by the html5lib test
suite, not by Beautiful Soup proper.
treebuilder_base
aNode
namespace
aNavigableString
parent
extract
contents
new_string
replace_with
a_most_recent_element
a_last_descendant
T Fanext_element
child
T aparent
most_recent_element
aAttrList
aNamespacedAttribute
attributes
a_AttributeValues
builder
a_replace_cdata_list_attribute_values
set_up_substitutions
insertBefore
appendChild
index
insert
next_sibling
T Fpaprevious_element
first_child
previous_sibling
T FtT ais_initialized
accept_self
new_parent_element
uMove all of this tag's children into another tag.
node
namespaces
html
a__doc__
a__file__
origin
has_location
a__cached__
aMIT
a__license__
aHTML5TreeBuilder
a__all__
aAny
aDict
aIterable
aSequence
aTYPE_CHECKING
aTuple
aUnion
typing_extensions
T aTypeAlias
aTypeAlias
ubs4._typing
T a_AttributeValue
a_AttributeValues
a_Encoding
a_Encodings
a_NamespaceURL
a_RawMarkup
a_AttributeValue
a_Encoding
a_Encodings
a_NamespaceURL
a_RawMarkup
ubs4.builder
T aDetectsXMLParsedAsHTML
aPERMISSIVE
aHTML
aHTML_5
aHTMLTreeBuilder
aPERMISSIVE
aHTML
aHTML_5
aHTMLTreeBuilder
ubs4.element
T aNamespacedAttribute
aPageElement
nonwhitespace_re
aPageElement
uhtml5lib.constants
T anamespaces
T aComment
aDoctype
aNavigableString
aTag
aTag
uhtml5lib.treebuilders
T abase
base
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
