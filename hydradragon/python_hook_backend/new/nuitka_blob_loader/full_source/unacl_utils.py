# Reconstructed from integrated Nuitka blob
# Module: unacl.utils


A bytes subclass that holds a messaged that has been encrypted by a
:class:`SecretBox`.
a__qualname__
a__annotations__
bytes
classmethod
cls
nonce
ciphertext
combined
return
a_from_parts
uEncryptedMessage._from_parts
property
uEncryptedMessage.nonce
uEncryptedMessage.ciphertext
a__orig_bases__
aStringFixer
self
a__str__
uStringFixer.__str__
D abytes_in
return
Obytes
Ostr
bytes_as_string
T l D asize
return
Oint
Obytes
random
aRawEncoder
size
seed
encoder
aEncoder
randombytes_deterministic
unacl\utils.py
u<module nacl.utils>
T a__class__
T aself
T acls
nonce
ciphertext
combined
obj
T abytes_in
T asize
T asize
seed
encoder
raw_data

a__spec__
.parsimonious
uParsimonious's public API. Import from here.
Things may move around in modules deeper than this one.
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_parsimonious
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uparsimonious.exceptions
T aParseError
aIncompleteParseError
aVisitationError
aUndefinedLabel
aBadGrammar
aParseError
aIncompleteParseError
aVisitationError
aUndefinedLabel
aBadGrammar
uparsimonious.grammar
T aGrammar
aTokenGrammar
aGrammar
aTokenGrammar
uparsimonious.nodes
T aNodeVisitor
aVisitationError
rule
aNodeVisitor
rule
uparsimonious\__init__.py
u<module parsimonious>

a__spec__
.parsimonious.exceptions
U
text
pos
expr
name
u'%s'
uRule %s didn't match at '%s' (line %s, column %s).
l aline
column
count
w
uReturn the 1-based line number where the expression ceased to
match.
rindex
T EValueError
EAttributeError
uReturn the 1-based column where the expression ceased to match.
dedent

Left recursion in rule

u at
u (line
u, column
u).
Parsimonious is a packrat parser, so it can't handle left recursion.
See https://en.wikipedia.org/wiki/Parsing_expression_grammar#Indirect_left_recursion
for how to rewrite your grammar into a rule that does not use left-recursion.
strip
uRule '%s' matched in its entirety, but it didn't consume all the text. The non-matching portion of the text begins with '%s' (line %s, column %s).
original_class
a__class__
a__init__
u%s: %s
Parse tree:
%s
a__name__
prettily
T aerror
uConstruct.
:arg exc: What went wrong. We wrap this and add more info.
:arg node: The node at which the error occurred
label
uThe label "%s" was never defined.
a__doc__
a__file__
origin
has_location
a__cached__
textwrap
T adedent
uparsimonious.utils
T aStrAndRepr
aStrAndRepr
a__prepare__
aParseError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
