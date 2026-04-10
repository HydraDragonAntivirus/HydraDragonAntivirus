# Reconstructed from integrated Nuitka blob
# Module: uparsimonious.nodes

uA parse tree node
Consider these immutable once constructed. As a side effect of a
memory-saving strategy in the cache, multiple references to a single
``Node`` might be returned in a single parse tree. So, if you start
messing with one, you'll see surprising parallel changes pop up elsewhere.
My philosophy is that parse trees (and their nodes) should be
representation-agnostic. That is, they shouldn't get all mixed up with what
the final rendered form of a wiki page (or the intermediate representation
of a programming language, or whatever) is going to be: you should be able
to parse once and render several representations from the tree, one after
nother.
a__qualname__
L aexpr
full_text
start
end
children
a__slots__
T na__init__
uNode.__init__
property
uNode.expr_name
a__iter__
uNode.__iter__
uNode.text
uNode.prettily
a__str__
uNode.__str__
a__eq__
uNode.__eq__
a__ne__
uNode.__ne__
T tuNode.__repr__
a__orig_bases__
aRegexNode
uNode returned from a ``Regex`` expression
Grants access to the ``re.Match`` object, in case you want to access
capturing groups, etc.
T Otype
uRuleDecoratorMeta.__new__
metaclass
aNodeVisitor
uA shell for writing things that turn parse trees into something useful
Performs a depth-first traversal of an AST. Subclass this, add methods for
each expr you care about, instantiate, and call
``visit(top_node_of_parse_tree)``. It'll return the useful stuff. This API
is very similar to that of ``ast.NodeVisitor``.
These could easily all be static methods, but that would add at least as
much weirdness at the call site as the ``()`` for instantiation. And this
way, we support subclasses that require state: options, for example, or a
symbol table constructed from a programming language's AST.
We never transform the parse tree in place, because...
* There are likely multiple references to the same ``Node`` object in a
parse tree, and changes to one reference would surprise you elsewhere.
* It makes it impossible to report errors: you'd end up with the "error"
rrow pointing someplace in a half-transformed mishmash of nodes--and
that's assuming you're even transforming the tree into another tree.
Heaven forbid you're making it into a string or something else.
uNodeVisitor.visit
uNodeVisitor.generic_visit
T l
uNodeVisitor.parse
uNodeVisitor.match
lift_child
uNodeVisitor.lift_child
uNodeVisitor._parse_or_match
rule
uparsimonious\nodes.py
T a.0
line
T a.0
wmaunvisit
T a__class__
T wxu<module parsimonious.nodes>
T aself
other
T aself
expr
full_text
start
end
children
T aself
T ametaclass
name
bases
namespace
unvisit
methods
aGrammar
a__class__
T aself
top_level
ret
T aself
text
pos
method_name
T amethod
rule_string
T arule_string
T aself
node
visited_children
T atext
T aself
node
children
first_child
T aself
text
pos
T aself
error
indent
ret
wnT arule_string
decorator
T aname
T aself
node
method
exc
exc_class
a__spec__
.parsimonious.utils
,
a__str__
ast
literal_eval
uPiggyback on Python's string support so we can have backslash escaping
nd niceties like
, 	, etc.
This also supports:
1. b"strings", allowing grammars to parse bytestrings, in addition to str.
2. r"strings" to simplify regexes.
type
u<Token "%s">
uGeneral tools which don't depend on other parts of Parsimonious
a__doc__
a__file__
origin
has_location
a__cached__
T Oobject
a__prepare__
aStrAndRepr
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
