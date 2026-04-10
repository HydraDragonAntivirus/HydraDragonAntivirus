# Reconstructed from integrated Nuitka blob
# Module: uparsimonious.expressions

uexpression.<locals>.AdHocExpression
a__qualname__
a_uncached_match
uexpression.<locals>.AdHocExpression._uncached_match
a_as_rhs
uexpression.<locals>.AdHocExpression._as_rhs
a__orig_bases__
T aname
uTurn a plain callable into an Expression.
The callable can be of this simple form::
def foo(text, pos):
'''If this custom expression matches starting at text[pos], return
the index where it stops matching. Otherwise, return None.'''
if the expression matched:
return end_pos
If there child nodes to return, return a tuple::
return end_pos, children
If the expression doesn't match at the given ``pos`` at all... ::
return None
If your callable needs to make sub-calls to other rules in the grammar or
do error reporting, it can take this form, gaining additional arguments::
def foo(text, pos, cache, error, grammar):
# Call out to other rules:
node = grammar['another_rule'].match_core(text, pos, cache, error)
...
# Return values as above.
The return value of the callable, if an int or a tuple, will be
utomatically transmuted into a :class:`~parsimonious.Node`. If it returns
a Node-like class directly, it will be passed through unchanged.
:arg rule_name: The rule name to attach to the resulting
:class:`~parsimonious.Expression`
:arg grammar: The :class:`~parsimonious.Grammar` this expression will be a
part of, to make delegating to other rules possible
is_simple
grammar
aNode
text
pos
T achildren
u{custom function "%s"}
name
identity_tuple
a_eq_check_cycles
add
match
T apos
end
aIncompleteParseError
uReturn a parse tree of ``text``.
Raise ``ParseError`` if the expression wasn't satisfied. Raise
``IncompleteParseError`` if the expression was satisfied but didn't
consume the full string.
aParseError
match_core
defaultdict
T Odict
uReturn the parse tree matching this expression at the given
position, not necessarily extending all the way to the end of ``text``.
Raise ``ParseError`` if there is no match there.
:arg pos: The index at which to start matching
aIN_PROGRESS
aLeftRecursionError
T apos
expr
expr
uInternal guts of ``match()``
This is appropriate to call only from custom rules or Expression
subclasses.
:arg cache: The packrat cache::
{(oid, pos): Node tree matched by object `oid` at index `pos` ...}
:arg error: A ParseError instance with ``text`` already filled in but
otherwise blank. We update the error reporting info on this object
s we go. (Sticking references on an existing instance is faster
than allocating a new one for each expression that fails.) We
return None rather than raising and catching ParseErrors because
catching is slow.
u<%s %s>
as_rule
strip
startswith
T w(aendswith
T w):l q nu%s = %s
rhs
uReturn the left- and right-hand sides of a rule that represents me.
Return unicode. If I have no ``name``, omit the left-hand side.
members
uReturn an iterable of my unicode-represented children, stopping
descent when we hit a named node so the returned value resembles the
input rule.
uReturn the right-hand side of a rule that represents me.
Implemented by subclasses.
a__class__
a__init__
literal
type
re
compile
wIwLwMwSwUwXwAaspan
aRegexNode
uReturn length of match, ``None`` if no match.
ilmsuxa

;l l l uReturn the textual equivalent of numerically encoded regex flags.
bits
flags
u<genexpr>
uRegex._regex_flags_from_bits.<locals>.<genexpr>
u~{!r}{}
pattern
a_regex_flags_from_bits
u``members`` is a sequence of expressions.
resolve_refs
rule_map
uCompound.resolve_refs.<locals>.<genexpr>
checked
uCompound._eq_check_cycles.<locals>.<genexpr>
new_pos
cache
error
children
start
u({0})
w a_unicode_members
u /
negativity
u%s%s
w!w&aLookahead
D anegative
tamin
max
self
w?Z w*w+u{%d,}
u{,%d}
u{%d,%d}
aQuantifier
T aname
min
max
uSubexpressions that make up a parsed grammar
These do the parsing.
a__doc__
a__file__
origin
has_location
a__cached__
collections
T adefaultdict
inspect
T agetfullargspec
isfunction
ismethod
ismethoddescriptor
regex
uparsimonious.exceptions
T aParseError
aIncompleteParseError
aLeftRecursionError
uparsimonious.nodes
T aNode
aRegexNode
uparsimonious.utils
T aStrAndRepr
aStrAndRepr
is_callable
expression
uA thing that can be matched against a piece of text
a__slots__
T u
uExpression.__init__
a__hash__
uExpression.__hash__
a__eq__
uExpression.__eq__
a__ne__
uExpression.__ne__
uExpression._eq_check_cycles
uExpression.resolve_refs
T l
parse
uExpression.parse
uExpression.match
uExpression.match_core
a__str__
uExpression.__str__
uExpression.as_rule
uExpression._unicode_members
uExpression._as_rhs
aLiteral
uA string literal
Use these if you can; they're the fastest.
uLiteral.__init__
uLiteral._uncached_match
uLiteral._as_rhs
aTokenMatcher
uAn expression matching a single token of a given type
This is for use only with TokenGrammars.
uTokenMatcher._uncached_match
aRegex
uAn expression that matches what a regex does.
Use these as much as you can and jam as much into each one as you can;
they're fast.
T u
FppppppuRegex.__init__
uRegex._uncached_match
uRegex._regex_flags_from_bits
uRegex._as_rhs
aCompound
uAn abstract expression which contains other expressions
uCompound.__init__
uCompound.resolve_refs
uCompound._eq_check_cycles
uCompound.__hash__
aSequence
uA series of expressions that must match contiguous, ordered pieces of
the text
In other words, it's a concatenation operator: each piece has to match, one
fter another.
uSequence._uncached_match
uSequence._as_rhs
aOneOf
uA series of expressions, one of which must match
Expressions are tested in order from first to last. The first to succeed
wins.
uOneOf._uncached_match
uOneOf._as_rhs
uAn expression which consumes nothing, even if its contained expression
succeeds
D anegative
FuLookahead.__init__
uLookahead._uncached_match
uLookahead._as_rhs
uLookahead._eq_check_cycles
aNot
uAn expression wrapper like the */+/?/{n,m} quantifier in regexes.
float
T ainf
uQuantifier.__init__
uQuantifier._uncached_match
uQuantifier._as_rhs
uQuantifier._eq_check_cycles
aZeroOrMore
T u
l aOneOrMore
aOptional
uparsimonious\expressions.py
T a.0
wmamo
checked
T a__class__
T a.0
wmarule_map
T a.0
wiabits
flags
u<module parsimonious.expressions>
T aterm
T amember
name
min
T amember
name
T aself
other
T aself
T aself
members
kwargs
a__class__
T aself
name
T aself
literal
name
a__class__
T aself
member
negative
kwargs
a__class__
T aself
member
min
max
name
kwargs
a__class__
T aself
pattern
name
ignore_case
locale
multiline
dot_all
unicode
verbose
ascii
a__class__
T aself
qualifier
T aself
callable
T acallable
T aself
other
checked
a__class__
T aself
other
checked
T aself
bits
flags
T aself
text
pos
cache
error
T aself
text
pos
cache
error
node
T aself
text
pos
cache
error
wmanode
T
self
text
pos
cache
error
new_pos
children
size
node
length
T aself
text
pos
cache
error
wmaspan
node
T
self
text
pos
cache
error
new_pos
children
wmanode
length
T aself
token_list
pos
cache
error
T aself
text
pos
cache
error
result
end
children
is_simple
callable
grammar
T acallable
grammar
is_simple
T aself
rhs
T acallable
rule_name
grammar
num_args
is_simple
aAdHocExpression
T avalue
criteria
T aself
text
pos
error
node
T aself
text
pos
cache
error
expr_cache
node
T aself
text
pos
node
T aself
rule_map
a__spec__
.parsimonious.grammar
3
is_callable
expression
self
a_expressions_from_rules
a__class__
a__init__
items
default_rule
uConstruct a grammar.
:arg rules: A string of production rules, one per line.
:arg default_rule: The name of the rule invoked when you call
:meth:`parse()` or :meth:`match()` on the grammar. Defaults to the
first rule. Falls back to None if there are no string-based rules
in this grammar.
:arg more_rules: Additional kwargs whose names are rule names and
values are Expressions or custom-coded callables which accomplish
things the built-in rule syntax cannot. These take precedence over
``rules`` in case of naming conflicts.
a_copy
uReturn a new Grammar whose :term:`default rule` is ``rule_name``.
aGrammar
a__new__
uReturn a shallow copy of myself.
Deep is unnecessary, since Expression trees are immutable. Subgrammars
recreate all the Expressions from scratch, and AbstractGrammars have
no Expressions.
rule_grammar
parse
aRuleVisitor
visit
uReturn a 2-tuple: a dict of rule names pointing to their
expressions, and then the first rule.
It's a web of expressions, all referencing each other. Typically,
there's a single root to the web of references, and that root is the
starting symbol for parsing, but there's nothing saying you can't have
multiple roots.
:arg custom_rules: A map of rule names to custom-coded rules:
Expressions
a_check_default_rule
T apos
uParse some text with the :term:`default rule`.
:arg pos: The index at which to start parsing
match
uParse some text with the :term:`default rule` but not necessarily
ll the way to the end.
:arg pos: The index at which to start parsing
uCan't call parse() on a Grammar that has no default rule. Choose a specific rule instead, like some_grammar['some_rule'].parse(...).
uRaise RuntimeError if there is no default rule defined.
values
w
uReturn a rule string that, when passed to the constructor, would
reconstitute the grammar.
u<genexpr>
uGrammar.__str__.<locals>.<genexpr>
as_rule
uGrammar({!r})
uReturn an expression that will reconstitute the grammar.
aTokenRuleVisitor
aRegex
T u#[^\r\n]*
comment
T aname
aOneOf
T u\s+
D aname
meaninglessness
aZeroOrMore
D aname
w_aSequence
aLiteral
T w=D aname
equals
T u[a-zA-Z_][a-zA-Z_0-9]*
D aname
label
aNot
D aname
reference
T u[*+?]
D aname
quantifier
T uu?r?"[^"\\]*(?:\\.[^"\\]*)*"
tpaspaceless_literal
T aignore_case
dot_all
name
D aname
literal
T w~T u[ilmsuxa]*
tT aignore_case
D aname
regex
D aname
atom
D aname
quantified
D aname
term
T w!D aname
not_term
members
aOneOrMore
D aname
sequence
T w/D aname
or_term
D aname
ored
D aname
expression
D aname
rule
D aname
rules
uReturn the rules for parsing the grammar definition syntax.
Return a 2-tuple: a dict of rule names pointing to their expressions,
nd then the top-level expression for the first rule.
cur
seen
aBadGrammar
uCircular Reference resolving
name

w=w.aadd
aUndefinedLabel
aLazyReference

Traverse the rule map following top-level lazy references,
until we reach a cycle (raise an error) or a concrete expression.
For example, the following is a circular reference:
foo = bar
baz = foo2
foo2 = foo
Note that every RHS of a grammar rule _must_ be either a
LazyReference or a concrete expression, so the reference chain will
eventually either terminate or find a cycle.
u<LazyReference to %s>
custom_rules
a_last_literal_node_and_type
uConstruct.
:arg custom_rules: A dict of {rule name: expression} holding custom
rules which will take precedence over the others
uTreat a parenthesized subexpression as just its contents.
Its position in the tree suffices to maintain its grouping semantics.
uTurn a quantifier into just its symbol-matching node.
quantifier_classes
text
:l q nasplit
T w,Z aQuantifier
T amin
max
aLookahead
uAssign a name to the Expression and return it.
uA parsed Sequence looks like [term node, OneOrMore node of
``another_term``s]. Flatten it out.
uReturn just the term from an ``or_term``.
We already know it's going to be ored, from the containing ``ored``.
uTurn a label into a unicode string.
uStick a :class:`LazyReference` in the tree as a placeholder.
We resolve them all later.
upper
literal
wIwLwMwSwUwXwAT aignore_case
locale
multiline
dot_all
unicode
verbose
ascii
uReturn a ``Regex`` expression.
evaluate_string
dedent
u                    Found
u (
u) and
u) string literals.
All strings in a single grammar must be of the same type.
uTurn a string literal into a ``Literal`` that recognizes it.
uPick just the literal out of a literal-and-junk combo.
uReplace childbearing nodes with a list of their children; keep
others untouched.
For our case, if a node has children, only the children are important.
Otherwise, keep the node around for (for example) the flags of the
regex rule. Most of these kept-around nodes are subsequently thrown
way by the other visitor methods.
We can't simply hang the visited children off the original node; that
would be disastrous if the node occurred in more than one place in the
tree.
aOrderedDict
update
resolve_refs
rule_map
uCollate all the rules into a map. Return (map, default rule).
The default rule is the first one. Or, if you have more than one rule
of that name, it's the last-occurring rule of that name. (This lets you
override the default rule when you extend a grammar.) If there are no
string-based rules, the default rule is None, because the custom rules,
due to being kwarg-based, are unordered.
uRuleVisitor.visit_rules.<locals>.<genexpr>
aTokenMatcher
uTurn a string literal into a ``TokenMatcher`` that matches
``Token`` objects by their ``type`` attributes.
T uRegexes do not make sense in TokenGrammars, since TokenGrammars operate on pre-lexed tokens rather than characters.
uA convenience which constructs expression trees from an easy-to-read syntax
Use this unless you have a compelling reason not to; it performs some
optimizations that would be tedious to do when constructing an expression tree
by hand.
a__doc__
a__file__
origin
has_location
a__cached__
collections
T aOrderedDict
textwrap
T adedent
uparsimonious.exceptions
T aBadGrammar
aUndefinedLabel
uparsimonious.expressions
TaLiteral
aRegex
aSequence
aOneOf
aLookahead
aQuantifier
aOptional
aZeroOrMore
aOneOrMore
aNot
aTokenMatcher
expression
is_callable
aOptional
uparsimonious.nodes
T aNodeVisitor
aNodeVisitor
uparsimonious.utils
T aevaluate_string
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
