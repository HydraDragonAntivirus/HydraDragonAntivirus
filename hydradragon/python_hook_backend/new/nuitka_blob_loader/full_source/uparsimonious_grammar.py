# Reconstructed from integrated Nuitka blob
# Module: uparsimonious.grammar

uA collection of rules that describe a language
You can start parsing from the default rule by calling ``parse()``
directly on the ``Grammar`` object::
g = Grammar('''
polite_greeting = greeting ", my good " title
greeting        = "Hi" / "Hello"
title           = "madam" / "sir"
''')
g.parse('Hello, my good sir')
Or start parsing from any of the other rules; you can pull them out of the
grammar as if it were a dictionary::
g['title'].parse('sir')
You could also just construct a bunch of ``Expression`` objects yourself
nd stitch them together into a language, but using a ``Grammar`` has some
important advantages:
* Languages are much easier to define in the nice syntax it provides.
* Circular references aren't a pain.
* It does all kinds of whizzy space- and time-saving optimizations, like
factoring up repeated subexpressions into a single object, which should
increase cache hit ratio. [Is this implemented yet?]
a__qualname__
T u
uGrammar.__init__
default
uGrammar.default
uGrammar._copy
uGrammar._expressions_from_rules
T l
uGrammar.parse
uGrammar.match
uGrammar._check_default_rule
a__str__
uGrammar.__str__
a__repr__
uGrammar.__repr__
a__orig_bases__
aTokenGrammar
uA Grammar which takes a list of pre-lexed tokens instead of text
This is useful if you want to do the lexing yourself, as a separate pass:
for example, to implement indentation-based languages.
uTokenGrammar._expressions_from_rules
aBootstrappingGrammar
uThe grammar used to recognize the textual rules that describe other
grammars
This grammar gets its start from some hard-coded Expressions and claws its
way from there to an expression tree that describes how to parse the
grammar description syntax.
uBootstrappingGrammar._expressions_from_rules

# Ignored things (represented by _) are typically hung off the end of the
# leafmost kinds of nodes. Literals like "/" count as leaves.
rules = _ rule*
rule = label equals expression
equals = "=" _
literal = spaceless_literal _
# So you can't spell a regex like `~"..." ilm`:
spaceless_literal = ~"u?r?b?\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\""is /
~"u?r?b?'[^'\\\\]*(?:\\\\.[^'\\\\]*)*'"is
expression = ored / sequence / term
or_term = "/" _ term
ored = term or_term+
sequence = term term+
not_term = "!" term _
lookahead_term = "&" term _
term = not_term / lookahead_term / quantified / atom
quantified = atom quantifier
tom = reference / literal / regex / parenthesized
regex = "~" spaceless_literal ~"[ilmsuxa]*"i _
parenthesized = "(" _ expression ")" _
quantifier = ~r"[*+?]|\{\d*,\d+\}|\{\d+,\d*\}|\{\d+\}" _
reference = label !equals
# A subsequent equal sign is the only thing that distinguishes a label
# (which begins a new rule) from a reference (which is just a pointer to a
# rule defined somewhere else):
label = ~"[a-zA-Z_][a-zA-Z_0-9]*(?![\"'])" _
# _ = ~r"\s*(?:#[^\r\n]*)?\s*"
_ = meaninglessness*
meaninglessness = ~r"\s+" / comment
comment = ~r"#[^\r\n]*"
rule_syntax
T Ostr
uA lazy reference to a rule, which we resolve after grokking all the
rules
uLazyReference.resolve_refs
a_as_rhs
uLazyReference._as_rhs
uTurns a parse tree of a grammar definition into a map of ``Expression``
objects
This is the magic piece that breathes life into a parsed bunch of parse
rules, allowing them to go forth and parse other things.
w?w*w+alift_child
visit_expression
visit_term
visit_atom
T nuRuleVisitor.__init__
visit_parenthesized
uRuleVisitor.visit_parenthesized
visit_quantifier
uRuleVisitor.visit_quantifier
visit_quantified
uRuleVisitor.visit_quantified
visit_lookahead_term
uRuleVisitor.visit_lookahead_term
visit_not_term
uRuleVisitor.visit_not_term
visit_rule
uRuleVisitor.visit_rule
visit_sequence
uRuleVisitor.visit_sequence
visit_ored
uRuleVisitor.visit_ored
visit_or_term
uRuleVisitor.visit_or_term
visit_label
uRuleVisitor.visit_label
visit_reference
uRuleVisitor.visit_reference
visit_regex
uRuleVisitor.visit_regex
visit_spaceless_literal
uRuleVisitor.visit_spaceless_literal
visit_literal
uRuleVisitor.visit_literal
generic_visit
uRuleVisitor.generic_visit
visit_rules
uRuleVisitor.visit_rules
uA visitor which builds expression trees meant to work on sequences of
pre-lexed tokens rather than strings
uTokenRuleVisitor.visit_spaceless_literal
uTokenRuleVisitor.visit_regex
uparsimonious\grammar.py
T a.0
expr
T a.0
expr
self
u<module parsimonious.grammar>
T a__class__
T aself
rules
more_rules
decorated_custom_rules
exprs
first
a__class__
T aself
custom_rules
T aself
T aself
exprs
T aself
new
a__class__
T aself
rule_syntax
custom_rules
comment
meaninglessness
w_aequals
label
reference
quantifier
spaceless_literal
literal
regex
atom
quantified
term
not_term
sequence
or_term
ored
expression
rule
rules
rule_tree
T aself
rules
custom_rules
tree
T aself
rule_name
new
T aself
node
visited_children
T aself
text
pos
T aself
rule_map
seen
cur
T aself
node
label
name
w_T aself
node
literal
spaceless_literal
w_T aself
node
lookahead_term
ampersand
term
w_T aself
node
not_term
exclamation
term
w_T aself
node
or_term
slash
w_aterm
T aself
node
ored
first_term
other_terms
T aself
node
parenthesized
left_paren
w_aexpression
right_paren
T aself
node
quantified
atom
quantifier
min_match
max_match
T aself
node
quantifier
symbol
w_T aself
node
reference
label
not_equals
T aself
node
regex
tilde
literal
flags
w_apattern
T aself
node
regex
tilde
literal
flags
w_T aself
node
rule
label
equals
expression
T aself
node
rules_list
w_arules
rule_map
name
rule
T aself
node
sequence
term
other_terms
T aself
spaceless_literal
visited_children
literal_value
last_node
last_type
T aself
spaceless_literal
visited_children
a__spec__
.parsimonious.nodes
m
expr
full_text
start
end
children
name
uSupport looping over my children and doing tuple unpacks on me.
It can be very handy to unpack nodes in arg lists; see
:class:`PegVisitor` for an example.
uReturn the text this node matched.
indent
uNode.prettily.<locals>.indent
u<%s%s matching "%s">%s
a__name__
expr_name
u called "%s"

text
u  <-- *** We were here. ***
ret
prettily
error
T aerror
w
uReturn a unicode, pretty-printed representation of me.
:arg error: The node to highlight because an error occurred there
splitlines

u<genexpr>
uNode.prettily.<locals>.indent.<locals>.<genexpr>
uReturn a compact, human-readable representation of me.
aNode
uSupport by-value deep comparison with other nodes for testing.
us = %r
u%s(%r, s, %s, %s%s)
u, children=[%s]
u,
a__repr__
T FT atop_level
uReturn a bit of code (though not an expression) that will recreate
me.
uRemove any leading "visit_" from a method name.
unvisit
uRuleDecoratorMeta.__new__.<locals>.unvisit
items
a_rule
isfunction
uparsimonious.grammar
T aGrammar
aGrammar
sort
u<lambda>
uRuleDecoratorMeta.__new__.<locals>.<lambda>
T akey
grammar
aRuleDecoratorMeta
a__new__
startswith
T avisit_
:l nna__code__
co_firstlineno
u{name} = {expr}
T aname
expr
uRuleDecoratorMeta.__new__.<locals>.<genexpr>
visit_
generic_visit
self
visit
aVisitationError
aUndefinedLabel
unwrapped_exceptions
uWalk a parse tree, transforming it into another representation.
Recursively descend a parse tree, dispatching to the method named after
the rule in the :class:`~parsimonious.grammar.Grammar` that produced
each node. If, for example, a rule was... ::
bold = '<b>'
...the ``visit_bold()`` method would be called. It is your
responsibility to subclass :class:`NodeVisitor` and implement those
methods.
uNo visitor method was defined for this expression: %s
as_rule
uDefault visitor method
:arg node: The node we're visiting
:arg visited_children: The results of visiting the children of that
node, in a list
I'm not sure there's an implementation of this that makes sense across
ll (or even most) use cases, so we leave it to subclasses to implement
for now.
a_parse_or_match
parse
uParse some text with this Visitor's default grammar and return the
result of visiting it.
``SomeVisitor().parse('some_string')`` is a shortcut for
``SomeVisitor().visit(some_grammar.parse('some_string'))``.
match
uParse and visit some text with this Visitor's default grammar, but
don't insist on parsing all the way to the end.
``SomeVisitor().match('some_string')`` is a shortcut for
``SomeVisitor().visit(some_grammar.match('some_string'))``.
uLift the sole child of ``node`` up to replace the node.
uThe {cls}.{method}() shortcut won't work because {cls} was never associated with a specific grammar. Fill out its `grammar` attribute, and try again.
T acls
method
T apos
uExecute a parse or match on the default grammar, followed by a
visitation.
Raise RuntimeError if there is no default grammar specified.
decorator
urule.<locals>.decorator
uDecorate a NodeVisitor ``visit_*`` method to tie a grammar rule to it.
The following will arrange for the ``visit_digit`` method to receive the
results of the ``~"[0-9]"`` parse rule::
@rule('~"[0-9]"')
def visit_digit(self, node, visited_children):
...
Notice that there is no "digit = " as part of the rule; that gets inferred
from the method name.
In cases where there is only one kind of visitor interested in a grammar,
using ``@rule`` saves you having to look back and forth between the visitor
nd the grammar definition.
On an implementation level, all ``@rule`` rules get stitched together into
a :class:`~parsimonious.Grammar` that becomes the NodeVisitor's
:term:`default grammar`.
Typically, the choice of a default rule for this grammar is simple: whatever
``@rule`` comes first in the class is the default. But the choice may become
surprising if you divide the ``@rule`` calls among subclasses. At the
moment, which method "comes first" is decided simply by comparing line
numbers, so whatever method is on the smallest-numbered line will be the
default. In a future release, this will change to pick the
first ``@rule`` call on the basemost class that has one. That way, a
subclass which does not override the default rule's ``visit_*`` method
won't unintentionally change which rule is the default.
rule_string
uNodes that make up parse trees
Parsing spits out a tree of these, which you can then tell to walk itself and
spit out a useful value. Or you can walk it yourself; the structural attributes
re public.
a__doc__
a__file__
origin
has_location
a__cached__
inspect
T aisfunction
version_info
exc_info
uparsimonious.exceptions
T aVisitationError
aUndefinedLabel
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
