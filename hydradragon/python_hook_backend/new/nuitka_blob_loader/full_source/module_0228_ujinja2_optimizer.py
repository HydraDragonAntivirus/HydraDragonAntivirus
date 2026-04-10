# Reconstructed from integrated Nuitka blob
# Module: ujinja2.optimizer

a__qualname__
a__init__
uOptimizer.__init__
uOptimizer.generic_visit
a__orig_bases__
ujinja2\optimizer.py
u<module jinja2.optimizer>
T a__class__
T aself
environment
T aself
node
args
kwargs
a__class__
T anode
environment
optimizer
.jinja2.parser
environment
a_tokenize
stream
name
filename
closed
extensions
iter_extensions
tags
extension
parse
self
l
a_last_identifier
a_tag_stack
a_end_token_stack
current
lineno
expected
update
describe_token_expr
u or
repr
q uUnexpected end of template.
uEncountered unknown tag

w.uYou probably made a nesting mistake. Jinja is expecting this tag, but currently looking for
uJinja was looking for the following tags:
message
append
uThe innermost block that needs to be closed is
fail
w a_fail_ut_eof
type
T avariable_end
block_end
rparen
test_any
l a__new__
nodes
aInternalName
aNode
a__init__
fi
T alineno
utag name expected
value
a_statement_keywords
parse_
call
parse_call_block
filter
parse_filter_block
get
pop
fail_unknown_tag
skip_if
T acolon
expect
T ablock_end
subparse
eof
fail_eof
parse_assign_target
T tT awith_namespace
T aassign
parse_tuple
aAssign
parse_filter
T naparse_statements
T T uname:endset
tT adrop_needle
aAssignBlock
T uname:for
T T uname:in
T aextra_end_rules
T uname:in
T FT uname:recursive
T awith_condexpr
extra_end_rules
T uname:if
parse_expression
T uname:recursive
T T uname:endfor
uname:else
endfor
T T uname:endfor
taFor
aIf
T FT awith_condexpr
node
test
T T uname:elif
uname:else
uname:endif
body
elif_
else_
T uname:elif
result
T uname:else
T T uname:endif
taWith
block_end
targets
T acomma
set_ctx
T aparam
values
T T uname:endwith
taScopedEvalContextModifier
aKeyword
autoescape
options
T T uname:endautoescape
taScope
aBlock
T aname
T uname:scoped
scoped
T uname:required
required
sub
T uBlock names in Jinja have to be valid Python identifiers and may not contain hyphens, use an underscore instead.
T T uname:endblock
taOutput
T uRequired blocks can only contain comments or whitespace
uname:
aTemplateData
data
isspace
u<genexpr>
uParser.parse_block.<locals>.<genexpr>
aExtends
template
T uname:with
uname:without
look
T uname:context
with
with_context
skip
aInclude
T uname:ignore
T uname:missing
ignore_missing
T l aparse_import_context
aImport
T uname:as
T aname_only
target
aFromImport
T uname:import
names
parse_context
uParser.parse_from.<locals>.parse_context
startswith
T w_unames starting with an underline can not be imported
aTemplateAssertionError
T aexc
comma
P awith
without
args
defaults
T alparen
rparen
T unon-default argument follows default argument
T arparen
aCallBlock
lparen
parse_signature
aCall
uexpected call
T T uname:endcall
taFilterBlock
T ntT astart_inline
T T uname:endfilter
taMacro
T T uname:endmacro
taName
store
T asimplified
extra_end_rules
with_namespace
parse_primary
T astore
can_assign
ucan't assign to
a__name__
lower
parse_condexpr
parse_or
aCondExpr
expr1
parse_and
T uname:or
aOr
left
parse_not
T uname:and
aAnd
T uname:not
aNot
parse_compare
parse_math1
a_compare_operators
ops
aOperand
in
notin
aCompare
parse_concat
T aadd
sub
a_math_nodes
parse_math2
tilde
aConcat
parse_pow
T amul
div
floordiv
mod
parse_unary
pow
aPow
aNeg
add
aPos
parse_postfix
parse_filter_expr
T atrue
false
aTrue
aFalse
aConst
T atrue
aTrue
T anone
aNone
dot
aNSRef
load
string
buf
T ainteger
float
T aexplicit_parentheses
lbracket
parse_list
lbrace
parse_dict
uunexpected
describe_token
uParser.parse_tuple.<locals>.parse
is_tuple_end
extra_end_rules
is_tuple
uExpected an expression, got
aTuple
with_namespace
with_condexpr
T albracket
rbracket
items
T arbracket
aList
T albrace
rbrace
aPair
T arbrace
aDict
parse_subscript
parse_call
pipe
is
parse_test
aGetattr
integer
uexpected name or number
aGetitem
parse_subscribed
uexpected subscript expression
colon
T arbracket
comma
aSlice
ensure
uParser.parse_call_args.<locals>.ensure
require_comma
mul
dyn_args
dyn_kwargs
assign
kwargs
uinvalid syntax for function call expression
token
parse_call_args
utoo many values to unpack (expected 4)
start_inline
aFilter
P astring
integer
lbracket
name
float
lparen
lbrace
T uname:else
uname:or
uname:and
T uname:is
T uYou cannot chain multiple tests with is
aTest
flush_data
uParser.subparse.<locals>.flush_data
add_data
variable_begin
T avariable_end
block_begin
parse_statement
extend
uinternal parsing error
data_buffer
:nnnaTemplate
D alineno
l aset_environment
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
typing
wtT anodes
exceptions
T aTemplateAssertionError
T aTemplateSyntaxError
aTemplateSyntaxError
lexer
T adescribe_token
T adescribe_token_expr
aTypeVar
a_ImportInclude
a_MacroCall
P amacro
set
for
from
autoescape
if
import
extends
include
print
block
with
P ane
gteq
eq
lt
gt
lteq
aAdd
aSub
aMul
div
aDiv
floordiv
aFloorDiv
mod
aMod
