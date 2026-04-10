# Reconstructed from integrated Nuitka blob
# Module: ujinja2.idtracking

a__qualname__
T nna__init__
uSymbols.__init__
uSymbols.analyze_node
uSymbols._define_ref
uSymbols.find_load
uSymbols.find_ref
ref
uSymbols.ref
uSymbols.copy
uSymbols.store
uSymbols.declare_parameter
uSymbols.load
uSymbols.branch_update
dump_stores
uSymbols.dump_stores
dump_param_targets
uSymbols.dump_param_targets
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
uRootVisitor.__init__
a_simple_visit
uRootVisitor._simple_visit
visit_Template
visit_Block
visit_Macro
visit_FilterBlock
visit_Scope
visit_If
visit_ScopedEvalContextModifier
visit_AssignBlock
uRootVisitor.visit_AssignBlock
visit_CallBlock
uRootVisitor.visit_CallBlock
visit_OverlayScope
uRootVisitor.visit_OverlayScope
T abody
visit_For
uRootVisitor.visit_For
visit_With
uRootVisitor.visit_With
uRootVisitor.generic_visit
a__orig_bases__
uFrameSymbolVisitor.__init__
T Favisit_Name
uFrameSymbolVisitor.visit_Name
visit_NSRef
uFrameSymbolVisitor.visit_NSRef
uFrameSymbolVisitor.visit_If
uFrameSymbolVisitor.visit_Macro
visit_Import
uFrameSymbolVisitor.visit_Import
visit_FromImport
uFrameSymbolVisitor.visit_FromImport
visit_Assign
uFrameSymbolVisitor.visit_Assign
uFrameSymbolVisitor.visit_For
uFrameSymbolVisitor.visit_CallBlock
uFrameSymbolVisitor.visit_FilterBlock
uFrameSymbolVisitor.visit_With
uFrameSymbolVisitor.visit_AssignBlock
uFrameSymbolVisitor.visit_Scope
uFrameSymbolVisitor.visit_Block
uFrameSymbolVisitor.visit_OverlayScope
ujinja2\idtracking.py
u<module jinja2.idtracking>
T a__class__
T aself
symbols
T aself
parent
level
T aself
name
load
ident
T aself
node
kwargs
child
T aself
node
kwargs
visitor
T aself
branch_symbols
stores
branch
sym
name
target
outer_target
T aself
rv
T aself
name
T aself
node
rv
target
instr
w_T aself
rv
node
name
T aself
target
T anodes
parent_symbols
sym
visitor
node
T aself
node
args
kwargs
T anodes
rv
subnode
original_symbols
self
kwargs
T akwargs
original_symbols
self
T aself
name
rv
T aself
name
outer_ref
T anode
parent_symbols
sym
T aself
node
kwargs
T aself
node
for_branch
kwargs
branch
item
T aself
node
kwargs
name
T aself
node
kwargs
original_symbols
inner_visit
body_symbols
elif_symbols
else_symbols
T aself
node
store_as_param
kwargs
T aself
node
kwargs
target
T aself
node
kwargs
target
child
.jinja2.lexer
re
escape
u<genexpr>
reverse_operators
aTOKEN_COMMENT_BEGIN
ubegin of comment
aTOKEN_COMMENT_END
uend of comment
aTOKEN_COMMENT
comment
aTOKEN_LINECOMMENT
aTOKEN_BLOCK_BEGIN
ubegin of statement block
aTOKEN_BLOCK_END
uend of statement block
aTOKEN_VARIABLE_BEGIN
ubegin of print statement
aTOKEN_VARIABLE_END
uend of print statement
aTOKEN_LINESTATEMENT_BEGIN
ubegin of line statement
aTOKEN_LINESTATEMENT_END
uend of line statement
aTOKEN_DATA
utemplate data / text
aTOKEN_EOF
uend of template
type
aTOKEN_NAME
value
a_describe_token_type
w:asplit
T w:l utoo many values to unpack (expected 2)
newline_re
findall
comment_start_string
block_start_string
variable_start_string
line_statement_prefix
u^[ \t\v]*
line_comment_prefix
aTOKEN_LINECOMMENT_BEGIN
u(?:^|(?<=\S))[^\S\r\n]*
sorted
D areverse
t:l nnamessage
error_class
describe_token
self
test
uToken.test_any.<locals>.<genexpr>
stream
current
close
a_iter
deque
a_pushed
name
filename
closed
aToken
l aTOKEN_INITIAL

aTokenStreamIterator
append
push
next_if
popleft
lineno
describe_token_expr
aTemplateSyntaxError
uunexpected end of template, expected
w.uexpected token
u, got
block_end_string
variable_end_string
comment_end_string
trim_blocks
lstrip_blocks
newline_sequence
keep_trailing_newline
a_lexer_cache
get
aLexer
a__class__
a__new__
wcuLexer.__init__.<locals>.c
a_Rule
whitespace_re
aTOKEN_WHITESPACE
float_re
aTOKEN_FLOAT
integer_re
aTOKEN_INTEGER
name_re
string_re
aTOKEN_STRING
operator_re
aTOKEN_OPERATOR
compile_rules
u\n?
u(?P<raw_begin>
u(\-|\+|)\s*raw\s*(?:\-
u\s*|
u))
w|u(?P<
w>u(\-|\+|))
root
u(.*?)(?:
w)aOptionalLStrip
u#bygroup
T u.+
u(.*?)((?:\+
u|\-
u#pop
T u(.)
aFailure
T uMissing end of comment tag
u(?:\+
u\-
aTOKEN_RAW_BEGIN
u(.*?)((?:
u(\-|\+|))\s*endraw\s*(?:\+
aTOKEN_RAW_END
T uMissing end of raw directive
T u\s*(\n|$)
T u(.*?)()(?=\n|$)
aTOKEN_LINECOMMENT_END
rules
compile
wMwSasub
tokeniter
aTokenStream
wrap
utoo many values to unpack (expected 3)
ignored_tokens
a_normalize_newlines
keyword
isidentifier
uInvalid character in identifier
:l q naencode
T aascii
backslashreplace
decode
T uunicode-escape
T w:q astrip
replace
T w_u
l
literal_eval
operators
uLexer.wrap
source
:nnl w
state
a_begin
statetokens
match
pos
balancing_stack
groups
:l nl w-arstrip
count
T w
w+agroupdict
rfind
line_starting
fullmatch
wmaitems
u wanted to resolve the token dynamically but no group matched
ignore_if_empty
newlines_stripped
group
w{w}w(w[w]T w}w)w]uunexpected '
w'u', expected '
:q nnaend
stack
u wanted to resolve the new state dynamically but no group matched
u yielded empty string without stack change
uunexpected char
u at
uLexer.tokeniter
uLexer.tokeniter.<locals>.<genexpr>
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
wtaast
T aliteral_eval
collections
T adeque
intern
a_identifier
T apattern
pattern
exceptions
T aTemplateSyntaxError
utils
T aLRUCache
aLRUCache
T l2T u\s+
T u(\r\n|\r|\n)
u('([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")

(
0b(_?[0-1])+ # binary
|
0o(_?[0-7])+ # octal
|
0x(_?[\da-f])+ # hex
|
[1-9](_?\d)* # decimal
|
0(_?0)* # decimal zero
)
aIGNORECASE
aVERBOSE

(?<!\.)  # doesn't start with a .
(\d+_)*\d+  # digits, possibly _ separated
(
(\.(\d+_)*\d+)?  # optional fractional part
e[+\-]?(\d+_)*\d+  # exponent part
|
\.(\d+_)*\d+  # required fractional part
)
T aadd
aTOKEN_ADD
T aassign
aTOKEN_ASSIGN
T acolon
aTOKEN_COLON
T acomma
aTOKEN_COMMA
T adiv
aTOKEN_DIV
T adot
aTOKEN_DOT
T aeq
aTOKEN_EQ
T afloordiv
aTOKEN_FLOORDIV
T agt
aTOKEN_GT
T agteq
aTOKEN_GTEQ
T albrace
aTOKEN_LBRACE
T albracket
aTOKEN_LBRACKET
T alparen
aTOKEN_LPAREN
T alt
aTOKEN_LT
T alteq
aTOKEN_LTEQ
T amod
aTOKEN_MOD
T amul
aTOKEN_MUL
T ane
aTOKEN_NE
T apipe
aTOKEN_PIPE
T apow
aTOKEN_POW
T arbrace
aTOKEN_RBRACE
T arbracket
aTOKEN_RBRACKET
T arparen
aTOKEN_RPAREN
T asemicolon
aTOKEN_SEMICOLON
T asub
aTOKEN_SUB
T atilde
aTOKEN_TILDE
T awhitespace
T afloat
T ainteger
T aname
T astring
T aoperator
T ablock_begin
T ablock_end
T avariable_begin
T avariable_end
T araw_begin
T araw_end
T acomment_begin
T acomment_end
T acomment
T alinestatement_begin
T alinestatement_end
T alinecomment_begin
T alinecomment_end
T alinecomment
T adata
T ainitial
T aeof
w/u//
w*w%u**
w~u==
u!=
u>=
w<u<=
w=w,w;u<lambda>
T akey
count_newlines
