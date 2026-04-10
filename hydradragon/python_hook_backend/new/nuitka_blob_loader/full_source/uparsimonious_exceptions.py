# Reconstructed from integrated Nuitka blob
# Module: uparsimonious.exceptions

uA call to ``Expression.parse()`` or ``match()`` didn't match.
a__qualname__
T q nuParseError.__init__
a__str__
uParseError.__str__
uParseError.line
uParseError.column
a__orig_bases__
aLeftRecursionError
uLeftRecursionError.__str__
aIncompleteParseError
uA call to ``parse()`` matched a whole Expression but did not consume the
entire text.
uIncompleteParseError.__str__
T EException
aVisitationError
uSomething went wrong while traversing a parse tree.
This exception exists to augment an underlying exception with information
bout where in the parse tree the error occurred. Otherwise, it could be
tiresome to figure out what went wrong; you'd have to play back the whole
tree traversal in your head.
uVisitationError.__init__
aBadGrammar
uSomething was wrong with the definition of a grammar.
Note that a ParseError might be raised instead if the error is in the
grammar definition syntax.
aUndefinedLabel
uA rule referenced in a grammar was never defined.
Circular references and forward references are okay, but you have to define
stuff at some point.
uUndefinedLabel.__init__
uUndefinedLabel.__str__
uparsimonious\exceptions.py
u<module parsimonious.exceptions>
T a__class__
T aself
text
pos
expr
T aself
label
T aself
exc
exc_class
node
a__class__
T aself
T aself
rule_name
window
T aself
rule_name
a__spec__
.parsimonious.expressions
isfunction
ismethod
ismethoddescriptor
value
a__func__
getfullargspec
callable
args
uCustom rule functions must take either 2 or 5 arguments, not %s.
aExpression
a__prepare__
aAdHocExpression
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
