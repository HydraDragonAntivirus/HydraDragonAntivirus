# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.exceptions


Base exception for any error that occurs during encoding.
a__qualname__
a__orig_bases__
aEncodingTypeError

Raised when trying to encode a python value whose type is not supported for
the output ABI type.
aIllegalValue

Raised when trying to encode a python value with the correct type but with
a value that is not considered legal for the output ABI type.
.. code-block:: python
fixed128x19_encoder(Decimal('NaN'))  # cannot encode NaN
aValueOutOfBounds

Raised when trying to encode a python value with the correct type but with
a value that appears outside the range of valid values for the output ABI
type.
.. code-block:: python
ufixed8x1_encoder(Decimal('25.6'))  # out of bounds
aDecodingError

Base exception for any error that occurs during decoding.
aInsufficientDataBytes

Raised when there are insufficient data to decode a value for a given ABI type.
aNonEmptyPaddingBytes

Raised when the padding bytes of an ABI value are malformed.
aInvalidPointer

Raised when the pointer to a value in the ABI encoding is invalid.
aParseError

Raised when an ABI type string cannot be parsed.
return
str
a__str__
uParseError.__str__
T EValueError
aABITypeError

Raised when a parsed ABI type has inconsistent properties; for example,
when trying to parse the type string ``'uint7'`` (which has a bit-width
that is not congruent with zero modulo eight).
aPredicateMappingError

Raised when an error occurs in a registry's internal mapping.
aNoEntriesFound

Raised when no registration is found for a type string in a registry's
internal mapping.
.. warning::
In a future version of ``eth-abi``, this error class will no longer
inherit from ``ValueError``.
aMultipleEntriesFound

Raised when multiple registrations are found for a type string in a
registry's internal mapping.  This error is non-recoverable and indicates
that a registry was configured incorrectly.  Registrations are expected to
cover completely distinct ranges of type strings.
.. warning::
In a future version of ``eth-abi``, this error class will no longer
inherit from ``ValueError``.
ueth_abi\exceptions.py
u<module eth_abi.exceptions>
T a__class__
T aself
a__spec__
.eth_abi.grammar
lru_cache
T nT amaxsize
a_parse_uncached
parse
aTupleType
T anode
aBasicType
text
expr
expressions
aOneOf
aQuantifier
min
max
uCan only parse string values: got

a__class__
parsimonious
aParseError
u()
uZero-sized tuple types "()" are not supported.
pos

Parses a type string into an appropriate instance of
:class:`~eth_abi.grammar.ABIType`.  If a type string cannot be parsed,
throws :class:`~eth_abi.exceptions.ParseError`.
:param type_str: The type string to be parsed.
:returns: An instance of :class:`~eth_abi.grammar.ABIType` containing
information about the parsed type string.
arrlist
node
w<a__qualname__
w ato_type_str
w>uMust implement `to_type_str`

Returns the string representation of an ABI type.  This will be equal to
the type string from which it was created.
uMust implement `item_type`

If this type is an array type, equal to an appropriate
:class:`~eth_abi.grammar.ABIType` instance for the array's items.
uMust implement `validate`

Validates the properties of an ABI type against the solidity ABI spec:
https://solidity.readthedocs.io/en/develop/abi-spec.html
Raises :class:`~eth_abi.exceptions.ABITypeError` if validation fails.
aABITypeError
uFor '
u' type at column
start
u in '
full_text
u':

Equal to ``True`` if a type is an array type (i.e. if it has an array
dimension list).  Otherwise, equal to ``False``.
uMust implement `is_dynamic`

Equal to ``True`` if a type has a dynamically sized encoding.
Otherwise, equal to ``False``.
is_array
u<genexpr>
uABIType._has_dynamic_arrlist.<locals>.<genexpr>
a__init__
components
w(w,w)uTupleType.to_type_str.<locals>.<genexpr>
uCannot determine item type for non-array type '
w':nq navalidate
a_has_dynamic_arrlist
is_dynamic
uTupleType.is_dynamic.<locals>.<genexpr>
base
sub
wxuBasicType.to_type_str.<locals>.<genexpr>
string
bytes
invalidate
T ustring type cannot have suffix
T ubytes type must have either no suffix or a numerical suffix
l T umaximum 32 bytes for fixed-length bytes
T aint
uint
T uinteger type must have numerical suffix
l l  T uinteger size out of bounds (max 256 bits)
T uinteger size must be multiple of 8
T afixed
ufixed
T ufixed type must have suffix of form <bits>x<exponent>, e.g. 128x19
T ufixed size out of bounds (max 256 bits)
T ufixed size must be multiple of 8
lPufixed exponent size out of bounds,
u must be in 1-80
hash
T uhash type must have numerical suffix
address
T uaddress cannot have suffix
re
escape
aTYPE_ALIAS_RE
u<lambda>
unormalize.<locals>.<lambda>

Normalizes a type string into its canonical version e.g. the type string
'int' becomes 'int256', etc.
:param type_str: The type string to be normalized.
:returns: The canonical version of the input type string.
aTYPE_ALIASES
group
T l
a__doc__
a__file__
origin
has_location
a__cached__
functools
T aexpressions
ueth_abi.exceptions
T aABITypeError
aParseError
aGrammar
T u
type = tuple_type / basic_type
tuple_type = components arrlist?
components = non_zero_tuple
non_zero_tuple = "(" type next_type* ")"
next_type = "," type
basic_type = base sub? arrlist?
base = alphas
sub = two_size / digits
two_size = (digits "x" digits)
rrlist = (const_arr / dynam_arr)+
const_arr = "[" digits "]"
dynam_arr = "[]"
lphas = ~"[A-Za-z]+"
digits = ~"[1-9][0-9]*"
grammar
aNodeVisitor
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
