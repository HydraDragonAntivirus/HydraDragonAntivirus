# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.grammar


Parsimonious node visitor which performs both parsing of type strings and
post-processing of parse trees.  Parsing operations are cached.
uNodeVisitor.__init__
visit_non_zero_tuple
uNodeVisitor.visit_non_zero_tuple
visit_tuple_type
uNodeVisitor.visit_tuple_type
visit_next_type
uNodeVisitor.visit_next_type
visit_basic_type
uNodeVisitor.visit_basic_type
visit_two_size
uNodeVisitor.visit_two_size
visit_const_arr
uNodeVisitor.visit_const_arr
visit_dynam_arr
uNodeVisitor.visit_dynam_arr
visit_alphas
uNodeVisitor.visit_alphas
visit_digits
uNodeVisitor.visit_digits
generic_visit
uNodeVisitor.generic_visit
uNodeVisitor._parse_uncached
a__orig_bases__
visitor

Base class for results of type string parsing operations.
aABIType
T aarrlist
node
a__slots__
T nnuABIType.__init__
a__repr__
uABIType.__repr__
a__eq__
uABIType.__eq__
uABIType.to_type_str
item_type
uABIType.item_type
uABIType.validate
uABIType.invalidate
uABIType.is_array
uABIType.is_dynamic
uABIType._has_dynamic_arrlist

Represents the result of parsing a tuple type string e.g. "(int,bool)".
T acomponents
D anode
nuTupleType.__init__
uTupleType.to_type_str
property
uTupleType.item_type
uTupleType.validate
uTupleType.is_dynamic

Represents the result of parsing a basic type string e.g. "uint", "address",
"ufixed128x19[][2]".
T abase
sub
uBasicType.__init__
uBasicType.to_type_str
uBasicType.item_type
uBasicType.is_dynamic
uBasicType.validate
D aint
uint
fixed
ufixed
function
byte
int256
uint256
fixed128x18
ufixed128x18
bytes24
bytes1
compile
u\b(
w|akeys
u)\b
normalize
ueth_abi\grammar.py
T a.0
waT a.0
dim
T a.0
wsT a.0
wcT amatch
u<module eth_abi.grammar>
T a__class__
T aself
other
T aself
arrlist
node
T aself
base
sub
arrlist
node
a__class__
T aself
T aself
components
arrlist
node
a__class__
T aself
type_str
kwargs
wea__class__
T aself
node
visited_children
expr
T aself
error_msg
node
T atype_str
T aself
sub
arrlist
T aself
arrlist
T aself
base
sub
bits
minus_e
T aself
wcT aself
node
visited_children
T aself
node
visited_children
base
sub
arrlist
T aself
node
visited_children
w_aint_value
T aself
node
visited_children
w_aabi_type
T aself
node
visited_children
w_afirst
rest
T aself
node
visited_children
components
arrlist
T aself
node
visited_children
first
w_asecond
a__spec__
.eth_abi.registry
|(
: acopy
a_name
a_values
a_labeled_predicates
uMatcher

u already exists in
u with label '
u' already exists in
items
aNoEntriesFound
uNo matching entries for '
u' in
u,
repr
aMultipleEntriesFound
uMultiple matching entries for '
u:
u. This occurs when two registrations match the same type string. You may need to delete one of the registrations or modify its matching behavior to ensure it doesn't collide with other registrations. See the "Registry" documentation for more information.
type_str
u<genexpr>
uPredicateMapping.find.<locals>.<genexpr>
u not found in
a_label_for_predicate
label
u not referred to by any label in
uLabel '
u' not found in
callable
remove_by_equality
remove_by_label
uKey to be removed must be callable or string: got
uMust implement `__call__`
uMust implement `__str__`
w<a__name__
w w>aself
a__slots__
a__iter__
uPredicate.__iter__
value
u(==
w)abase
with_sub
grammar
parse
exceptions
aParseError
aBasicType
arrlist
sub
u(base ==
u and sub is not None
u and sub is None

A predicate that matches a type string with an array dimension list.
aTupleType

A predicate that matches a tuple type with no array dimension list.
wraps
aABIRegistry
args
aAny
kwargs
return
new_method
u_clear_encoder_cache.<locals>.new_method
get_encoder
cache_clear
old_method
u_clear_decoder_cache.<locals>.new_method
get_decoder
add
aEquals
uLookup must be a callable or a value of type `str`: got
uLookup/label must be a callable or a value of type `str`: got
find
uNo matching
aPredicateMapping
T uencoder registry
a_encoders
T udecoder registry
a_decoders
lru_cache
T nT amaxsize
a_get_encoder_uncached
a_get_decoder_uncached
a__class__
a_get_registration
aBaseCoder
from_type_str
a_register
T alabel

Registers the given ``encoder`` under the given ``lookup``.  A unique
string label may be optionally provided that can be used to refer to
the registration by name.  For more information about arguments, refer
to :any:`register`.
a_unregister

Unregisters an encoder in the registry with the given lookup or label.
If ``lookup_or_label`` is a string, the encoder with the label
``lookup_or_label`` will be unregistered.  If it is an function, the
encoder with the lookup function ``lookup_or_label`` will be
unregistered.

Registers the given ``decoder`` under the given ``lookup``.  A unique
string label may be optionally provided that can be used to refer to
the registration by name.  For more information about arguments, refer
to :any:`register`.

Unregisters a decoder in the registry with the given lookup or label.
If ``lookup_or_label`` is a string, the decoder with the label
``lookup_or_label`` will be unregistered.  If it is an function, the
decoder with the lookup function ``lookup_or_label`` will be
unregistered.
register_encoder
register_decoder

Registers the given ``encoder`` and ``decoder`` under the given
``lookup``.  A unique string label may be optionally provided that can
be used to refer to the registration by name.
:param lookup: A type string or type string matcher function
(predicate).  When the registry is queried with a type string
``query`` to determine which encoder or decoder to use, ``query``
will be checked against every registration in the registry.  If a
registration was created with a type string for ``lookup``, it will
be considered a match if ``lookup == query``.  If a registration
was created with a matcher function for ``lookup``, it will be
considered a match if ``lookup(query) is True``.  If more than one
registration is found to be a match, then an exception is raised.
:param encoder: An encoder callable or class to use if ``lookup``
matches a query.  If ``encoder`` is a callable, it must accept a
python value and return a ``bytes`` value.  If ``encoder`` is a
class, it must be a valid subclass of :any:`encoding.BaseEncoder`
nd must also implement the :any:`from_type_str` method on
:any:`base.BaseCoder`.
:param decoder: A decoder callable or class to use if ``lookup``
matches a query.  If ``decoder`` is a callable, it must accept a
stream-like object of bytes and return a python value.  If
``decoder`` is a class, it must be a valid subclass of
:any:`decoding.BaseDecoder` and must also implement the
:any:`from_type_str` method on :any:`base.BaseCoder`.
:param label: An optional label that can be used to refer to this
registration by name.  This label can be used to unregister an
entry in the registry via the :any:`unregister` method and its
variants.
unregister_encoder
unregister_decoder

Unregisters the entries in the encoder and decoder registries which
have the label ``label``.

Returns ``True`` if an encoder is found for the given type string
``type_str``.  Otherwise, returns ``False``.  Raises
:class:`~eth_abi.exceptions.MultipleEntriesFound` if multiple encoders
re found.
is_dynamic
strict

Copies a registry such that new registrations can be made or existing
registrations can be unregistered without affecting any instance from
which a copy was obtained.  This is useful if an existing registry
fulfills most of a user's needs but requires one or two modifications.
In that case, a copy of that registry can be obtained and the necessary
changes made without affecting the original registry.
a__doc__
a__file__
origin
has_location
a__cached__
abc
functools
aCallable
aOptional
aType
aUnion
eth_typing
T aabi
abi
T adecoding
encoding
exceptions
grammar
decoding
encoding
T aBaseCoder
T aMultipleEntriesFound
aNoEntriesFound
aTypeStr
aLookup
aEncoderCallable
aContextFramesBytesIO
aDecoderCallable
aBaseEncoder
aEncoder
aBaseDecoder
aDecoder
aABC
a__prepare__
aCopyable
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
