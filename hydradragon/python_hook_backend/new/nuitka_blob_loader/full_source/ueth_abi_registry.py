# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.registry

a__qualname__
abstractmethod
uCopyable.copy
a__copy__
uCopyable.__copy__
a__deepcopy__
uCopyable.__deepcopy__
a__orig_bases__

Acts as a mapping from predicate functions to values.  Values are retrieved
when their corresponding predicate matches a given input.  Predicates can
lso be labeled to facilitate removal from the mapping.
a__init__
uPredicateMapping.__init__
uPredicateMapping.add
uPredicateMapping.find
uPredicateMapping.remove_by_equality
uPredicateMapping._label_for_predicate
uPredicateMapping.remove_by_label
remove
uPredicateMapping.remove
uPredicateMapping.copy

Represents a predicate function to be used for type matching in
``ABIRegistry``.
aPredicate
a__call__
uPredicate.__call__
a__str__
uPredicate.__str__
a__repr__
uPredicate.__repr__
a__hash__
uPredicate.__hash__
a__eq__
uPredicate.__eq__

A predicate that matches any input equal to `value`.
T avalue
uEquals.__init__
uEquals.__call__
uEquals.__str__
aBaseEquals

A predicate that matches a basic type string with a base component equal to
`value` and no array component.  If `with_sub` is `True`, the type string
must have a sub component to match.  If `with_sub` is `False`, the type
string must *not* have a sub component to match.  If `with_sub` is None,
the type string's sub component is ignored.
T abase
with_sub
D awith_sub
nuBaseEquals.__init__
uBaseEquals.__call__
uBaseEquals.__str__
has_arrlist
is_base_tuple
T Q
na_clear_encoder_cache
a_clear_decoder_cache
aBaseRegistry
uBaseRegistry._register
uBaseRegistry._unregister
uBaseRegistry._get_registration
uABIRegistry.__init__
uABIRegistry._get_registration
lookup
encoder
str
uABIRegistry.register_encoder
lookup_or_label
uABIRegistry.unregister_encoder
decoder
uABIRegistry.register_decoder
uABIRegistry.unregister_decoder
register
uABIRegistry.register
unregister
uABIRegistry.unregister
uABIRegistry._get_encoder_uncached
bool
has_encoder
uABIRegistry.has_encoder
T tuABIRegistry._get_decoder_uncached
uABIRegistry.copy
registry
T auint
aUnsignedIntegerEncoder
aUnsignedIntegerDecoder
D alabel
uint
T aint
aSignedIntegerEncoder
aSignedIntegerDecoder
D alabel
int
T aaddress
aAddressEncoder
aAddressDecoder
D alabel
address
T abool
aBooleanEncoder
aBooleanDecoder
D alabel
bool
T aufixed
aUnsignedFixedEncoder
aUnsignedFixedDecoder
D alabel
ufixed
T afixed
aSignedFixedEncoder
aSignedFixedDecoder
D alabel
fixed
T abytes
tT awith_sub
aBytesEncoder
aBytesDecoder
D alabel
ubytes<M>
T abytes
FaByteStringEncoder
aByteStringDecoder
D alabel
bytes
T afunction
D alabel
function
T astring
aTextStringEncoder
aStringDecoder
D alabel
string
aBaseArrayEncoder
aBaseArrayDecoder
D alabel
has_arrlist
aTupleEncoder
aTupleDecoder
D alabel
is_base_tuple
registry_packed
aPackedUnsignedIntegerEncoder
aPackedSignedIntegerEncoder
aPackedAddressEncoder
aPackedBooleanEncoder
aPackedUnsignedFixedEncoder
aPackedSignedFixedEncoder
aPackedBytesEncoder
aPackedByteStringEncoder
aPackedTextStringEncoder
aPackedArrayEncoder
ueth_abi\registry.py
T a.0
predicate
value
type_str
u<module eth_abi.registry>
T a__class__
T aself
type_str
abi_type
T aself
other
T aself
args
kwargs
T aself
T aself
args
T aself
base
with_sub
T aself
value
T aself
name
T aself
attr
T aold_method
new_method
T aself
type_str
strict
decoder
T aself
type_str
T aself
mapping
type_str
coder
a__class__
T amapping
type_str
value
weT aself
predicate
key
value
T amapping
lookup
value
label
T amapping
lookup_or_label
T aself
predicate
value
label
T aself
cpy
T aself
type_str
results
predicates
values
predicate_reprs
T atype_str
abi_type
T aself
type_str
weT aself
args
kwargs
old_method
T aold_method
T aself
lookup
encoder
decoder
label
T aself
lookup
decoder
label
T aself
lookup
encoder
label
T aself
predicate_or_label
T aself
predicate
label
T aself
label
predicate
T aself
label
T aself
lookup_or_label
a__spec__
.eth_abi.utils
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_abi
u\not_existing
utils
T aNUITKA_PACKAGE_eth_abi_utils
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ueth_abi\utils\__init__.py
u<module eth_abi.utils>

a__spec__
.eth_abi.utils.numeric
>
l l acompute_unsigned_integer_bounds
decimal
localcontext
abi_decimal_context
a__enter__
a__exit__
aDecimal
aTEN
T nnnaZERO
upper
compute_signed_integer_bounds
lower
uArgument `places` must be int.  Got value

u of type
w.wxareturn
wfuscale_places.<locals>.f
aEneg
aEpos
scale_by_
a__name__
a__qualname__

Returns a function that shifts the decimal point of decimal values to the
right by ``places`` places.
scaling_factor
a__doc__
a__file__
origin
has_location
a__cached__
aCallable
aTuple
l  aABI_DECIMAL_PREC
aContext
T aprec
T l
T l
D wxareturn
Oint
paceil32
num_bits
T Oint
pafrac_places
compute_unsigned_fixed_bounds
compute_signed_fixed_bounds
places
scale_places
ueth_abi\utils\numeric.py
u<module eth_abi.utils.numeric>
T wxT anum_bits
frac_places
int_lower
int_upper
exp
lower
upper
T anum_bits
T anum_bits
frac_places
int_upper
upper
T wxascaling_factor
T ascaling_factor
T aplaces
scaling_factor
wfaplaces_repr
func_name
a__spec__
.eth_abi.utils.padding
2
rjust
d
ljust
d a__doc__
a__file__
origin
has_location
a__cached__
ueth_utils.toolz
T acurry
curry
D avalue
length
return
Obytes
Oint
Obytes
zpad
T l T alength
zpad32
zpad_right
zpad32_right
fpad
fpad32
ueth_abi\utils\padding.py
u<module eth_abi.utils.padding>
T avalue
length

a__spec__
.eth_abi.utils.string
l uAbbreviation limit may not be less than 3
u...
rep

Converts a value into its string representation and abbreviates that
representation based on the given length `limit` if necessary.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
T lOavalue
limit
return
abbr
ueth_abi\utils\string.py
u<module eth_abi.utils.string>
T avalue
limit
rep

a__spec__
.eth_abi.utils.validation
v
is_bytes
uThe `

u` value must be of bytes type. Got
T Olist
Otuple
u` value type must be one of list or tuple. Got
a__doc__
a__file__
origin
has_location
a__cached__
aAny
eth_utils
T ais_bytes
param
param_name
return
validate_bytes_param
validate_list_like_param
ueth_abi\utils\validation.py
u<module eth_abi.utils.validation>
T aparam
param_name
a__spec__
.eth_account._utils
3
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_account
u\not_existing
a_utils
T aNUITKA_PACKAGE_eth_account__utils
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ueth_account\_utils\__init__.py
u<module eth_account._utils>

a__spec__
.eth_account._utils.encode_typed_data
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_account
u\not_existing
u_utils\encode_typed_data
T aNUITKA_PACKAGE_eth_account__utils
u\not_existing
encode_typed_data
T aNUITKA_PACKAGE_eth_account__utils_encode_typed_data
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
encoding_and_hashing
T ahash_domain
hash_eip712_message
hash_domain
hash_eip712_message
ueth_account\_utils\encode_typed_data\__init__.py
u<module eth_account._utils.encode_typed_data>

a__spec__
.eth_account._utils.encode_typed_data.encoding_and_hashing
g
keys
parse_core_array_type
type
custom_types_that_are_deps
add
difference
uUnable to determine primary type
T abytes32
b
bytes32
keccak
encode_data
T astring
bytes
T abytes32
c
uMissing value for field `

u` of type `
w`ais_array_type
uInvalid value for field `
u`: expected array, got `
parse_parent_array_type
encode_field
types
name
parsed_type
T abytes32
b   F   #< ~}
S  ';{   ]  paencode
bool
startswith
T abytes
is_0x_prefixed_hexstr
to_bytes
T ahexstr
T atext
value
bytes
string
T T aint
uint
to_int
uInvalid find_type_dependencies input: expected string, got `
aEIP712_SOLIDITY_TYPES
uNo definition of type `
find_type_dependencies
results
remove
sorted
children_list
w aresult
w(w,w)aencode_type
hash_type
data
get
encoded_types
encoded_values
get_primary_type
D aname
version
chainId
verifyingContract
salt
D aname
type
name
string
D aname
type
version
string
D aname
type
chainId
uint256
D aname
type
verifyingContract
address
D aname
type
salt
bytes32
uInvalid domain key: `
aEIP712Domain
hash_struct
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aList
aOptional
aSet
aTuple
aUnion
eth_abi
T aencode
eth_utils
T akeccak
to_bytes
to_int
ueth_account._utils.encode_typed_data.helpers
T aEIP712_SOLIDITY_TYPES
is_0x_prefixed_hexstr
is_array_type
parse_core_array_type
parse_parent_array_type
T Ostr
pareturn
type_
T Oint
Obytes
T namessage_types
message_data
hash_eip712_message
domain_data
hash_domain
ueth_account\_utils\encode_typed_data\encoding_and_hashing.py
u<module eth_account._utils.encode_typed_data.encoding_and_hashing>
T atype_
types
data
encoded_types
encoded_values
field
type
value
T atypes
name
type_
value
parsed_type
type_value_pairs
data_types
data_hashes
T	atype_
types
result
unsorted_deps
deps
children_list
child
child_type
child_name
T atype_
types
results
field
T atypes
custom_types
custom_types_that_are_deps
type_
type_fields
field
parsed_type
primary_type
T adomain_data
eip712_domain_map
wkadomain_types
T amessage_types
message_data
primary_type
T atype_
types
data
encoded
T atype_
types
a__spec__
.eth_account._utils.encode_typed_data.helpers
U
)
L abool
address
string
bytes
uint
int
;l
l l aint
l u
uint
bytes
endswith
T w]ais_hexstr
startswith
T u0x
is_array_type
index
T w[atype_
rindex
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aList
eth_utils
T ais_hexstr
return
a_get_eip712_solidity_types
aEIP712_SOLIDITY_TYPES
D atype_
return
Ostr
Obool
value
is_0x_prefixed_hexstr
D atype_
return
Ostr
paparse_core_array_type
parse_parent_array_type
ueth_account\_utils\encode_typed_data\helpers.py
u<module eth_account._utils.encode_typed_data.helpers>
T atypes
ints
uints
bytes_
T avalue
T atype_
a__spec__
.eth_account._utils.legacy_transactions
]
set_transaction_type_if_needed
type
aTypedTransaction
from_dict
T ablobs
uBlob data is not supported for legacy transactions.
assert_valid_fields
pipe
partial
merge
aTRANSACTION_DEFAULTS
chain_id_to_v
apply_formatters_to_dict
aLEGACY_TRANSACTION_FORMATTERS
wvaTransaction
aUnsignedTransaction
dissoc
as_dict
wrwsablob_data
blobs
as_bytes
encode
rlp
aREQUIRED_TRANSACTION_KEYS
difference
keys
uTransaction must include these fields:

aALLOWED_TRANSACTION_KEYS
uTransaction must not include unrecognized fields:
aLEGACY_TRANSACTION_VALID_VALUES
values
items
uTransaction had invalid fields:
pop
T achainId
cast
aTransactionDictType
itertools
islice
aUNSIGNED_TRANSACTION_FIELDS
vrs
transaction
u<genexpr>
uvrs_from.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aGenerator
aList
aOptional
aTuple
aUnion
eth_rlp
T aHashableRLP
aHashableRLP
ueth_utils.curried
T aapply_formatters_to_dict
ueth_utils.toolz
T acurry
dissoc
merge
partial
pipe
curry
urlp.sedes
T aBinary
big_endian_int
binary
aBinary
big_endian_int
binary
ueth_account.typed_transactions
T aTypedTransaction
ueth_account.types
T aBlobs
aTransactionDictType
aBlobs
transaction_utils
T aset_transaction_type_if_needed
validation
T aLEGACY_TRANSACTION_FORMATTERS
aLEGACY_TRANSACTION_VALID_VALUES
nonce
gasPrice
gas
to
fixed_length
T l tT aallow_empty
value
data
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
