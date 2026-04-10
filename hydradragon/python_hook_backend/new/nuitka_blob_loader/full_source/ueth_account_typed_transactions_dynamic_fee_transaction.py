# Reconstructed from integrated Nuitka blob
# Module: ueth_account.typed_transactions.dynamic_fee_transaction


Represents a dynamic fee transaction access per EIP-1559.
a__qualname__
l achainId
nonce
gas
to
fixed_length
T l tT aallow_empty
value
data
unsigned_transaction_fields
signature_fields
D atype
chainId
to
value
data
accessList
c0x2
l
c
l
c
L
fields
str
a__init__
uDynamicFeeTransaction.__init__
classmethod
return
uDynamicFeeTransaction.assert_valid_fields
T nablobs
uDynamicFeeTransaction.from_dict
encoded_transaction
uDynamicFeeTransaction.from_bytes
uDynamicFeeTransaction.as_dict
bytes
hash
uDynamicFeeTransaction.hash
payload
uDynamicFeeTransaction.payload
int
uDynamicFeeTransaction.vrs
a__orig_bases__
ueth_account\typed_transactions\dynamic_fee_transaction.py
T a.0
wkaself
T aval
T aval
self
T aself
u<module eth_account.typed_transactions.dynamic_fee_transaction>
T a__class__
T aself
dictionary
T acls
dictionary
transaction_valid_values
valid_fields
invalid
T acls
encoded_transaction
transaction_payload
rlp_serializer
dictionary
rpc_structured_dict
T acls
dictionary
blobs
sanitized_dictionary
transaction_type
T aself
transaction_without_signature_fields
rlp_structured_txn_without_sig_fields
rlp_serializer
hash
T aself
rlp_serializer
rlp_structured_dict
payload
a__spec__
.eth_account.typed_transactions.typed_transaction
o
f
a_TypedTransactionImplementation
uexpected _TypedTransactionImplementation, got

uexpected int, got
transaction_type
transaction
uShould not be called directly. Use instead the 'from_dict' method.
blob_data
uReturns the blobs associated with this transaction.
set_transaction_type_if_needed
type
is_int_or_prefixed_hexstr
umissing or incorrect transaction type
pipe
hexstr_if_str
to_int
aAccessListTransaction
aDynamicFeeTransaction
aBlobTransaction
uUnknown Transaction type:
from_dict
T ablobs
T atransaction_type
transaction

Builds a TypedTransaction from a dictionary.
Verifies the dictionary is well formed.
aHexBytes
uexpected Hexbytes, got
l uunexpected input
from_bytes
utyped transaction has unknown type:
uBuilds a TypedTransaction from a signed encoded transaction.
hash

Hashes this TypedTransaction to prepare it for signing.
As per the EIP-2718 specifications,
the hashing format is dictated by the transaction type itself,
nd so we delegate the call.
Note that the return type will be bytes.
payload

Encodes this TypedTransaction and returns it as bytes.
The transaction format follows EIP-2718's typed transaction
format (TransactionType || TransactionPayload).
Note that we delegate to a transaction type's payload() method as
the EIP-2718 does not prescribe a TransactionPayload format,
leaving types free to implement their own encoding.
normalize_transaction_dict
as_dict
uReturns this transaction as a dictionary.
vrs
uReturns (v, r, s) if they exist.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aOptional
aTuple
aUnion
ueth_utils.curried
T ahexstr_if_str
to_int
ueth_utils.toolz
T apipe
hexbytes
T aHexBytes
ueth_account._utils.transaction_utils
T anormalize_transaction_dict
set_transaction_type_if_needed
ueth_account._utils.validation
T ais_int_or_prefixed_hexstr
ueth_account.types
T aBlobs
aBlobs
access_list_transaction
T aAccessListTransaction
base
T a_TypedTransactionImplementation
ublob_transactions.blob_transaction
T aBlobPooledTransactionData
aBlobTransaction
aBlobPooledTransactionData
dynamic_fee_transaction
T aDynamicFeeTransaction
