# Reconstructed from integrated Nuitka blob
# Module: ueth_account.typed_transactions.blob_transactions.blob_transaction


Represents a blob transaction as per EIP-4844.
a__qualname__
a__annotations__
l achainId
nonce
gas
to
fixed_length
T l tT aallow_empty
value
D atype
chainId
to
value
data
accessList
c0x3
l
c
l
c
L
fields
T l   T l0T nastr
a__init__
uBlobTransaction.__init__
classmethod
T Fahas_blobs
bool
return
uBlobTransaction.assert_valid_fields
uBlobTransaction.from_dict
encoded_transaction
uBlobTransaction.from_bytes
uBlobTransaction.as_dict
bytes
hash
uBlobTransaction.hash
payload
uBlobTransaction.payload
int
uBlobTransaction.vrs
staticmethod
blob_versioned_hashes
uBlobTransaction._validate_versioned_hashes_against_blob_data
a__orig_bases__
ueth_account\typed_transactions\blob_transactions\blob_transaction.py
T a.0
entry
T a.0
wkaself
T a.0
key
a_val
rlp_structured_dict
T aval
T aval
self
T aself
u<module eth_account.typed_transactions.blob_transactions.blob_transaction>
T a__class__
T aself
dictionary
blobs
T ablob_versioned_hashes
blob_data
diff
T aself
dictionary
T acls
dictionary
has_blobs
transaction_valid_values
valid_fields
invalid
T acls
encoded_transaction
transaction_payload
dictionary
rpc_structured_dict
blobs
T acls
dictionary
blobs
has_blobs
sanitized_dictionary
transaction_type
T aself
transaction_without_signature_fields
rlp_structured_txn_without_sig_fields
rlp_serializer
hash_
T aself
rlp_structured_dict
rlp_serializer
payload
pooled_txn_as_dict
a__spec__
.eth_account.typed_transactions.blob_transactions
4
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_account
u\not_existing
utyped_transactions\blob_transactions
T aNUITKA_PACKAGE_eth_account_typed_transactions
u\not_existing
blob_transactions
T aNUITKA_PACKAGE_eth_account_typed_transactions_blob_transactions
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
blob_transaction
T aBlobTransaction
aBlobTransaction
ueth_account\typed_transactions\blob_transactions\__init__.py
u<module eth_account.typed_transactions.blob_transactions>

a__spec__
.eth_account.typed_transactions
v
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_account
u\not_existing
typed_transactions
T aNUITKA_PACKAGE_eth_account_typed_transactions
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
access_list_transaction
T aAccessListTransaction
aAccessListTransaction
ublob_transactions.blob_transaction
T aBlobTransaction
aBlobTransaction
dynamic_fee_transaction
T aDynamicFeeTransaction
aDynamicFeeTransaction
typed_transaction
T aTypedTransaction
aTypedTransaction
ueth_account\typed_transactions\__init__.py
u<module eth_account.typed_transactions>

a__spec__
.eth_account.typed_transactions.dynamic_fee_transaction
dictionary
merge
aLEGACY_TRANSACTION_VALID_VALUES
type
is_int_or_prefixed_hexstr
maxPriorityFeePerGas
maxFeePerGas
accessList
is_rpc_structured_access_list
wvu0x0
apply_formatters_to_dict
values
items
uTransaction had invalid fields:

uBlob data is not supported for `DynamicFeeTransaction`.
assert_valid_fields
pipe
partial
transaction_field_defaults
aTYPED_TRANSACTION_FORMATTERS
pop
T atype
transaction_type
uexpected transaction type
u, got
T adictionary

Builds a DynamicFeeTransaction from a dictionary.
Verifies that the dictionary is well formed.
aHexBytes
uexpected Hexbytes, got type:
uunexpected input
:l nna_signed_transaction_serializer
from_bytes
as_dict
transaction_rlp_to_rpc_structure
from_dict
uBuilds a DynamicFeeTransaction from a signed encoded transaction.
copy
uReturns this transaction as a dictionary.
dissoc
wrwsatransaction_rpc_to_rlp_structure
a_unsigned_transaction_serializer
u<lambda>
uDynamicFeeTransaction.hash.<locals>.<lambda>
keccak
cast

Hashes this DynamicFeeTransaction to prepare it for signing.
As per the EIP-1559 specifications, the signature is a secp256k1 signature over
``keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
maxFeePerGas, gasLimit, to, value, data, accessList]))``
rlp
encode
self
vrs
uattempting to encode an unsigned transaction

Returns this transaction's payload as bytes.
Here, the transaction payload is:
TransactionPayload = rlp([chainId,
nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
ccessList, signatureYParity, signatureR, signatureS])
u<genexpr>
uDynamicFeeTransaction.payload.<locals>.<genexpr>
uReturns (v, r, s) if they exist.
uDynamicFeeTransaction.vrs.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aOptional
aTuple
eth_rlp
T aHashableRLP
aHashableRLP
eth_utils
T akeccak
ueth_utils.curried
T aapply_formatters_to_dict
ueth_utils.toolz
T adissoc
merge
partial
pipe
hexbytes
T aHexBytes
urlp.sedes
T aBinary
big_endian_int
binary
aBinary
big_endian_int
binary
ueth_account._utils.transaction_utils
T atransaction_rlp_to_rpc_structure
transaction_rpc_to_rlp_structure
ueth_account._utils.validation
T aLEGACY_TRANSACTION_VALID_VALUES
is_int_or_prefixed_hexstr
is_rpc_structured_access_list
ueth_account.types
T aBlobs
aBlobs
access_list_transaction
T aaccess_list_sede_type
access_list_sede_type
base
T aTYPED_TRANSACTION_FORMATTERS
a_TypedTransactionImplementation
a_TypedTransactionImplementation
a__prepare__
aDynamicFeeTransaction
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
