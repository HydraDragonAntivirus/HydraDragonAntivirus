# Reconstructed from integrated Nuitka blob
# Module: ueth_account.typed_transactions.base

a__qualname__
a__annotations__
T tT aarbitrary_types_allowed
model_config
return
as_hexbytes
u_BlobDataElement.as_hexbytes
bytes
u_BlobDataElement.as_bytes
as_hexstr
u_BlobDataElement.as_hexstr
a__orig_bases__
aBlob

Represents a Blob.
wvavalidate_data
uBlob.validate_data

Represents a Blob KZG Commitment.
validate_commitment
uBlobKZGCommitment.validate_commitment

Represents a Blob Proof.
validate_proof
uBlobProof.validate_proof

Represents a Blob Versioned Hash.
validate_versioned_hash
uBlobVersionedHash.validate_versioned_hash
aBlobPooledTransactionData

Represents the blob data for a type 3 `PooledTransaction` as defined by
EIP-4844. This class takes blobs as bytes and computes the corresponding
commitments, proofs, and versioned hashes.
kzg_commitment
uBlobPooledTransactionData._kzg_to_versioned_hash
T ablobs
validate_blobs
uBlobPooledTransactionData.validate_blobs
property
versioned_hashes
uBlobPooledTransactionData.versioned_hashes
uBlobPooledTransactionData.commitments
proofs
uBlobPooledTransactionData.proofs
a_TypedTransactionImplementation

Abstract class that every typed transaction must implement.
Should not be imported or used by clients of the library.
blob_data
hash
u_TypedTransactionImplementation.hash
payload
u_TypedTransactionImplementation.payload
str
as_dict
u_TypedTransactionImplementation.as_dict
int
vrs
u_TypedTransactionImplementation.vrs
ueth_account\typed_transactions\base.py
u<module eth_account.typed_transactions.base>
T a__class__
T aself
kzg_commitment
T aself
T acls
wva__spec__
.eth_account.typed_transactions.blob_transactions.blob_transaction
n
dictionary
aBlobPooledTransactionData
aBlob
aHexBytes
T adata
T ablobs
blob_data
blobVersionedHashes
a_validate_versioned_hashes_against_blob_data
merge
aLEGACY_TRANSACTION_VALID_VALUES
type
is_int_or_prefixed_hexstr
maxPriorityFeePerGas
maxFeePerGas
accessList
is_rpc_structured_access_list
maxFeePerBlobGas
is_sequence_of_bytes_or_hexstr
T l FT aitem_bytes_size
can_be_empty
wvu0x0
apply_formatters_to_dict
values
items
uTransaction had invalid fields:

tx_payload_body
unsigned_transaction_fields
signature_fields
transaction_type
set_transaction_type_if_needed
assert_valid_fields
T ahas_blobs
pipe
partial
transaction_field_defaults
aTYPED_TRANSACTION_FORMATTERS
pop
T atype
uexpected transaction type
u, got
T adictionary
blobs

Builds a BlobTransaction from a dictionary.
Verifies that the dictionary is well-formed.
u<genexpr>
uBlobTransaction.from_dict.<locals>.<genexpr>
uexpected Hexbytes, got type:
uunexpected input
:l nna_signed_pooled_transaction_serializer
from_bytes
as_dict
rlp
exceptions
aObjectDeserializationError
a_signed_transaction_serializer
transaction_rlp_to_rpc_structure
get
from_dict

Builds a BlobTransaction from a signed encoded transaction.
copy
versioned_hashes
data
uReturns this transaction as a dictionary.
dissoc
wrwsatransaction_rpc_to_rlp_structure
T ablobVersionedHashes
a_unsigned_transaction_serializer
u<lambda>
uBlobTransaction.hash.<locals>.<lambda>
keccak
cast

Keccak256 hash of the BlobTransaction to prepare it for signing.
As per the EIP-4844 specifications, the signature is a secp256k1 signature over
``keccak256(0x03 || rlp([chainId, nonce, maxPriorityFeePerGas,
maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas,
blobVersionedHashes]))``.
encode
self
vrs
uattempting to encode an unsigned transaction
blobs
as_bytes
commitments
proofs

Returns this transaction's payload as bytes.
Here, the transaction payload is:
TransactionPayload = rlp([chainId,
nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
ccessList, maxFeePerBlobGas, blobVersionedHashes, signatureYParity,
signatureR, signatureS])
uBlobTransaction.payload.<locals>.<genexpr>
rlp_structured_dict
uReturns (v, r, s) if they exist.
uBlobTransaction.vrs.<locals>.<genexpr>
difference
aValidationError
u`blobVersionedHashes` value defined in transaction does not match versioned hashes computed from blobs.
diff:
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aList
aOptional
aTuple
eth_rlp
T aHashableRLP
aHashableRLP
eth_utils
T aValidationError
keccak
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
aCountableList
big_endian_int
binary
aBinary
aCountableList
big_endian_int
binary
ueth_account._utils.transaction_utils
T aset_transaction_type_if_needed
transaction_rlp_to_rpc_structure
transaction_rpc_to_rlp_structure
ueth_account._utils.validation
T aLEGACY_TRANSACTION_VALID_VALUES
is_int_or_prefixed_hexstr
is_rpc_structured_access_list
is_sequence_of_bytes_or_hexstr
ueth_account.typed_transactions.access_list_transaction
T aaccess_list_sede_type
access_list_sede_type
ueth_account.typed_transactions.base
T aTYPED_TRANSACTION_FORMATTERS
aBlob
aBlobPooledTransactionData
a_TypedTransactionImplementation
a_TypedTransactionImplementation
ueth_account.types
T aBlobs
aBlobs
a__prepare__
aBlobTransaction
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
