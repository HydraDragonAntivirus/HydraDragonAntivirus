# Reconstructed from integrated Nuitka blob
# Module: ueth_account.typed_transactions.access_list_transaction


Represents an access list transaction per EIP-2930.
a__qualname__
chainId
nonce
gasPrice
gas
to
T l tavalue
data
unsigned_transaction_fields
signature_fields
D atype
chainId
to
value
data
accessList
c0x1
l
c
l
c
L
fields
str
a__init__
uAccessListTransaction.__init__
classmethod
return
uAccessListTransaction.assert_valid_fields
T nablobs
uAccessListTransaction.from_dict
encoded_transaction
uAccessListTransaction.from_bytes
uAccessListTransaction.as_dict
bytes
hash
uAccessListTransaction.hash
payload
uAccessListTransaction.payload
int
uAccessListTransaction.vrs
a__orig_bases__
ueth_account\typed_transactions\access_list_transaction.py
T a.0
wkaself
T aval
T aval
self
T aself
u<module eth_account.typed_transactions.access_list_transaction>
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
.eth_account.typed_transactions.base
5
data
aHexStr
u0x
as_bytes
hex

aValidationError
T uInvalid Blob size. Blob data must be comprised of 4096 32-byte field elements.
T uBlob KZG Commitment must be 48 bytes long.
T uBlob Proof must be 48 bytes long.
T uBlob Versioned Hash must be 32 bytes long.
:nl naVERSIONED_HASH_VERSION_KZG
T uBlob Versioned Hash must start with the KZG version byte.
a_versioned_hash_version_kzg
hashlib
sha256
digest
:l nnT uBlob transactions must contain at least 1 blob.
T uBlob transactions cannot contain more than 6 blobs.
a_versioned_hashes
commitments
aBlobVersionedHash
aHexBytes
self
a_kzg_to_versioned_hash
T adata
a_commitments
blobs
aBlobKZGCommitment
blob_to_kzg_commitment
load_trusted_setup
aTRUSTED_SETUP
a_proofs
aBlobProof
compute_blob_kzg_proof
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
os
aAny
aDict
aList
aOptional
aTuple
aUnion
ckzg
T ablob_to_kzg_commitment
compute_blob_kzg_proof
load_trusted_setup
eth_typing
T aHexStr
eth_utils
T aValidationError
is_bytes
is_string
to_bytes
to_int
is_bytes
is_string
to_bytes
to_int
ueth_utils.curried
T aapply_formatter_to_array
apply_formatters_to_dict
apply_one_of_formatters
hexstr_if_str
apply_formatter_to_array
apply_formatters_to_dict
apply_one_of_formatters
hexstr_if_str
ueth_utils.toolz
T aidentity
merge
identity
merge
hexbytes
T aHexBytes
pydantic
upydantic.main
aBaseModel
upydantic.config
aConfigDict
upydantic.fields
computed_field
upydantic.functional_validators
field_validator
ueth_account._utils.validation
T aLEGACY_TRANSACTION_FORMATTERS
aLEGACY_TRANSACTION_FORMATTERS
chainId
type
accessList
address
storageKeys
maxPriorityFeePerGas
maxFeePerGas
maxFeePerBlobGas
blobVersionedHashes
aTYPED_TRANSACTION_FORMATTERS
join
blob_transactions
ukzg_trusted_setup.txt
d a__prepare__
a_BlobDataElement
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
