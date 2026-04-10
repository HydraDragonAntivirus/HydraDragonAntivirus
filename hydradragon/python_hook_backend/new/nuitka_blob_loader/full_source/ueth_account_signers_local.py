# Reconstructed from integrated Nuitka blob
# Module: ueth_account.signers.local


A collection of convenience methods to sign and encrypt, with an
embedded private key.
:var bytes key: the 32-byte private key data
.. code-block:: python
>>> my_local_account.address
"0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
>>> my_local_account.key
b"\x01\x23..."
You can also get the private key by casting the account to :class:`bytes`:
.. code-block:: python
>>> bytes(my_local_account)
b"\\x01\\x23..."
a__qualname__
account
a__init__
uLocalAccount.__init__
return
bytes
a__bytes__
uLocalAccount.__bytes__
property
address
uLocalAccount.address
uLocalAccount.key
T nnapassword
str
kdf
iterations
int
uLocalAccount.encrypt
message_hash
uLocalAccount.unsafe_sign_hash
signable_message
uLocalAccount.sign_message
T natransaction_dict
blobs
uLocalAccount.sign_transaction
T nnnnadomain_data
message_types
message_data
full_message
uLocalAccount.sign_typed_data
a__orig_bases__
ueth_account\signers\local.py
u<module eth_account.signers.local>
T a__class__
T aself
T aself
key
account
key_raw
T aself
password
kdf
iterations
T aself
signable_message
T aself
transaction_dict
blobs
T aself
domain_data
message_types
message_data
full_message
T aself
message_hash

a__spec__
.eth_account.typed_transactions.access_list_transaction
dictionary
merge
aLEGACY_TRANSACTION_VALID_VALUES
type
is_int_or_prefixed_hexstr
accessList
is_rpc_structured_access_list
wvu0x0
apply_formatters_to_dict
values
items
uTransaction had invalid fields:

uBlob data is not supported for `AccessListTransaction`.
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

Builds an AccessListTransaction from a dictionary.
Verifies that the dictionary is well formed.
aHexBytes
uexpected Hexbytes, got type:
uunexpected input
:l nna_signed_transaction_serializer
from_bytes
as_dict
transaction_rlp_to_rpc_structure
from_dict
uBuilds an AccessListTransaction from a signed encoded transaction.
copy
uReturns this transaction as a dictionary.
dissoc
wrwsatransaction_rpc_to_rlp_structure
a_unsigned_transaction_serializer
u<lambda>
uAccessListTransaction.hash.<locals>.<lambda>
keccak
cast

Hashes this AccessListTransaction to prepare it for signing.
As per the EIP-2930 specifications, the signature is a secp256k1 signature over
``keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit,
to, value, data, accessList])).``
rlp
encode
self
vrs
uattempting to encode an unsigned transaction

Returns this transaction's payload as bytes.
Here, the transaction payload is:
TransactionPayload = rlp([chainId,
nonce, gasPrice, gasLimit, to, value, data, accessList,
signatureYParity, signatureR, signatureS])
u<genexpr>
uAccessListTransaction.payload.<locals>.<genexpr>
uReturns (v, r, s) if they exist.
uAccessListTransaction.vrs.<locals>.<genexpr>
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
T aBigEndianInt
aBinary
aCountableList
aList
big_endian_int
binary
aBigEndianInt
aBinary
aCountableList
aList
aListSedesClass
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
base
T aTYPED_TRANSACTION_FORMATTERS
a_TypedTransactionImplementation
a_TypedTransactionImplementation
fixed_length
T l FT aallow_empty
T l aaccess_list_sede_type
a__prepare__
aAccessListTransaction
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
