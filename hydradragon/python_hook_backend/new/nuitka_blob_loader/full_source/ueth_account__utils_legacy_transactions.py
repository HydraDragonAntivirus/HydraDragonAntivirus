# Reconstructed from integrated Nuitka blob
# Module: ueth_account._utils.legacy_transactions

a__qualname__
fields
a__orig_bases__
T natransaction_dict
return
serializable_unsigned_transaction_from_dict
unsigned_transaction
T Oint
ppaencode_transaction
D ato
value
data
chainId
c
l
c
nS avalue
chainId
to
gas
data
gasPrice
nonce
fill_transaction_defaults
aChainAwareUnsignedTransaction
T Oint
Obytes
strip_signature
T Oint
nnavrs_from
ueth_account\_utils\legacy_transactions.py
T a.0
part
transaction
u<module eth_account._utils.legacy_transactions>
T a__class__
T atransaction_dict
valid_fields
missing_keys
superfluous_keys
invalid
T atransaction_dict
chain_id
T	aunsigned_transaction
vrs
wvwrwsachain_naive_transaction
blob_data
signed_typed_transaction
signed_transaction
T atransaction_dict
T atransaction_dict
blobs
filled_transaction
serializer
T atransaction
unsigned_parts
T atransaction
a__spec__
.eth_account._utils.signing
h
serializable_unsigned_transaction_from_dict
T ablobs
hash
aUnsignedTransaction
sign_transaction_hash
aTransaction
wvaTypedTransaction
sign_msg_hash
vrs
uunknown Transaction object:

encode_transaction
T avrs
extract_chain_id
strip_signature
aChainAwareUnsignedTransaction

Regenerate the hash of the signed transaction object.
1. Infer the chain ID from the signature
2. Strip out signature from transaction
3. Annotate the transaction with that ID, if available
4. Take the hash of the serialized, unsigned, chain-aware transaction
Chain ID inference and annotation is according to EIP-155
See details at https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
:return: the hash of the provided transaction, to be signed
aCHAIN_ID_OFFSET
P l
l aV_OFFSET
P l l uv
u is invalid, must be one of: 0, 1, 27, 28, 35+
l u
Extracts chain ID, according to EIP-155.
@return (chain_id, v)
:nq nato_int
to_standard_v
to_bytes
to_eth_v
rjust
T l d
cast
pipe
a_pad_to_eth_word
to_bytes32
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aTuple
ueth_keys.datatypes
T aPrivateKey
aPrivateKey
eth_utils
T ato_bytes
to_int
ueth_utils.toolz
T apipe
ueth_account._utils.legacy_transactions
T aChainAwareUnsignedTransaction
aTransaction
aUnsignedTransaction
encode_transaction
serializable_unsigned_transaction_from_dict
strip_signature
ueth_account.typed_transactions
T aTypedTransaction
ueth_account.types
T aBlobs
aBytes32
aTransactionDictType
aBlobs
aBytes32
aTransactionDictType
l#l dEaPERSONAL_SIGN_VERSION
d
aINTENDED_VALIDATOR_SIGN_VERSION
d aSTRUCTURED_DATA_SIGN_VERSION
T naeth_key
transaction_dict
blobs
return
T Oint
ppObytes
sign_transaction_dict
txn_obj
hash_of_signed_transaction
raw_v
D aethereum_signature_bytes
return
Obytes
pato_standard_signature_bytes
D aenhanced_v
return
Oint
pav_raw
chain_id
account
transaction_hash
T Oint
ppabytes_val
val
key
msg_hash
sign_message_hash
ueth_account\_utils\signing.py
u<module eth_account._utils.signing>
T abytes_val
T araw_v
above_id_offset
chain_id
v_bit
T atxn_obj
chain_id
a_v
unsigned_parts
signable_transaction
extended_transaction
T akey
msg_hash
signature
v_raw
wrwswvaeth_signature_bytes
T
eth_key
transaction_dict
blobs
unsigned_transaction
transaction_hash
chain_id
wvwrwsaencoded_transaction
T aaccount
transaction_hash
chain_id
signature
v_raw
wrwswvT aval
T av_raw
chain_id
wvT aethereum_signature_bytes
rs
wvastandard_v
T aenhanced_v
a_chain
chain_naive_v
v_standard
a__spec__
.eth_account._utils.transaction_utils
v
H
items
T Olist
Otuple
txn_dict
normalize_transaction_dict

Normalizes a transaction dictionary.
u<genexpr>
unormalize_transaction_dict.<locals>.<genexpr>
type
T agasPrice
accessList
assoc
u0x1
T amaxFeePerGas
maxPriorityFeePerGas
T amaxFeePerBlobGas
blobVersionedHashes
u0x3
u0x2
transaction_dict
uset_transaction_type_if_needed.<locals>.<genexpr>
get
T aaccessList
dissoc
accessList
a_access_list_rpc_to_rlp_structure
dictionary

Convert a JSON-RPC-structured transaction to an rlp-structured transaction.
is_rpc_structured_access_list
uprovided object not formatted as JSON-RPC-structured access list
address
storageKeys
u_access_list_rpc_to_rlp_structure.<locals>.<genexpr>
u_access_list_rpc_to_rlp_structure.<locals>.<genexpr>.<locals>.<genexpr>
a_access_list_rlp_to_rpc_structure

Convert an rlp-structured transaction to a JSON-RPC-structured transaction.
is_rlp_structured_access_list
uprovided object not formatted as rlp-structured access list
u_access_list_rlp_to_rpc_structure.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
toolz
T aassoc
dissoc
ueth_account._utils.validation
T ais_rlp_structured_access_list
is_rpc_structured_access_list
ueth_account.types
T aAccessList
aRLPStructuredAccessList
aTransactionDictType
aAccessList
aRLPStructuredAccessList
aTransactionDictType
return
set_transaction_type_if_needed
transaction_rpc_to_rlp_structure
access_list
transaction_rlp_to_rpc_structure
ueth_account\_utils\transaction_utils.py
T a.0
wtT a.0
wdT a.0
w_T a.0
item
T a.0
type_1_arg
transaction_dict
T a.0
type_2_arg
transaction_dict
T a.0
type_3_arg
transaction_dict
u<module eth_account._utils.transaction_utils>
T aaccess_list
T atxn_dict
key
value
T atransaction_dict
T adictionary
access_list
rpc_structured_access_list
T adictionary
access_list
rlp_structured_access_list

a__spec__
.eth_account._utils.validation
]
is_binary_address
is_checksum_address
is_integer
is_0x_prefixed
aVALID_EMPTY_ADDRESSES
is_valid_address
is_list_like
is_dict
get
T aaddress
T astorageKeys
is_address
is_int_or_prefixed_hexstr
uReturns true if 'val' is a valid JSON-RPC structured access list.
u<genexpr>
uis_rpc_structured_access_list.<locals>.<genexpr>
uReturns true if 'val' is a valid rlp-structured access list.
is_bytes
is_hexstr
uis_sequence_of_bytes_or_hexstr.<locals>.<genexpr>
aHexBytes
item_bytes_size
T Oint
Ostr
Obytes
Obytearray
getenv
T aETH_ACCOUNT_KDF
scrypt
T apbkdf2
scrypt
uInvalid KDF type:

u. Must be one of 'pbkdf2' or 'scrypt'
cast
aKDFType
a__doc__
a__file__
origin
has_location
a__cached__
os
aAny
aOptional
ueth_keyfile.keyfile
T aKDFType
eth_utils
T ais_binary_address
is_checksum_address
is_dict
is_hexstr
ueth_utils.curried
T
apply_one_of_formatters
hexstr_if_str
is_0x_prefixed
is_address
is_bytes
is_integer
is_list_like
is_string
to_bytes
to_int
apply_one_of_formatters
hexstr_if_str
is_string
to_bytes
to_int
ueth_utils.toolz
T acurry
identity
curry
identity
hexbytes
T aHexBytes
S c

naval
return
is_none
value
is_empty_or_checksum_address
is_rpc_structured_access_list
is_rlp_structured_access_list
T nFacan_be_empty
is_sequence_of_bytes_or_hexstr
nonce
gasPrice
gas
to
c
u<lambda>
data
wvwrwsaLEGACY_TRANSACTION_FORMATTERS
chainId
aLEGACY_TRANSACTION_VALID_VALUES
validate_and_set_default_kdf
ueth_account\_utils\validation.py
T a.0
w_T a.0
item
T a.0
item
item_bytes_size
T aval
u<module eth_account._utils.validation>
T aval
item
address
storage_keys
storage_key
T aval
wdaaddress
storage_keys
storage_key
T avalue
item_bytes_size
can_be_empty
T avalue
T aos_kdf
a__spec__
.eth_account.account
a_use_unaudited_hdwallet_features

Use this flag to enable unaudited HD Wallet features.
text_if_str
to_bytes
keccak
urandom
T l acast
aLocalAccount
from_key

Creates a new private key, and returns it as a
:class:`~eth_account.local.LocalAccount`.
:param extra_entropy: Add extra randomness to whatever randomness your OS
can provide
:type extra_entropy: str or bytes or int
:returns: an object with private key and convenience methods
.. code-block:: python
>>> from eth_account import Account
>>> acct = Account.create('KEYSMASH FJAFJKLDSKF7JKFDJ 1530')
>>> acct.address
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> acct.key
HexBytes('0x8676e9a8c86c8921e922e61e0bb6e9e9689aad4c99082620610b00140e5f21b8')
# These methods are also available: sign_message(), sign_transaction(),
# encrypt().
# They correspond to the same-named methods in Account.*
# but without the private key argument
json
loads
is_dict
uThe keyfile should be supplied as a JSON string, or a dictionary.
aHexBytes
decode_keyfile_json

Decrypts a private key.
The key may have been encrypted using an Ethereum client or
:meth:`~Account.encrypt`.
:param keyfile_json: The encrypted key
:type keyfile_json: dict or str
:param str password: The password that was used to encrypt the key
:returns: the raw private key
:rtype: ~hexbytes.main.HexBytes
.. doctest:: python
>>> encrypted = {
... 'address': '5ce9454909639D2D17A3F753ce7d93fa0b9aB12E',
... 'crypto': {'cipher': 'aes-128-ctr',
...  'cipherparams': {'iv': '482ef54775b0cc59f25717711286f5c8'},
...  'ciphertext': 'cb636716a9fd46adbb31832d964df2082536edd5399a3393327dc89b0193a2be',
...  'kdf': 'scrypt',
...  'kdfparams': {},
...  'kdfparams': {'dklen': 32,
...                'n': 262144,
...                'p': 8,
...                'r': 1,
...                'salt': 'd3c9a9945000fcb6c9df0f854266d573'},
...  'mac': '4f626ec5e7fea391b2229348a65bfef532c2a4e8372c0a6a814505a350a7689d'},
... 'id': 'b812f3f9-78cc-462a-9e89-74418aa27cb0',
... 'version': 3}
>>> Account.decrypt(encrypted, 'password')
HexBytes('0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364')
keys
aPrivateKey
a_default_kdf
create_keyfile_json
T akdf
iterations

Creates a dictionary with an encrypted version of your private key.
To import this keyfile into Ethereum clients like geth and parity:
encode this dictionary with :func:`json.dumps` and save it to disk where your
client keeps key files.
:param private_key: The raw private key
:type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:param str password: The password which you will need to unlock the account
in your client
:param str kdf: The key derivation function to use when encrypting your
private key
:param int iterations: The work factor for the key derivation function
:returns: The data to use in your encrypted file
:rtype: dict
If kdf is not set, the default key derivation function falls back to the
environment variable :envvar:`ETH_ACCOUNT_KDF`. If that is not set, then
'scrypt' will be used as the default.
.. doctest:: python
>>> from pprint import pprint
>>> encrypted = Account.encrypt(
...     0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364,
...     'password'
... )
>>> pprint(encrypted)
{'address': '5ce9454909639D2D17A3F753ce7d93fa0b9aB12E',
'crypto': {'cipher': 'aes-128-ctr',
'cipherparams': {'iv': '...'},
'ciphertext': '...',
'kdf': 'scrypt',
'kdfparams': {'dklen': 32,
'n': 262144,
'p': 1,
'r': 8,
'salt': '...'},
'mac': '...'},
'id': '...',
'version': 3}
>>> with open('my-keyfile', 'w') as f: # doctest: +SKIP
...    f.write(json.dumps(encrypted))
a_parse_private_key

Returns a convenient object for working with the given private key.
:param private_key: The raw private key
:type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:return: object with methods for signing and encrypting
:rtype: LocalAccount
.. doctest:: python
>>> acct = Account.from_key(
... 0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364)
>>> acct.address
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> acct.key
HexBytes('0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364')
# These methods are also available: sign_message(), sign_transaction(),
# encrypt(). They correspond to the same-named methods in Account.*
# but without the private key argument
uThe use of the Mnemonic features of Account is disabled by default until its API stabilizes. To use these features, please enable them by running `Account.enable_unaudited_hdwallet_features()` and try again.
seed_from_mnemonic
key_from_seed

Generate an account from a mnemonic.
.. CAUTION:: This feature is experimental, unaudited, and likely to change soon
:param str mnemonic: space-separated list of BIP39 mnemonic seed words
:param str passphrase: Optional passphrase used to encrypt the mnemonic
:param str account_path: Specify an alternate HD path for deriving the seed
using BIP32 HD wallet key derivation.
:return: object with methods for signing and encrypting
:rtype: LocalAccount
.. doctest:: python
>>> from eth_account import Account
>>> Account.enable_unaudited_hdwallet_features()
>>> acct = Account.from_mnemonic(
...  "coral allow abandon recipe top tray caught video climb similar "
...  "prepare bracket antenna rubber announce gauge volume "
...  "hub hood burden skill immense add acid")
>>> acct.address
'0x9AdA5dAD14d925f4df1378409731a9B71Bc8569d'
# These methods are also available: sign_message(), sign_transaction(),
#  encrypt(). They correspond to the same-named methods in Account.*
# but without the private key argument
Or, generate multiple accounts from a mnemonic.
>>> from eth_account import Account
>>> Account.enable_unaudited_hdwallet_features()
>>> iterator = 0
>>> for i in range(10):
...     acct = Account.from_mnemonic(
...         "health embark april buyer eternal leopard "
...         "want before nominee head thing tackle",
...         account_path=f"m/44'/60'/0'/0/{iterator}")
...     iterator = iterator + 1
...     acct.address
'0x61Cc15522D06983Ac7aADe23f9d5433d38e78195'
'0x1240460F6E370f28079E5F9B52f9DcB759F051b7'
'0xd30dC9f996539826C646Eb48bb45F6ee1D1474af'
'0x47e64beb58c9A469c5eD086aD231940676b44e7C'
'0x6D39032ffEF9987988a069F52EFe4d95D0770555'
'0x3836A6530D1889853b047799Ecd8827255072e77'
'0xed5490dEfF8d8FfAe45cb4066C3daC7C6BFF6a22'
'0xf04F9Ff322799253bcC6B12762AD127570a092c5'
'0x900F7fa9fbe85BB25b6cdB94Da24D807f7feb213'
'0xa248e118b0D19010387b1B768686cd9B473FA137'
.. CAUTION:: For the love of Bob please do not use this mnemonic,
it is for testing purposes only.
generate_mnemonic
from_mnemonic

Create a new private key and related mnemonic.
.. CAUTION:: This feature is experimental, unaudited, and likely to change soon
Creates a new private key, and returns it as a
:class:`~eth_account.local.LocalAccount`, alongside the mnemonic that can
used to regenerate it using any BIP39-compatible wallet.
:param str passphrase: Extra passphrase to encrypt the seed phrase
:param int num_words: Number of words to use with seed phrase.
Default is 12 words.
Must be one of [12, 15, 18, 21, 24].
:param (Language, str) language: Language to use for BIP39 mnemonic seed phrase.
The use of a string is deprecated and will be
removed in a future version.
:param str account_path: Specify an alternate HD path for deriving the
seed using BIP32 HD wallet key derivation.
:returns: A tuple consisting of an object with private key and
convenience methods, and the mnemonic seed phrase that can be
used to restore the account.
:rtype: (LocalAccount, str)
.. doctest:: python
>>> from eth_account import Account
>>> Account.enable_unaudited_hdwallet_features()
>>> acct, mnemonic = Account.create_with_mnemonic()
>>> acct.address # doctest: +SKIP
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> acct == Account.from_mnemonic(mnemonic)
True
# These methods are also available:
# sign_message(), sign_transaction(), encrypt()
# They correspond to the same-named methods in Account.*
# but without the private key argument
a_hash_eip191_message
aChecksumAddress
a_recover_hash

Get the address of the account that signed the given message.
You must specify exactly one of: vrs or signature
:param signable_message: the message that was signed
:param vrs: the three pieces generated by an elliptic curve signature
:type vrs: tuple(v, r, s), each element is hex str, bytes or int
:param signature: signature bytes concatenated as r+s+v
:type signature: hex str or bytes or int
:returns: address of signer, hex-encoded & checksummed
:rtype: str
.. doctest:: python
>>> from eth_account.messages import encode_defunct
>>> from eth_account import Account
>>> message = encode_defunct(text="I   SF")
>>> vrs = (
...   28,
...   '0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb3',
...   '0x3e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce')
>>> Account.recover_message(message, vrs=vrs)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
# All of these recover calls are equivalent:
# variations on vrs
>>> vrs = (
...   '0x1c',
...   '0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb3',
...   '0x3e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce')
>>> Account.recover_message(message, vrs=vrs)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> # Caution about this approach: likely problems if there are leading 0s
>>> vrs = (
...   0x1c,
...   0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb3,
...   0x3e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce)
>>> Account.recover_message(message, vrs=vrs)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> vrs = (
...   b'\x1c',
...   b'\xe6\xca\x9b\xbaX\xc8\x86\x11\xfa\xd6jl\xe8\xf9\x96\x90\x81\x95Y8\x07\xc4\xb3\x8b\xd5(\xd2\xcf\xf0\x9dN\xb3',
...   b'>[\xfb\xbfM>9\xb1\xa2\xfd\x81jv\x80\xc1\x9e\xbe\xba\xf3\xa1A\xb29\x93J\xd4<\xb3?\xce\xc8\xce')
>>> Account.recover_message(message, vrs=vrs)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
# variations on signature
>>> signature = '0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb33e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce1c'
>>> Account.recover_message(message, signature=signature)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> signature = b'\xe6\xca\x9b\xbaX\xc8\x86\x11\xfa\xd6jl\xe8\xf9\x96\x90\x81\x95Y8\x07\xc4\xb3\x8b\xd5(\xd2\xcf\xf0\x9dN\xb3>[\xfb\xbfM>9\xb1\xa2\xfd\x81jv\x80\xc1\x9e\xbe\xba\xf3\xa1A\xb29\x93J\xd4<\xb3?\xce\xc8\xce\x1c'
>>> Account.recover_message(message, signature=signature)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
>>> # Caution about this approach: likely problems if there are leading 0s
>>> signature = 0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb33e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce1c
>>> Account.recover_message(message, signature=signature)
'0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
uThe message hash must be exactly 32-bytes
hexstr_if_str
to_int
to_standard_v
a_keys
aSignature
T avrs
to_standard_signature_bytes
T asignature_bytes
uYou must supply the vrs tuple or the signature bytes
recover_public_key_from_msg_hash
to_checksum_address
l aTypedTransaction
from_bytes
hash
vrs
aTransaction
hash_of_signed_transaction
vrs_from

Get the address of the account that signed this transaction.
:param serialized_transaction: the complete signed transaction
:type serialized_transaction: hex str, bytes or int
:returns: address of signer, hex-encoded & checksummed
:rtype: ChecksumAddress
.. doctest:: python
>>> raw_transaction = '0xf86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a009ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9ca0440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428'
>>> Account.recover_transaction(raw_transaction)
'0x2c7536E3605D9C16a7a3D7b1898e529396a65c23'
aKeyAPI

Change the backend used by the underlying eth-keys library.
*(The default is fine for most users)*
:param backend: any backend that works in
`eth_keys.KeyApi(backend)
<https://github.com/ethereum/eth-keys/#keyapibackendnone>`_
aSignedMessage
a_sign_hash

Sign the provided message.
This API supports any messaging format that will encode to EIP-191 messages.
If you would like historical compatibility with :meth:`w3.eth.sign() <web3.eth.Eth.sign>`
you can use :meth:`~eth_account.messages.encode_defunct`.
Other options are the "validator", or "structured data" standards.
You can import all supported message encoders in
``eth_account.messages``.
:param signable_message: the encoded message for signing
:param private_key: the key to sign the message with
:type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:returns: Various details about the signature - most importantly the
fields: v, r, and s
:rtype: ~eth_account.datastructures.SignedMessage
.. doctest:: python
>>> msg = "I   SF"
>>> from eth_account.messages import encode_defunct
>>> msghash = encode_defunct(text=msg)
>>> msghash
SignableMessage(version=b'E',
header=b'thereum Signed Message:\n6',
body=b'I\xe2\x99\xa5SF')
>>> # If you're curious about the internal fields of SignableMessage, take a look at EIP-191, linked above
>>> key = "0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364"
>>> Account.sign_message(msghash, key)
SignedMessage(message_hash=HexBytes('0x1476abb745d423bf09273f1afd887d951181d25adc66c4834a70491911b7f750'),
r=104389933075820307925104709181714897380569894203213074526835978196648170704563,
s=28205917190874851400050446352651915501321657673772411533993420917949420456142,
v=28,
signature=HexBytes('0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb33e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce1c'))
.. _EIP-191: https://eips.ethereum.org/EIPS/eip-191

Sign the provided hash.
.. WARNING:: *Never* sign a hash that you didn't generate,
it can be an arbitrary transaction. For example, it might
send all of your account's ether to an attacker.
Instead, prefer :meth:`~eth_account.account.Account.sign_message`,
which cannot accidentally sign a transaction.
:param message_hash: the 32-byte message hash to be signed
:type message_hash: hex str, bytes or int
:param private_key: the key to sign the message with
:type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:returns: Various details about the signature - most
importantly the fields: v, r, and s
:rtype: ~eth_account.datastructures.SignedMessage
sign_message_hash
T amessage_hash
wrwswvasignature
aMapping
utransaction_dict must be dict-like, got

from
address
dissoc
decode
ufrom field must match key's
u, but it was
sign_transaction_dict
a_key_obj
T ablobs
aSignedTransaction
T araw_transaction
hash
wrwswvu
Sign a transaction using a local private key.
It produces signature details and the hex-encoded transaction suitable for
broadcast using :meth:`w3.eth.sendRawTransaction()
<web3.eth.Eth.sendRawTransaction>`.
To create the transaction dict that calls a contract, use contract object:
`my_contract.functions.my_function().buildTransaction()
<http://web3py.readthedocs.io/en/latest/contracts.html#methods>`_
Note: For non-legacy (typed) transactions, if the transaction type is not
explicitly provided, it may be determined from the transaction parameters of
a well-formed transaction. See below for examples on how to sign with
different transaction types.
:param dict transaction_dict: the transaction with available keys, depending
on the type of transaction: nonce, chainId, to, data, value, gas, gasPrice,
type, accessList, maxFeePerGas, and maxPriorityFeePerGas
:param private_key: the private key to sign the data with
:type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:param blobs: optional list of blobs to sign in addition to the transaction
:type blobs: list of bytes or HexBytes
:returns: Various details about the signature - most
importantly the fields: v, r, and s
:rtype: SignedTransaction
.. doctest:: python
>>> # EIP-1559 dynamic fee transaction (more efficient and preferred over legacy txn)
>>> from eth_account import Account
>>> dynamic_fee_transaction = {
...     "type": 2,  # optional - can be implicitly determined based on max fee params
...     "gas": 100000,
...     "maxFeePerGas": 2000000000,
...     "maxPriorityFeePerGas": 2000000000,
...     "data": "0x616263646566",
...     "nonce": 34,
...     "to": "0x09616C3d61b3331fc4109a9E41a8BDB7d9776609",
...     "value": "0x5af3107a4000",
...     "accessList": (  # optional
...         {
...             "address": "0x0000000000000000000000000000000000000001",
...             "storageKeys": (
...                 "0x0100000000000000000000000000000000000000000000000000000000000000",
...             )
...         },
...     ),
...     "chainId": 1337,
... }
>>> key = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
>>> signed_df_tx = Account.sign_transaction(dynamic_fee_transaction, key)
>>> signed_df_tx
SignedTransaction(raw_transaction=HexBytes('0x02f8b28205392284773594008477359400830186a09409616c3d61b3331fc4109a9e41a8bdb7d9776609865af3107...d58b85d5'),
hash=HexBytes('0x2721b2ac99d878695e410af9e8968859b6f6e94f544840be0eb2935bead7deba'),
r=48949965662841329840326477994465373664672499148507933176648302825256944281697,
s=1123041608316060268133200864147951676126406077675157976022772782796802590165,
v=1)
>>> w3.eth.sendRawTransaction(signed_df_tx.raw_transaction)  # doctest: +SKIP
.. doctest:: python
>>> # legacy transaction (less efficient than EIP-1559 dynamic fee txn)
>>> from eth_account import Account
>>> legacy_transaction = {
...     # Note that the address must be in checksum format or native bytes:
...     'to': '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55',
...     'value': 1000000000,
...     'gas': 2000000,
...     'gasPrice': 234567897654321,
...     'nonce': 0,
...     'chainId': 1337
... }
>>> key = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
>>> signed_legacy_tx = Account.sign_transaction(legacy_transaction, key)
>>> signed_legacy_tx
SignedTransaction(raw_transaction=HexBytes('0xf86c8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca0080820a95a01a7...c0bfdb52'),
hash=HexBytes('0xd0a3e5dc7439f260c64cb0220139ec5dc7e016f82ce272a25a0f0b38fe751673'),
r=11971260903864915610009019893820767192081275151191539081612245320300335068143,
s=35365272040292958794699923036506252105590820339897221552886630515981233937234,
v=2709)
>>> w3.eth.sendRawTransaction(signed_legacy_tx.raw_transaction)  # doctest: +SKIP
.. doctest:: python
>>> from eth_account import Account
>>> access_list_transaction = {
...     "type": 1,  # optional - can be implicitly determined based on 'accessList' and 'gasPrice' params
...     "gas": 100000,
...     "gasPrice": 1000000000,
...     "data": "0x616263646566",
...     "nonce": 34,
...     "to": "0x09616C3d61b3331fc4109a9E41a8BDB7d9776609",
...     "value": "0x5af3107a4000",
...     "accessList": (
...         {
...             "address": "0x0000000000000000000000000000000000000001",
...             "storageKeys": (
...                 "0x0100000000000000000000000000000000000000000000000000000000000000",
...             )
...         },
...     ),
...     "chainId": 1337,
... }
>>> key = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
>>> signed_al_tx = Account.sign_transaction(access_list_transaction, key)
>>> signed_al_tx
SignedTransaction(raw_transaction=HexBytes('0x01f8ad82053922843b9aca00830186a09409616c3d61b3331fc4109a9e41a8bdb7d9776609865af3107a400086616...2b5043ea'),
hash=HexBytes('0xca9af2ef41691e06eb07e02125938fd9bb5a311e8daf330b264e77d6cdf3d17e'),
r=107355854401379915513092408112372039746594668141865279802319959599514133709188,
s=6729502936685237038651223791038758905953302464070244934323623239104475448298,
v=1)
>>> w3.eth.sendRawTransaction(signed_al_tx.raw_transaction)  # doctest: +SKIP
.. doctest:: python
>>> from eth_account import Account
>>> blob_transaction = {
...    "type": 3,  # optional - can be implicitly determined based on `maxFeePerBlobGas` param
...    "gas": 100000,
...    "maxFeePerGas": 2000000000,
...    "maxPriorityFeePerGas": 2000000000,
...    "maxFeePerBlobGas": 2000000000,
...    "data": "0x616263646566",
...    "nonce": 34,
...    "to": "0x09616C3d61b3331fc4109a9E41a8BDB7d9776609",
...    "value": "0x5af3107a4000",
...    "accessList": (  # optional
...        {
...            "address": "0x0000000000000000000000000000000000000001",
...            "storageKeys": (
...                "0x0100000000000000000000000000000000000000000000000000000000000000",
...            )
...        },
...    ),
...    "chainId": 1337,
... }
>>> empty_blob = b"\x00" * 32 * 4096  # 4096 empty 32-byte field elements
>>> key = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
>>> # The `blobVersionedHashes` transaction field is calculated from the `blobs` kwarg
>>> signed_blob_tx = Account.sign_transaction(blob_transaction, key, blobs=[empty_blob])
>>> signed_blob_tx
SignedTransaction(raw_transaction=HexBytes('0x03fa020147f8d98205392284773594008477359400830186a09409616c3d61b3331fc4109a9e41a8bdb7d97766098...00000000'),
hash=HexBytes('0xf9dc8867c4324fd7f4506622aa700989562770f01d7d681cef74a1a1deb9fea9'),
r=14319949980593194209648175507603206696573324965145502821772573913457715875718,
s=9129184742597516615341309773045281461399831333162885393648678700392065987233,
v=1)
>>> w3.eth.sendRawTransaction(signed_blob_tx.raw_transaction)  # doctest: +SKIP
aValidationError
uThe private key must be exactly 32 bytes long, instead of
u bytes.

Generate a :class:`eth_keys.datatypes.PrivateKey` from the provided key.
If the key is already of type :class:`eth_keys.datatypes.PrivateKey`,
return the key.
:param key: the private key from which a :class:`eth_keys.datatypes.PrivateKey`
will be generated
:type key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:returns: the provided key represented as a
:class:`eth_keys.datatypes.PrivateKey`
encode_typed_data

Sign the provided EIP-712 message with the provided key.
:param private_key: the key to sign the message with
:param domain_data: EIP712 domain data
:param message_types: custom types used by the `value` data
:param message_data: data to be signed
:param full_message: a dict containing all data and types
:type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
:type domain_data: dict
:type message_types: dict
:type message_data: dict
:type full_message: dict
:returns: Various details about the signature - most importantly the
fields: v, r, and s
:rtype: ~eth_account.datastructures.SignedMessage
You may supply the information to be encoded in one of two ways:
As exactly three arguments:
- ``domain_data``, a dict of the EIP-712 domain data
- ``message_types``, a dict of custom types (do not include a ``EIP712Domain``
key)
- ``message_data``, a dict of the data to be signed
Or as a single argument:
- ``full_message``, a dict containing the following keys:
- ``types``, a dict of custom types (may include a ``EIP712Domain`` key)
- ``primaryType``, (optional) a string of the primary type of the message
- ``domain``, a dict of the EIP-712 domain data
- ``message``, a dict of the data to be signed
.. WARNING:: Note that this code has not gone through an external audit, and
the test cases are incomplete.
See documentation for :meth:`~eth_account.messages.encode_typed_data` for usage details
See the `EIP-712 spec <https://eips.ethereum.org/EIPS/eip-712>`_ for more information.
.. doctest:: python
>>> # examples of basic usage
>>> from eth_account import Account
>>> # 3-argument usage
>>> # all domain properties are optional
>>> domain_data = {
...     "name": "Ether Mail",
...     "version": "1",
...     "chainId": 1,
...     "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
...     "salt": b"decafbeef",
... }
>>> # custom types
>>> message_types = {
...     "Person": [
...         {"name": "name", "type": "string"},
...         {"name": "wallet", "type": "address"},
...     ],
...     "Mail": [
...         {"name": "from", "type": "Person"},
...         {"name": "to", "type": "Person"},
...         {"name": "contents", "type": "string"},
...     ],
... }
>>> # the data to be signed
>>> message_data = {
...     "from": {
...         "name": "Cow",
...         "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
...     },
...     "to": {
...         "name": "Bob",
...         "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
...     },
...     "contents": "Hello, Bob!",
... }
>>> key = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
>>> signed_message = Account.sign_typed_data(key, domain_data, message_types, message_data)
>>> signed_message.message_hash
HexBytes('0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530')
>>> # 1-argument usage
>>> # all domain properties are optional
>>> full_message = {
...     "types": {
...         "EIP712Domain": [
...             {"name": "name", "type": "string"},
...             {"name": "version", "type": "string"},
...             {"name": "chainId", "type": "uint256"},
...             {"name": "verifyingContract", "type": "address"},
...             {"name": "salt", "type": "bytes32"},
...         ],
...         "Person": [
...             {"name": "name", "type": "string"},
...             {"name": "wallet", "type": "address"},
...         ],
...         "Mail": [
...             {"name": "from", "type": "Person"},
...             {"name": "to", "type": "Person"},
...             {"name": "contents", "type": "string"},
...         ],
...     },
...     "primaryType": "Mail",
...     "domain": {
...         "name": "Ether Mail",
...         "version": "1",
...         "chainId": 1,
...         "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
...         "salt": b"decafbeef"
...     },
...     "message": {
...         "from": {
...             "name": "Cow",
...             "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
...         },
...         "to": {
...             "name": "Bob",
...             "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
...         },
...         "contents": "Hello, Bob!",
...     },
... }
>>> signed_message_2 = Account.sign_typed_data(key, full_message=full_message)
>>> signed_message_2.message_hash
HexBytes('0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530')
>>> signed_message_2 == signed_message
True
.. _EIP-712: https://eips.ethereum.org/EIPS/eip-712
a__doc__
a__file__
origin
has_location
a__cached__
ucollections.abc
T aMapping
os
aAny
aDict
aOptional
aTuple
aTypeVar
aUnion
eth_keyfile
T acreate_keyfile_json
decode_keyfile_json
ueth_keyfile.keyfile
T aKDFType
aKDFType
eth_keys
T aKeyAPI
keys
ueth_keys.backends
T aCoinCurveECCBackend
aNativeECCBackend
aCoinCurveECCBackend
aNativeECCBackend
ueth_keys.datatypes
T aPrivateKey
ueth_keys.exceptions
T aValidationError
eth_typing
T aChecksumAddress
aHash32
aHexStr
aHash32
aHexStr
ueth_utils.curried
T acombomethod
hexstr_if_str
is_dict
keccak
text_if_str
to_bytes
to_int
combomethod
ueth_utils.toolz
T adissoc
hexbytes
T aHexBytes
ueth_account._utils.legacy_transactions
T aTransaction
vrs_from
ueth_account._utils.signing
T ahash_of_signed_transaction
sign_message_hash
sign_transaction_dict
to_standard_signature_bytes
to_standard_v
ueth_account._utils.validation
T avalidate_and_set_default_kdf
validate_and_set_default_kdf
ueth_account.account_local_actions
T aAccountLocalActions
aAccountLocalActions
ueth_account.datastructures
T aSignedMessage
aSignedTransaction
ueth_account.hdaccount
T aETHEREUM_DEFAULT_PATH
generate_mnemonic
key_from_seed
seed_from_mnemonic
aETHEREUM_DEFAULT_PATH
ueth_account.messages
T aSignableMessage
a_hash_eip191_message
encode_typed_data
aSignableMessage
ueth_account.signers.local
T aLocalAccount
ueth_account.typed_transactions
T aTypedTransaction
ueth_account.types
T aBlobs
aLanguage
aPrivateKeyType
aTransactionDictType
aBlobs
aLanguage
aPrivateKeyType
aTransactionDictType
aVRS
a__prepare__
aAccount
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
