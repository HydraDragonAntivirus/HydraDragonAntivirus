# Reconstructed from integrated Nuitka blob
# Module: ueth_account.signers.base


Specify convenience methods to sign transactions and message hashes.
a__qualname__
property
return

The checksummed public address for this account.
.. code-block:: python
>>> my_account.address # doctest: +SKIP
"0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
uBaseAccount.address
signable_message

Sign the EIP-191_ message.
This uses the same structure
s in :meth:`~eth_account.account.Account.sign_message`
but without specifying the private key.
:param signable_message: The encoded message, ready for signing
.. _EIP-191: https://eips.ethereum.org/EIPS/eip-191
sign_message
uBaseAccount.sign_message
message_hash

Sign the hash of a message.
.. WARNING:: *Never* sign a hash that you didn't generate,
it can be an arbitrary transaction. For example, it might
send all of your account's ether to an attacker.
Instead, prefer :meth:`~eth_account.account.Account.sign_message`,
which cannot accidentally sign a transaction.
This uses the same structure
s in :meth:`~eth_account.account.Account.unsafe_sign_hash`
but without specifying the private key.
:param bytes message_hash: 32 byte hash of the message to sign
unsafe_sign_hash
uBaseAccount.unsafe_sign_hash
transaction_dict

Sign a transaction dict.
This uses the same structure as in
:meth:`~eth_account.account.Account.sign_transaction`
but without specifying the private key.
:param dict transaction_dict: transaction with all fields specified
sign_transaction
uBaseAccount.sign_transaction
other
bool
a__eq__
uBaseAccount.__eq__
int
a__hash__
uBaseAccount.__hash__
a__orig_bases__
ueth_account\signers\base.py
u<module eth_account.signers.base>
T a__class__
T aself
other
T aself
T aself
signable_message
T aself
transaction_dict
T aself
message_hash

a__spec__
.eth_account.signers
7
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_account
u\not_existing
signers
T aNUITKA_PACKAGE_eth_account_signers
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ueth_account\signers\__init__.py
u<module eth_account.signers>

a__spec__
.eth_account.signers.local
q
a_publicapi
public_key
to_checksum_address
a_address
to_bytes
a_private_key
a_key_obj

Initialize a new account with the given private key.
:param eth_keys.PrivateKey key: to prefill in private key execution
:param ~eth_account.account.Account account: the key-unaware management API
key

Get the private key.
encrypt
T akdf
iterations

Generate a string with the encrypted key.
This uses the same structure as in
:meth:`~eth_account.account.Account.encrypt`, but without a
private key argument.
cast
aSignedMessage
unsafe_sign_hash
T aprivate_key
sign_message

Generate a string with the encrypted key.
This uses the same structure as in
:meth:`~eth_account.account.Account.sign_message`, but without a
private key argument.
aSignedTransaction
sign_transaction
T ablobs
sign_typed_data
T aprivate_key
domain_data
message_types
message_data
full_message

Sign the provided EIP-712 message with the local private key.
This uses the same structure as in
:meth:`~eth_account.account.Account.sign_typed_data`, but without a
private key argument.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aOptional
ueth_keyfile.keyfile
T aKDFType
aKDFType
ueth_keys.datatypes
T aPrivateKey
aPrivateKey
eth_typing
T aChecksumAddress
aHash32
aChecksumAddress
aHash32
ueth_account.account_local_actions
T aAccountLocalActions
aAccountLocalActions
ueth_account.datastructures
T aSignedMessage
aSignedTransaction
ueth_account.messages
T aSignableMessage
aSignableMessage
ueth_account.signers.base
T aBaseAccount
aBaseAccount
ueth_account.types
T aBlobs
aTransactionDictType
aBlobs
aTransactionDictType
a__prepare__
aLocalAccount
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
