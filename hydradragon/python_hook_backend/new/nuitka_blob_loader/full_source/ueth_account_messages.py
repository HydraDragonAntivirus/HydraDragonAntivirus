# Reconstructed from integrated Nuitka blob
# Module: ueth_account.messages


A message compatible with EIP-191_ that is ready to be signed.
The properties are components of an EIP-191_ signable message. Other message formats
can be encoded into this format for easy signing. This data structure doesn't need
to know about the original message format. For example, you can think of
EIP-712 as compiling down to an EIP-191 message.
In typical usage, you should never need to create these by hand. Instead, use
one of the available encode_* methods in this module, like:
- :meth:`encode_intended_validator`
- :meth:`encode_defunct`
- :meth:`encode_typed_data`
.. _EIP-191: https://eips.ethereum.org/EIPS/eip-191
a__qualname__
a__annotations__
bytes
a__orig_bases__
signable_message
return
T nD ahexstr
text
nnavalidator_address
primitive
hexstr
text
encode_intended_validator
defunct_hash_message
T nnnnadomain_data
message_types
message_data
full_message
encode_typed_data
ueth_account\messages.py
u<module eth_account.messages>
T a__class__
T asignable_message
version
joined
T aprimitive
hexstr
text
signable
hashed
T aprimitive
hexstr
text
message_bytes
msg_length
T avalidator_address
primitive
hexstr
text
canonical_address
message_bytes
Tadomain_data
message_types
message_data
full_message
full_message_types
full_message_domain
domain_data_keys
domain_types_keys
derived_primary_type
provided_primary_type
parsed_domain_data
parsed_message_types
parsed_message_data
a__spec__
.eth_account.signers.base
F
address

Equality test between two accounts.
Two accounts are considered the same if they are exactly the same type,
nd can sign for the same address.
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
aAny
eth_typing
T aChecksumAddress
aHash32
aChecksumAddress
aHash32
ueth_account.datastructures
T aSignedMessage
aSignedTransaction
aSignedMessage
aSignedTransaction
ueth_account.messages
T aSignableMessage
aSignableMessage
ueth_account.types
T aTransactionDictType
aTransactionDictType
a__prepare__
aBaseAccount
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
