# Reconstructed from integrated Nuitka blob
# Module: ueth_account.hdaccount.mnemonic


Creates and validates BIP39 mnemonics.
.. doctest:: python
>>> from eth_account.hdaccount import Language, Mnemonic
>>> # Create a new Mnemonic instance with Czech language
>>> cz_mnemonic = Mnemonic(Language.CZECH)
>>> # English is the default language
>>> en_mnemonic = Mnemonic()
>>> # List available languages
>>> available_languages = Mnemonic.list_languages()
>>> print(available_languages)
['chinese_simplified', 'chinese_traditional', 'czech', 'english', 'french', 'italian', 'japanese', 'korean', 'spanish']
>>> # List available enumerated languages
>>> available_languages = Mnemonic.list_languages_enum()
>>> print(available_languages)
[<Language.CHINESE_SIMPLIFIED: 'chinese_simplified'>, <Language.CHINESE_TRADITIONAL: 'chinese_traditional'>, <Language.CZECH: 'czech'>, <Language.ENGLISH: 'english'>, <Language.FRENCH: 'french'>, <Language.ITALIAN: 'italian'>, <Language.JAPANESE: 'japanese'>, <Language.KOREAN: 'korean'>, <Language.SPANISH: 'spanish'>]
>>> # Generate a new mnemonic phrase
>>> mnemonic_phrase = en_mnemonic.generate()
>>> print(mnemonic_phrase) # doctest: +SKIP
'cabin raise oven oven knock fantasy flock letter click empty skate volcano'
>>> # Validate a mnemonic phrase
>>> is_valid = en_mnemonic.is_mnemonic_valid(mnemonic_phrase)
>>> print(is_valid)
True
>>> # Convert mnemonic phrase to seed
>>> seed = en_mnemonic.to_seed(mnemonic_phrase, passphrase="optional passphrase")
>>> print(seed) # doctest: +SKIP
b'\x97ii\x07\x12\xf0$\x81\x98\xb6?\x07\x08t7\x18d\x87\xe1\x7f\xbe\xbaL\xb4i%\xeb\x12\xce\xe2h\x1c\xb2\x19\x13\xfb9wtoV\x9c\xb8\xdf;5\xba4X\xa3\xd6b`|\xdc\xb1\x10\xb0\xeeS\x86\x95\xd75'
a__qualname__
aENGLISH
raw_language
a__init__
uMnemonic.__init__
uMnemonic.list_languages
list_languages_enum
uMnemonic.list_languages_enum
raw_mnemonic
detect_language
uMnemonic.detect_language
T l D anum_words
return
Oint
Ostr
generate
uMnemonic.generate
D aentropy
return
Obytes
Ostr
uMnemonic.to_mnemonic
D amnemonic
return
Ostr
Obool
is_mnemonic_valid
uMnemonic.is_mnemonic_valid
D aprefix
return
Ostr
puMnemonic.expand_word
D amnemonic
return
Ostr
paexpand
uMnemonic.expand
T u
D achecked_mnemonic
passphrase
return
Ostr
pObytes
to_seed
uMnemonic.to_seed
ueth_account\hdaccount\mnemonic.py
T a.0
lang
T a.0
wwaself
T a.0
wfT a.0
wiabits
T a.0
idx
self
u<module eth_account.hdaccount.mnemonic>
T a__class__
T aself
raw_language
language
languages
T acls
raw_mnemonic
mnemonic
words
matching_languages
language
T aself
mnemonic
T aself
prefix
matches
T aself
num_words
T alanguage
wfawordlist
T aself
mnemonic
words
num_words
indices
encoded_seed
idx
entropy_size
checksum
computed_checksum
stored_checksum
T aself
entropy
entropy_size
bits
checksum
indices
words
phrase
T acls
checked_mnemonic
passphrase
mnemonic
salt
stretched
a__spec__
.eth_account.messages
35
m
version
aValidationError
uThe supplied message version is

u. The EIP-191 signable message standard only supports one-byte versions.
d aheader
body
aHash32
keccak
is_valid_address
uCannot encode message with 'Validator Address':
u. It must be a checksum address, or an address converted to bytes.
to_canonical_address
to_bytes
T ahexstr
text
aSignableMessage
aHexBytes
T d

Encode a message using the "intended validator" approach (ie~ version 0)
defined in EIP-191_.
Supply the message as exactly one of these three arguments:
bytes as a primitive, a hex string, or a unicode string.
.. WARNING:: Note that this code has not gone through an external audit.
:param validator_address: which on-chain contract is capable of validating this
message, provided as a checksummed address or in native bytes.
:param primitive: the binary message to be signed
:type primitive: bytes or int
:param str hexstr: the message encoded as hex
:param str text: the message as a series of unicode characters (a normal Py3 str)
:returns: The EIP-191 encoded message, ready for signing
.. _EIP-191: https://eips.ethereum.org/EIPS/eip-191
encode
T uutf-8
dEcthereum Signed Message:

Encode a message for signing, using an old, unrecommended approach.
Only use this method if you must have compatibility with
:meth:`w3.eth.sign() <web3.eth.Eth.sign>`.
EIP-191 defines this as "version ``E``".
.. NOTE: This standard includes the number of bytes in the message as a part of
the header. Awkwardly, the number of bytes in the message is encoded in
decimal ascii. So if the message is 'abcde', then the length is encoded
s the ascii character '5'. This is one of the reasons that this message
format is not preferred. There is ambiguity when the message '00' is
encoded, for example.
Supply exactly one of the three arguments: bytes, a hex string, or a unicode string.
:param primitive: the binary message to be signed
:type primitive: bytes or int
:param str hexstr: the message encoded as hex
:param str text: the message as a series of unicode characters (a normal Py3 str)
:returns: The EIP-191 encoded message, ready for signing
.. doctest:: python
>>> from eth_account.messages import encode_defunct
>>> from eth_utils.curried import to_hex, to_bytes
>>> message_text = "I   SF"
>>> encode_defunct(text=message_text)
SignableMessage(version=b'E',
header=b'thereum Signed Message:\n6',
body=b'I\xe2\x99\xa5SF')
These four also produce the same hash:
>>> encode_defunct(to_bytes(text=message_text))
SignableMessage(version=b'E',
header=b'thereum Signed Message:\n6',
body=b'I\xe2\x99\xa5SF')
>>> encode_defunct(bytes(message_text, encoding='utf-8'))
SignableMessage(version=b'E',
header=b'thereum Signed Message:\n6',
body=b'I\xe2\x99\xa5SF')
>>> to_hex(text=message_text)
'0x49e299a55346'
>>> encode_defunct(hexstr='0x49e299a55346')
SignableMessage(version=b'E',
header=b'thereum Signed Message:\n6',
body=b'I\xe2\x99\xa5SF')
>>> encode_defunct(0x49e299a55346)
SignableMessage(version=b'E',
header=b'thereum Signed Message:\n6',
body=b'I\xe2\x99\xa5SF')
encode_defunct
a_hash_eip191_message

Convert the provided message into a message hash, to be signed.
.. CAUTION:: Intended for use with
:meth:`eth_account.account.Account.unsafe_sign_hash`.
This is for backwards compatibility only. All new implementations
should use :meth:`encode_defunct` instead.
:param primitive: the binary message to be signed
:type primitive: bytes or int
:param str hexstr: the message encoded as hex
:param str text: the message as a series of unicode characters (a normal Py3 str)
:returns: The hash of the message, after adding the prefix
uYou may supply either `full_message` as a single argument or `domain_data`, `message_types`, and `message_data` as three arguments, but not both.
types
copy
domain
aEIP712Domain
keys
name
uThe fields provided in `domain` do not match the fields provided in `types.EIP712Domain`. The fields provided in `domain` were `
u`, but the fields provided in `types.EIP712Domain` were `
u`.
pop
T aEIP712Domain
naprimaryType
get_primary_type
uThe provided `primaryType` does not match the derived `primaryType`. The provided `primaryType` was `
u`, but the derived `primaryType` was `
message
T d ahash_domain
hash_eip712_message

Encode an EIP-712_ message in a manner compatible with other implementations
in use, such as the Metamask and Ethers ``signTypedData`` functions.
See the `EIP-712 spec <https://eips.ethereum.org/EIPS/eip-712>`_ for more information.
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
Type Coercion:
- For fixed-size bytes types, smaller values will be padded to fit in larger
types, but values larger than the type will raise ``ValueOutOfBounds``.
e.g., an 8-byte value will be padded to fit a ``bytes16`` type, but 16-byte
value provided for a ``bytes8`` type will raise an error.
- Fixed-size and dynamic ``bytes`` types will accept ``int``s. Any negative
values will be converted to ``0`` before being converted to ``bytes``
- ``int`` and ``uint`` types will also accept strings. If prefixed with ``"0x"``
, the string will be interpreted as hex. Otherwise, it will be interpreted as
decimal.
Noteable differences from ``signTypedData``:
- Custom types that are not alphanumeric will encode differently.
- Custom types that are used but not defined in ``types`` will not encode.
:param domain_data: EIP712 domain data
:param message_types: custom types used by the `value` data
:param message_data: data to be signed
:param full_message: a dict containing all data and types
:returns: a ``SignableMessage``, an encoded message ready to be signed
.. doctest:: python
>>> # examples of basic usage
>>> from eth_account import Account
>>> from eth_account.messages import encode_typed_data
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
>>> signable_message = encode_typed_data(domain_data, message_types, message_data)
>>> signed_message = Account.sign_message(signable_message, key)
>>> signed_message.message_hash
HexBytes('0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530')
>>> # the message can be signed in one step using Account.sign_typed_data
>>> signed_typed_data = Account.sign_typed_data(key, domain_data, message_types, message_data)
>>> signed_typed_data == signed_message
True
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
>>> signable_message_2 = encode_typed_data(full_message=full_message)
>>> signed_message_2 = Account.sign_message(signable_message_2, key)
>>> signed_message_2.message_hash
HexBytes('0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530')
>>> signed_message_2 == signed_message
True
>>> # the full_message can be signed in one step using Account.sign_typed_data
>>> signed_typed_data_2 = Account.sign_typed_data(key, domain_data, message_types, message_data)
>>> signed_typed_data_2 == signed_message_2
True
.. _EIP-712: https://eips.ethereum.org/EIPS/eip-712
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
aNamedTuple
aOptional
aUnion
eth_typing
T aAddress
aHash32
aAddress
ueth_utils.curried
T aValidationError
keccak
text_if_str
to_bytes
to_canonical_address
text_if_str
hexbytes
T aHexBytes
ueth_account._utils.encode_typed_data.encoding_and_hashing
T aget_primary_type
hash_domain
hash_eip712_message
ueth_account._utils.validation
T ais_valid_address
text_to_bytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
