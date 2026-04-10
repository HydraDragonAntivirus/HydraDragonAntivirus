# Reconstructed from integrated Nuitka blob
# Module: uens.exceptions


Base class for all ENS Errors
a__qualname__
a__orig_bases__
aENSValueError

An ENS exception wrapper for `ValueError`, for better control over
exception handling.
aENSTypeError

An ENS exception wrapper for `TypeError`, for better control over
exception handling.
aAddressMismatch

In order to set up reverse resolution correctly, the ENS name should first
point to the address. This exception is raised if the name does
not currently point to the address.
aIDNAError
aInvalidName

Raised if the provided name does not meet the normalization
standards specified in `ENSIP-15
<https://docs.ens.domains/ens-improvement-proposals/ensip-15-normalization-standard>`_.
aUnauthorizedError

Raised if the sending account is not the owner of the name
you are trying to modify. Make sure to set ``from`` in the
``transact`` keyword argument to the owner of the name.
aUnownedName

Raised if you are trying to modify a name that no one owns.
If working on a subdomain, make sure the subdomain gets created
first with :meth:`~ens.ENS.setup_address`.
aResolverNotFound

Raised if no resolver was found for the name you are trying to resolve.
aUnsupportedFunction

Raised if a resolver does not support a particular method.
aBidTooLow

Raised if you bid less than the minimum amount
aInvalidBidHash

Raised if you supply incorrect data to generate the bid hash.
aInvalidLabel

Raised if you supply an invalid label
aOversizeTransaction

Raised if a transaction you are trying to create would cost so
much gas that it could not fit in a block.
For example: when you try to start too many auctions at once.
aUnderfundedBid

Raised if you send less wei with your bid than you declared
s your intent to bid.
aENSValidationError

Raised if there is a validation error
uens\exceptions.py
u<module ens.exceptions>

a__spec__
.ens.utils
E
web3
T aWeb3
aWeb3
uweb3.eth
T aEth
aEth
cast
aBaseProvider
default
eth
T aens
modules
customize_web3
uweb3.middleware
T aStalecheckMiddlewareBuilder
aStalecheckMiddlewareBuilder
middleware_onion
get
T aens_name_to_address
remove
T astalecheck
build
aACCEPTABLE_STALE_HOURS
l  aadd
D aname
stalecheck
a_normalization
T anormalize_name_ensip15
normalize_name_ensip15
is_empty_name

T Obytes
Obytearray
decode
T uutf-8
name
as_text

Clean the fully qualified name, as defined in ENS `EIP-137
<https://github.com/ethereum/EIPs/blob/master/EIPS/eip-137.md#name-syntax>`_  # blocklint: pragma # noqa: E501
This does *not* enforce whether ``name`` is a label or fully qualified domain.
:param str name: the dot-separated ENS name
:raises InvalidName: if ``name`` has invalid syntax
d
normalize_name
split
T w.ato_bytes
T atext
aENSValidationError
uLabel at position
u too long after encoding.
c

Encode a name according to DNS standards specified in section 3.1
of RFC1035 with the following validations:
- There is no limit on the total length of the encoded name
nd the limit on labels is the ENS standard of 255.
- Return a single 0-octet, b'\x00', if empty name.
:param str name: the dot-separated ENS name
aInvalidName

Validate whether the fully qualified name is valid, as defined in ENS `EIP-137
<https://github.com/ethereum/EIPs/blob/master/EIPS/eip-137.md#name-syntax>`_  # blocklint: pragma # noqa: E501
:param str name: the dot-separated ENS name
:returns: True if ``name`` is set, and :meth:`~ens.ENS.nameprep` will not
raise InvalidName
datetime
fromtimestamp
timezone
utc
encode
keccak
w.aENSValueError
uCannot generate hash for label
u with a '.'
aEMPTY_SHA3_BYTES
label_to_hash
node

Hashes a pre-normalized name.
The normalization of the name is a prerequisite and is not handled by this function.
:param str name: A normalized name string to be hashed.
:return: namehash - the hash of the name
:rtype: HexBytes
normal_name_to_hash

Generate the namehash. This is also known as the ``node`` in ENS contracts.
In normal operation, generating the namehash is handled
behind the scenes. For advanced usage, it is a helpful utility.
This normalizes the name with `nameprep
<https://github.com/ethereum/EIPs/blob/master/EIPS/eip-137.md#name-syntax>`_  # blocklint: pragma # noqa: E501
before hashing.
:param str name: ENS name to hash
:return: the namehash
:rtype: bytes
:raises InvalidName: if ``name`` has invalid syntax
is_same_address
address
u<genexpr>
uaddress_in.<locals>.<genexpr>
remove_0x_prefix
aHexStr
to_normalized_address
aREVERSE_REGISTRAR_DOMAIN
aAUCTION_START_GAS_CONSTANT
aAUCTION_START_GAS_MARGINAL
T uYou must specify the sending account
from
aENSTypeError
aEMPTY_ADDR_HEX
strip
P u
w.ais_valid_name
T aAsyncWeb3
aAsyncWeb3
T aAsyncEth
aAsyncEth
aAsyncBaseProvider
ens_name_to_address
middleware
stalecheck
append
T amiddleware
ens
modules
uinit_async_web3.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
T adatetime
timezone
aTYPE_CHECKING
aAny
aCollection
aOptional
aSequence
aTuple
aType
aUnion
eth_typing
T aAddress
aChecksumAddress
aHexAddress
aHexStr
aAddress
aChecksumAddress
aHexAddress
eth_utils
T ais_same_address
remove_0x_prefix
to_bytes
to_normalized_address
hexbytes
T aHexBytes
aHexBytes
uens.exceptions
T aENSTypeError
aENSValueError
constants
T aACCEPTABLE_STALE_HOURS
aAUCTION_START_GAS_CONSTANT
aAUCTION_START_GAS_MARGINAL
aEMPTY_ADDR_HEX
aEMPTY_SHA3_BYTES
aREVERSE_REGISTRAR_DOMAIN
exceptions
T aENSValidationError
aInvalidName
return
a_Web3
T nnaprovider
T aMiddleware
Ostr
init_web3
D aw3
return
a_Web3
a_Web3
D aname
return
Ostr
pD aname
return
Ostr
Obytes
ens_encode_name
D aname
return
Ostr
Obool
timestamp
to_utc_datetime
val
T Ostr
Obytes
sha3_text
label
raw_name_to_hash
addresses
address_in
address_to_reverse_domain
labels
estimate_auction_start_gas
modifier_kwargs
assert_signer_in_modifier_kwargs
addr
is_none_or_zero_address
D aens_name
return
Ostr
Obool
is_valid_ens_name
T nT
init_async_web3
uens\utils.py
T a.0
item
address
T a.0
mw
name
u<module ens.utils>
T aWeb3Main
T aaddress
addresses
T aaddress
lower_unprefixed_address
T amodifier_kwargs
aERR_MSG
a_modifier_type
modifier_dict
T aw3
aStalecheckMiddlewareBuilder
stalecheck_middleware
T aname
normalized_name
labels
labels_as_bytes
index
label
dns_prepped_labels
T alabels
T	aprovider
middleware
aAsyncWeb3Main
aAsyncEthMain
aStalecheckMiddlewareBuilder
wia_mw
name
async_w3
T aprovider
middleware
aWeb3Main
aEthMain
w3
T aname
T aaddr
T aens_name
split_domain
name
T alabel
T aname
node
labels
label
labelhash
T aname
normalize_name_ensip15
T aname
normalized_name
T aval
T atimestamp
a__spec__
.eth_abi.abi
a__doc__
a__file__
origin
has_location
a__cached__
ueth_abi.codec
T aABICodec
aABICodec
ueth_abi.registry
T aregistry
registry
default_codec
encode
decode
is_encodable
is_encodable_type
ueth_abi\abi.py
u<module eth_abi.abi>

a__spec__
.eth_abi.base
A
decorator
uparse_type_str.<locals>.decorator

Used by BaseCoder subclasses as a convenience for implementing the
``from_type_str`` method required by ``ABIRegistry``.  Useful if normalizing
then parsing a type string with an (optional) expected base is required in
that method.
wraps
new_from_type_str
uparse_type_str.<locals>.decorator.<locals>.new_from_type_str
normalize
parse
u{} (normalized to {})
expected_base
aBasicType
uCannot create {} for non-basic type {}
a__name__
base
uCannot create {} for type {}: expected type with base '{}'
with_arrlist
arrlist
uCannot create {} for type {}: expected type with no array dimension list
uCannot create {} for type {}: expected type with array dimension list
validate
old_from_type_str
uparse_tuple_type_str.<locals>.new_from_type_str

Used by BaseCoder subclasses as a convenience for implementing the
``from_type_str`` method required by ``ABIRegistry``.  Useful if normalizing
then parsing a tuple type string is required in that method.
aTupleType
uCannot create {} for non-tuple type {}
uProperty {key} not found on {cls_name} class. `{cls_name}.__init__` only accepts keyword arguments which are present on the {cls_name} class.
T akey
cls_name
uMust implement `from_type_str`

Used by :any:`ABIRegistry` to get an appropriate encoder or decoder
instance for the given type string and type registry.
a__doc__
a__file__
origin
has_location
a__cached__
functools
grammar
T aBasicType
aTupleType
normalize
parse
T nFaparse_type_str
parse_tuple_type_str
