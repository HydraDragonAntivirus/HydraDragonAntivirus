# Reconstructed from integrated Nuitka blob
# Module: uens.base_ens

aBaseENS
a__qualname__
a__annotations__
T aAsyncWeb3
aWeb3
ens
T aContract
aAsyncContract
aContract
aAsyncContract
D areturn
Obool
uBaseENS.strict_bytes_type_checking
setter
D astrict_bytes_type_check
return
Obool
nalabel
return
labelhash
uBaseENS.labelhash
namehash
uBaseENS.namehash
D aname
return
Ostr
panameprep
uBaseENS.nameprep
D aname
return
Ostr
Obool
uBaseENS.is_valid_name
address
reverse_domain
uBaseENS.reverse_domain
parent
uBaseENS.parent
contract_call_result
extended_resolver
fn_name
a_decode_ensip10_resolve_data
uBaseENS._decode_ensip10_resolve_data
func
a_type_aware_resolver
uBaseENS._type_aware_resolver
uens\base_ens.py
u<module ens.base_ens>
T a__class__
T aself
contract_call_result
extended_resolver
fn_name
func
output_types
decoded
T aself
address
func
T aname
T alabel
T aname
labels
T aself
T aself
strict_bytes_type_check
a__spec__
.ens
$
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_ens
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
async_ens
T aAsyncENS
aAsyncENS
base_ens
T aBaseENS
aBaseENS
ens
T aENS
aENS
exceptions
T aAddressMismatch
aBidTooLow
aInvalidLabel
aInvalidName
aUnauthorizedError
aUnderfundedBid
aUnownedName
aAddressMismatch
aBidTooLow
aInvalidLabel
aInvalidName
aUnauthorizedError
aUnderfundedBid
aUnownedName
L
aAsyncENS
aBaseENS
aENS
aAddressMismatch
aBidTooLow
aInvalidLabel
aInvalidName
aUnauthorizedError
aUnderfundedBid
aUnownedName
a__all__
uens\__init__.py
u<module ens>

a__spec__
.ens.constants
l
/
a__doc__
a__file__
origin
has_location
a__cached__
eth_typing
T aChecksumAddress
aHexAddress
aHexStr
aChecksumAddress
aHexAddress
aHexStr
hexbytes
T aHexBytes
aHexBytes
l0aACCEPTABLE_STALE_HOURS
l   aAUCTION_START_GAS_CONSTANT
l   aAUCTION_START_GAS_MARGINAL
T b
aEMPTY_SHA3_BYTES
T u0x0000000000000000000000000000000000000000
aEMPTY_ADDR_HEX
uaddr.reverse
aREVERSE_REGISTRAR_DOMAIN
T u0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
aENS_MAINNET_ADDR
T u0x3b3b57de
aENS_ADDR_INTERFACE_ID
T u0x691f3431
aENS_NAME_INTERFACE_ID
T u0x2203ab56
aENS_ABI_INTERFACE_ID
T u0xc8690233
aENS_PUBLIC_KEY_INTERFACE_ID
T u0x59d1d43c
aENS_TEXT_INTERFACE_ID
T u0xbc1c58d1
aENS_CONTENT_HASH_INTERFACE_ID
T u0xf1cb7e06
aENS_MULTICHAIN_ADDRESS_INTERFACE_ID
T u0x9061b923
aENS_EXTENDED_RESOLVER_INTERFACE_ID
uens\constants.py
u<module ens.constants>

a__spec__
.ens.ens
w+
cast
aBaseProvider
default
init_web3
w3
aENS_MAINNET_ADDR
eth
contract
abis
aENS
T aabi
address
ens
aPUBLIC_RESOLVER_2_EXTENDED
T aabi
a_resolver_contract
aREVERSE_RESOLVER
a_reverse_resolver_contract

:param provider: a single provider used to connect to Ethereum
:type provider: instance of `web3.providers.base.BaseProvider`
:param hex-string addr: the address of the ENS registry on-chain.
If not provided, ENS.py will default to the mainnet ENS
registry address.
manager
provider
middleware_onion
middleware
T aaddr
middleware
strict_bytes_type_checking

Generate an ENS instance from a Web3 instance
:param `web3.Web3` w3: to infer connection, middleware, and codec information
:param hex-string addr: the address of the ENS registry on-chain. If not
provided, defaults to the mainnet ENS registry address.
aChecksumAddress
a_resolve
addr
resolver
a_validate_resolver_and_interface_id
aENS_MULTICHAIN_ADDRESS_INTERFACE_ID
uaddr(bytes32,uint256)
raw_name_to_hash
caller
is_none_or_zero_address
to_checksum_address

Look up the Ethereum address that `name` currently points to.
:param str name: an ENS name to look up
:param int coin_type: if provided, look up the address for this coin type
:raises InvalidName: if `name` has invalid syntax
:raises ResolverNotFound: if no resolver found for `name`
:raises UnsupportedFunction: if the resolver does not support the ``addr()``
function
deepcopy
setup_owner
T atransact
a_assert_control
is_binary_address
is_checksum_address
aENSValueError
T uYou must supply the address in checksum format
address
aEMPTY_ADDR_HEX
from
a_set_resolver
functions
setAddr
transact

Set up the name to point to the supplied address.
The sender of the transaction must own the name, or
its parent name.
Example: If the caller owns ``parentname.eth`` with no subdomains
nd calls this method with ``sub.parentname.eth``,
then ``sub`` will be created as part of this call.
:param str name: ENS name to set up
:param str address: name will point to this address, in checksum format.
If ``None``, erase the record. If not specified, name will point
to the owner's address.
:param int coin_type: if provided, set up the address for this coin type
:param dict transact: the transaction configuration, like in
:meth:`~web3.eth.Eth.send_transaction`
:raises InvalidName: if ``name`` has invalid syntax
:raises UnauthorizedError: if ``'from'`` in `transact` does not own `name`
address_to_reverse_domain
D afn_name
name

Look up the name that the address points to, using a
reverse lookup. Reverse lookup is opt-in for name owners.
:param address:
:type address: hex-string
uthe reverse record
a_setup_reverse
aAddressMismatch
uCould not set address

u to point to name, because the name resolves to
u. To change the name for an existing address, call setup_address() first.
owner
aUnownedName
T uclaim subdomain using setup_address() first
setup_address

Set up the address for reverse lookup, aka "caller ID".
After successful setup, the method :meth:`~ens.ENS.name` will return
`name` when supplied with `address`.
:param str name: ENS name that address will point to
:param str address: address to set up, in checksum format
:param dict transact: the transaction configuration, like in
:meth:`~web3.eth.send_transaction`
:raises AddressMismatch: if the name does not already point to the address
:raises InvalidName: if `name` has invalid syntax
:raises UnauthorizedError: if ``'from'`` in `transact` does not own `name`
:raises UnownedName: if no one owns `name`

Get the owner of a name. Note that this may be different from the
deed holder in the '.eth' registrar. Learn more about the difference
between deed and name ownership in the ENS `Managing Ownership docs
<http://docs.ens.domains/en/latest/userguide.html#managing-ownership>`_
:param str name: ENS name to look up
:return: owner address
:rtype: str
a_first_owner
a_claim_ownership

Set the owner of the supplied name to `new_owner`.
For typical scenarios, you'll never need to call this method directly,
simply call :meth:`setup_name` or :meth:`setup_address`. This method does *not*
set up the name to point to an address.
If `new_owner` is not supplied, then this will assume you
want the same owner as the parent domain.
If the caller owns ``parentname.eth`` with no subdomains
nd calls this method with ``sub.parentname.eth``,
then ``sub`` will be created as part of this call.
:param str name: ENS name to set up
:param new_owner: account that will own `name`. If ``None``, set owner to
empty addr. If not specified, name will point to the parent domain
owner's address.
:param dict transact: the transaction configuration, like in
:meth:`~web3.eth.Eth.send_transaction`
:raises InvalidName: if `name` has invalid syntax
:raises UnauthorizedError: if ``'from'`` in `transact` does not own `name`
:returns: the new owner's address
normalize_name
a_get_resolver

Get the resolver for an ENS name.
:param str name: The ENS name
aENS_TEXT_INTERFACE_ID
text

Get the value of a text record by key from an ENS name.
:param str name: ENS name to look up
:param str key: ENS name's text record key
:return: ENS name's text record value
:rtype: str
:raises UnsupportedFunction: If the resolver does not support
the "0x59d1d43c" interface id
:raises ResolverNotFound: If no resolver is found for the provided name
a_set_property
setText

Set the value of a text record of an ENS name.
:param str name: ENS name
:param str key: Name of the attribute to set
:param str value: Value to set the attribute to
:param dict transact: The transaction configuration, like in
:meth:`~web3.eth.Eth.send_transaction`
:return: Transaction hash
:rtype: HexBytes
:raises UnsupportedFunction: If the resolver does not support
the "0x59d1d43c" interface id
:raises ResolverNotFound: If no resolver is found for the provided name
is_empty_name
current_name
self
normal_name_to_hash
aContract
a_type_aware_resolver
parent
T uresolver.eth
resolver_addr
setResolver
T aaddress
namehash
a_resolver_supports_interface
aENS_EXTENDED_RESOLVER_INTERFACE_ID
encode_abi
resolve
ens_encode_name
a_decode_ensip10_resolve_data
is_address
call
address_in
accounts
aUnauthorizedError
uin order to modify
u, you must control account
u, which owns
split
T w.apieces
w.aunowned
pop
T l
name

Takes a name, and returns the owner of the deepest subdomain that has an owner
:returns: (owner or None, list(unowned_subdomain_labels), first_owned_domain)
setSubnodeOwner
owned
label_to_hash
a_reverse_registrar
setName
aREVERSE_REGISTRAR_DOMAIN
aREVERSE_REGISTRAR
T aaddress
abi
merge
aResolverNotFound
uNo resolver found for name `
u`. It is likely the name contains an unsupported top level domain (tld).
aUnsupportedFunction
uResolver for name `
u` does not support the `
u` interface.
all_functions
supportsInterface
u<genexpr>
u_resolver_supports_interface.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
copy
T adeepcopy
aTYPE_CHECKING
aAny
aOptional
aSequence
aTuple
aUnion
eth_typing
T aAddress
aChecksumAddress
aHexAddress
aHexStr
aAddress
aHexAddress
aHexStr
eth_utils
T ais_address
is_binary_address
is_checksum_address
to_checksum_address
ueth_utils.toolz
T amerge
hexbytes
T aHexBytes
aHexBytes
T aabis
base_ens
T aBaseENS
aBaseENS
constants
T aEMPTY_ADDR_HEX
aENS_EXTENDED_RESOLVER_INTERFACE_ID
aENS_MAINNET_ADDR
aENS_MULTICHAIN_ADDRESS_INTERFACE_ID
aENS_TEXT_INTERFACE_ID
aREVERSE_REGISTRAR_DOMAIN
exceptions
T aAddressMismatch
aENSValueError
aResolverNotFound
aUnauthorizedError
aUnownedName
aUnsupportedFunction
utils
T aaddress_in
address_to_reverse_domain
default
ens_encode_name
init_web3
is_empty_name
is_none_or_zero_address
label_to_hash
normal_name_to_hash
normalize_name
raw_name_to_hash
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
