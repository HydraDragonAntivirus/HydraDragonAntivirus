# Reconstructed from integrated Nuitka blob
# Module: ueth_typing.abi


TypedDict representing an `ABIElement` component.
a__qualname__
a__annotations__
str
name
type
components
a__orig_bases__
aABIComponentIndexed

TypedDict representing an indexed `ABIElement` component.
bool
indexed
aABIEvent

TypedDict to represent the `ABI` for an event.
event
anonymous
inputs
D atotal
FaABIFunctionType

TypedDict representing the `ABI` for all function types.
This is the base type for functions.
Please use ABIFunction, ABIConstructor, ABIFallback or ABIReceive instead.
T apure
view
nonpayable
payable
stateMutability
payable
constant
aABIFunction

TypedDict representing the `ABI` for a function.
function
outputs
aABIConstructor

TypedDict representing the `ABI` for a constructor function.
constructor
aABIFallback

TypedDict representing the `ABI` for a fallback function.
fallback
aABIReceive

TypedDict representing the `ABI` for a receive function.
receive
aABIError

TypedDict representing the `ABI` for an error.
error
aABICallable
aABIElement
aABIElementInfo

TypedDict to represent properties of an `ABIElement`, including the abi,
selector and arguments.
abi
selector
arguments
aABI
ueth_typing\abi.py
u<module eth_typing.abi>
T a__class__

a__spec__
.eth_typing.bls

Types used for BLS Signatures.
a__doc__
a__file__
origin
has_location
a__cached__
aNewType
T aBLSPubkey
Obytes
aBLSPubkey
T aBLSPrivateKey
Oint
aBLSPrivateKey
T aBLSSignature
Obytes
aBLSSignature
ueth_typing\bls.py
u<module eth_typing.bls>

a__spec__
.eth_typing
F
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_eth_typing
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
version
a__version
abi
T aABI
aABICallable
aABIComponent
aABIComponentIndexed
aABIConstructor
aABIElement
aABIElementInfo
aABIError
aABIEvent
aABIFallback
aABIFunction
aABIReceive
aDecodable
aTypeStr
aABI
aABICallable
aABIComponent
aABIComponentIndexed
aABIConstructor
aABIElement
aABIElementInfo
aABIError
aABIEvent
aABIFallback
aABIFunction
aABIReceive
aDecodable
aTypeStr
bls
T aBLSPrivateKey
aBLSPubkey
aBLSSignature
aBLSPrivateKey
aBLSPubkey
aBLSSignature
discovery
T aNodeID
aNodeID
encoding
T aHexStr
aPrimitives
aHexStr
aPrimitives
enums
T aForkName
aForkName
evm
T aAddress
aAnyAddress
aBlockIdentifier
aBlockNumber
aChecksumAddress
aHash32
aHexAddress
aAddress
aAnyAddress
aBlockIdentifier
aBlockNumber
aChecksumAddress
aHash32
aHexAddress
exceptions
T aMismatchedABI
aValidationError
aMismatchedABI
aValidationError
networks
T aURI
aChainId
aURI
aChainId
T aABI
aABICallable
aABIComponent
aABIComponentIndexed
aABIConstructor
aABIElement
aABIElementInfo
aABIError
aABIEvent
aABIFallback
aABIFunction
aABIReceive
aDecodable
aTypeStr
aBLSPrivateKey
aBLSPubkey
aBLSSignature
aNodeID
aHexStr
aPrimitives
aForkName
aAddress
aAnyAddress
aBlockIdentifier
aBlockNumber
aChecksumAddress
aHash32
aHexAddress
aMismatchedABI
aValidationError
aURI
aChainId
a__all__
u5.2.0
a__version__
ueth_typing\__init__.py
u<module eth_typing>

a__spec__
.eth_typing.discovery

Types for the Discovery Protocol.
a__doc__
a__file__
origin
has_location
a__cached__
aNewType
T aNodeID
Obytes
aNodeID
ueth_typing\discovery.py
u<module eth_typing.discovery>

a__spec__
.eth_typing.encoding

Types for encoding and decoding data.
a__doc__
a__file__
origin
has_location
a__cached__
aNewType
aUnion
T aHexStr
Ostr
aHexStr
T Obytes
Oint
Obool
aPrimitives
ueth_typing\encoding.py
u<module eth_typing.encoding>

a__spec__
.eth_typing.enums
%

Fork names for Ethereum network upgrades.
a__doc__
a__file__
origin
has_location
a__cached__
