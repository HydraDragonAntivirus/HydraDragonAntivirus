# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.base


Base class for all encoder and decoder classes.
aBaseCoder
a__qualname__
is_dynamic
a__init__
uBaseCoder.__init__
uBaseCoder.validate
from_type_str
uBaseCoder.from_type_str
ueth_abi\base.py
u<module eth_abi.base>
T aself
kwargs
cls
key
value
T aold_from_type_str
new_from_type_str
T aexpected_base
with_arrlist
T acls
type_str
registry
T acls
type_str
registry
normalized_type_str
abi_type
type_str_repr
old_from_type_str
T aold_from_type_str
T	acls
type_str
registry
normalized_type_str
abi_type
type_str_repr
expected_base
with_arrlist
old_from_type_str
T aexpected_base
old_from_type_str
with_arrlist
T aexpected_base
with_arrlist
decorator
T aself

a__spec__
.eth_abi.codec
\
a_registry

Constructor.
:param registry: The registry providing the encoders to be used when
encoding values.
validate_list_like_param
types
args
self
get_encoder
aTupleEncoder
T aencoders

Encodes the python values in ``args`` as a sequence of binary values of
the ABI types in ``types`` via the head-tail mechanism.
:param types: A list or tuple of string representations of the ABI types
that will be used for encoding e.g.  ``('uint256', 'bytes[]',
'(int,int)')``
:param args: A list or tuple of python values to be encoded.
:returns: The head-tail encoded binary representation of the python
values in ``args`` as values of the ABI types in ``types``.
is_encodable_type
validate_value
aEncodingError

Determines if the python value ``arg`` is encodable as a value of the
ABI type ``typ``.
:param typ: A string representation for the ABI type against which the
python value ``arg`` will be checked e.g. ``'uint256'``,
``'bytes[]'``, ``'(int,int)'``, etc.
:param arg: The python value whose encodability should be checked.
:returns: ``True`` if ``arg`` is encodable as a value of the ABI type
``typ``.  Otherwise, ``False``.
has_encoder

Returns ``True`` if values for the ABI type ``typ`` can be encoded by
this codec.
:param typ: A string representation for the ABI type that will be
checked for encodability e.g. ``'uint256'``, ``'bytes[]'``,
``'(int,int)'``, etc.
:returns: ``True`` if values for ``typ`` can be encoded by this codec.
Otherwise, ``False``.
validate_bytes_param
data
get_decoder
strict
T astrict
aTupleDecoder
T adecoders
stream_class
cast
aTuple
aAny

Decodes the binary value ``data`` as a sequence of values of the ABI types
in ``types`` via the head-tail mechanism into a tuple of equivalent python
values.
:param types: A list or tuple of string representations of the ABI types that
will be used for decoding e.g. ``('uint256', 'bytes[]', '(int,int)')``
:param data: The binary value to be decoded.
:param strict: If ``False``, dynamic-type decoders will ignore validations such
s making sure the data is padded to a multiple of 32 bytes or checking that
padding bytes are zero / empty. ``False`` is how the Solidity ABI decoder
currently works. However, ``True`` is the default for the eth-abi library.
:returns: A tuple of equivalent python values for the ABI values
represented in ``data``.
a__doc__
a__file__
origin
has_location
a__cached__
aIterable
ueth_typing.abi
T aDecodable
aTypeStr
aDecodable
aTypeStr
ueth_abi.decoding
T aContextFramesBytesIO
aTupleDecoder
aContextFramesBytesIO
ueth_abi.encoding
T aTupleEncoder
ueth_abi.exceptions
T aEncodingError
ueth_abi.registry
T aABIRegistry
aABIRegistry
ueth_abi.utils.validation
T avalidate_bytes_param
validate_list_like_param
