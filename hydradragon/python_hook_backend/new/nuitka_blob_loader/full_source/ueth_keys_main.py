# Reconstructed from integrated Nuitka blob
# Module: ueth_keys.main

a__qualname__
message_hash
bytes
private_key
return
uKeyAPI.ecdsa_sign
uKeyAPI.ecdsa_sign_non_recoverable
signature
public_key
bool
uKeyAPI.ecdsa_verify
uKeyAPI.ecdsa_recover
uKeyAPI.private_key_to_public_key
a__orig_bases__
T nT abackend
lazy_key_api
ueth_keys\main.py
u<module eth_keys.main>
T a__class__
T aself
message_hash
signature
public_key
T aself
message_hash
private_key
signature
T aself
private_key
public_key

a__spec__
.eth_keys.utils.address
keccak
:q nna__doc__
a__file__
origin
has_location
a__cached__
eth_utils
T akeccak
D apublic_key_bytes
return
Obytes
papublic_key_bytes_to_address
ueth_keys\utils\address.py
u<module eth_keys.utils.address>
T apublic_key_bytes

a__spec__
.eth_keys.utils
#
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_keys
u\not_existing
utils
T aNUITKA_PACKAGE_eth_keys_utils
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ueth_keys\utils\__init__.py
u<module eth_keys.utils>

a__spec__
.eth_keys.utils.der
P
)

Encode two integers using DER, defined as:
::
ECDSASpec DEFINITIONS ::= BEGIN
ECDSASignature ::= SEQUENCE {
r   INTEGER,
s   INTEGER
}
END
Only a subset of integers are supported: positive, 32-byte ints.
See: https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-sequence
l0a_encode_int
signature_r
signature_s
two_int_sequence_encoder
uEncoded sequence must start with 0x30 byte, but got

a_decode_int
:l nnuEncoded sequence must not contain any trailing data, but had

Decode bytes to two integers using DER, defined as:
::
ECDSASpec DEFINITIONS ::= BEGIN
ECDSASignature ::= SEQUENCE {
r   INTEGER,
s   INTEGER
}
END
Only a subset of integers are supported: positive, 32-byte ints.
r is returned first, and s is returned second
See: https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-sequence
l aint_to_big_endian
primitive
l  aencoded
uEncoded value must be an integer, starting with on 0x02 byte, but got
big_endian_to_int
a__doc__
a__file__
origin
has_location
a__cached__
aIterator
aTuple
eth_utils
T aapply_to_return_value
big_endian_to_int
int_to_big_endian
apply_to_return_value
T Obytes
return
T Oint
patwo_int_sequence_decoder
T Oint
Obytes
ueth_keys\utils\der.py
u<module eth_keys.utils.der>
T aencoded
length
decoded_int
T aprimitive
encoded
T aencoded
int1
rest
int2
empty
T asignature_r
signature_s
encoded1
encoded2
a__spec__
.eth_keys.utils.module_loading
!
rsplit
T w.l u
u doesn't look like a module path
import_module
uModule "
u" does not define a "
u" attribute/class

Source: django.utils.module_loading
Import a dotted module path and return the attribute/class designated by the
last name in the path. Raise ImportError if the import failed.
split
T w.adotted_path
w.:l nnaoperator
attrgetter
uUnable to derive appropriate import path for
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aTuple
return
import_string
T Ostr
pasplit_at_longest_importable_path
ueth_keys\utils\module_loading.py
u<module eth_keys.utils.module_loading>
T adotted_path
module_path
class_name
msg
module
T adotted_path
num_path_parts
wiapath_parts
import_part
remainder
module
a__spec__
.eth_keys.utils.numeric
min
aSECPK1_N

Coerce the s component of an ECDSA signature into its low-s form.
See https://bitcoin.stackexchange.com/questions/83408/in-ecdsa-why-is-r-%E2%88%92s-mod-n-complementary-to-r-s  # noqa: E501
or https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md.
a__doc__
a__file__
origin
has_location
a__cached__
ueth_keys.constants
T aSECPK1_N
D avalue
return
Oint
Obytes
int_to_byte
D avalue
return
Oint
pacoerce_low_s
ueth_keys\utils\numeric.py
u<module eth_keys.utils.numeric>
T avalue

a__spec__
.eth_keys.utils.padding
rjust
T l d
a__doc__
a__file__
origin
has_location
a__cached__
D avalue
return
Obytes
papad32
ueth_keys\utils\padding.py
u<module eth_keys.utils.padding>
T avalue

a__spec__
.eth_keys.validation
d
H
is_integer
aValidationError
uValue must be a an integer.  Got:

is_bytes
uValue must be a byte string.  Got:
validate_integer
uValue
u is not greater than or equal to
u is not less than or equal to
uUnexpected
u length: Expected
u, but got
u bytes
validate_bytes
validate_bytes_length
l umessage hash
l@uuncompressed public key
l!ucompressed public key
:l
l nT d d uUnexpected compressed public key format: Must start with 0x02 or 0x03, but starts with
encode_hex
uprivate key
lAurecoverable signature
unon recoverable signature
validate_gte
D aminimum
l
validate_lte
D amaximum
l avalidate_lt_secpk1n
a__doc__
a__file__
origin
has_location
a__cached__
aAny
eth_utils
T aValidationError
encode_hex
is_bytes
is_integer
ueth_utils.toolz
T acurry
curry
ueth_keys.constants
T aSECPK1_N
aSECPK1_N
value
return
minimum
maximum
T amaximum
D avalue
expected_length
name
return
Obytes
Oint
Ostr
navalidate_message_hash
validate_uncompressed_public_key_bytes
validate_compressed_public_key_bytes
validate_private_key_bytes
validate_recoverable_signature_bytes
validate_non_recoverable_signature_bytes
D avalue
return
Oint
navalidate_signature_v
validate_signature_r_or_s
ueth_keys\validation.py
u<module eth_keys.validation>
T avalue
T avalue
expected_length
name
actual_length
T avalue
first_byte
T avalue
minimum
T avalue
maximum
a__spec__
.eth_rlp
!
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_eth_rlp
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
version
a__version
main
T aHashableRLP
aHashableRLP
u2.2.0
a__version__
ueth_rlp\__init__.py
u<module eth_rlp>

a__spec__
.eth_rlp.main
&
J

In addition to the standard initialization of.
::
my_obj = MyRLP(name1=1, name2=b'\xff')
This method enables initialization with.
::
my_obj = MyRLP.from_dict({'name1': 1, 'name2': b'\xff'})
In general, the standard initialization is preferred, but
some approaches might favor this API, like when using
:meth:`toolz.functoolz.pipe`.
::
return eth_utils.toolz.pipe(
my_dict,
normalize,
validate,
MyRLP.from_dict,
)
:param dict field_dict: the dictionary of values to initialize with
:returns: the new rlp object
:rtype: HashableRLP
rlp
decode
cast
aSelf

Shorthand invocation for :meth:`rlp.decode` using this class.
:param bytes serialized_bytes: the byte string to decode
:return: the decoded object
:rtype: HashableRLP
aHexBytes
pipe
encode
keccak

:returns: the hash of the encoded bytestring
:rtype: ~hexbytes.main.HexBytes
fields
a__class__
a__iter__
self
u<genexpr>
uHashableRLP.__iter__.<locals>.<genexpr>
as_dict
aDict
aAny

Convert rlp object to a dict
:returns: mapping of RLP field names to field values
:rtype: dict
a__doc__
a__file__
origin
has_location
a__cached__
sys
aUnion
eth_utils
T akeccak
ueth_utils.toolz
T apipe
hexbytes
T aHexBytes
typing_extensions
T aSelf
aSerializable
a__prepare__
aHashableRLP
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
