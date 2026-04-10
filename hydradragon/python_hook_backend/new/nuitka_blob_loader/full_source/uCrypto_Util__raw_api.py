# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Util._raw_api

a__qualname__
abstractmethod
uReturn the memory location we point to
get
u_VoidPointer.get
uReturn a raw pointer to this pointer
address_of
u_VoidPointer.address_of
a__orig_bases__
flags
optimize
l uCFFI with optimize=2 fails due to pycparser bug.
cffi
T aFFI
aFFI
aNULL
null_pointer
typeof
T uconst uint8_t*
T uuint8_t[1]
a__bases__
c_ulong
c_ulonglong
c_uint
c_size_t
T nacreate_string_buffer
get_c_string
get_raw_buffer
c_uint8_ptr
uModel a newly allocated pointer to void
a__init__
uVoidPointer_cffi.__init__
uVoidPointer_cffi.get
uVoidPointer_cffi.address_of
aVoidPointer
backend
uctypes.util
T afind_library
aArray
c_ssize_t
a_c_ssize_t
pythonapi
aPyObject_GetBuffer
aPyBuffer_Release
py_object
aPOINTER
a_c_ssize_p
aStructure
obj
itemsize
c_int
ndim
format
c_char_p
shape
strides
suboffsets
internal
a_fields_
version_info
insert
smalltable
uVoidPointer_ctypes.__init__
uVoidPointer_ctypes.get
uVoidPointer_ctypes.address_of
aSmartPointer
uClass to hold a non-managed piece of memory
uSmartPointer.__init__
uSmartPointer.get
release
uSmartPointer.release
a__del__
uSmartPointer.__del__
load_pycryptodome_raw_lib
is_buffer
is_writeable_buffer
uCrypto\Util\_raw_api.py
u<module Crypto.Util._raw_api>
T a__class__
T aself
T aself
raw_pointer
destructor
T wxT wcT adata
T adata
obj
buf
buffer_type
T ainit_or_size
size
result
T ac_string
T abuf
T aname
cdecl
lib
T aname
cdecl
platform
bits
linkage
full_name
T
name
cdecl
split
dir_comps
basename
attempts
ext
filename
full_name
exp
T aself
rp

a__spec__
.Crypto.Util.asn1
^M
( a_buffer
a_index
a_bookmark
uNot enough data for DER decoding: expected %d bytes and found %d
bord
read
T l a_tag_octet
a_convertTag
payload
l uExplicit and implicit tags are mutually exclusive
l  l  a_inner_tag_octet
uInitialize the DER object according to a specific ASN.1 type.
:Parameters:
sn1Id : integer or byte
The universal DER tag number for this object
(e.g. 0x10 for a SEQUENCE).
If None, the tag is not known yet.
payload : byte string
The initial payload of the object (that it,
the content octets).
If not specified, the payload is empty.
implicit : integer or byte
The IMPLICIT tag number (< 0x1F) to use for the encoded object.
It overrides the universal tag *asn1Id*.
It cannot be combined with the ``explicit`` parameter.
By default, there is no IMPLICIT tag.
constructed : bool
True when the ASN.1 type is *constructed*.
False when it is *primitive* (default).
explicit : integer or byte
The EXPLICIT tag number (< 0x1F) to use for the encoded object.
It cannot be combined with the ``implicit`` parameter.
By default, there is no EXPLICIT tag.
a_is_number
tag
l uWrong DER tag
uCheck if *tag* is a real DER tag (5 bits).
Convert it from a character to number if necessary.
l along_to_bytes
bchr
uBuild length octets according to BER/DER
definite form.
a_definite_form
uReturn this DER element, fully encoded as a binary byte string.
read_byte
uInvalid DER: length has leading zero
bytes_to_long
uInvalid DER: length in long form but smaller than 128
uDecode DER length octets from a file.
byte_string
uInput is not a byte string
aBytesIO_EOF
a_decodeFromStream
remaining_data
uUnexpected extra data after the DER structure
uDecode a complete DER element, and re-initializes this
object with it.
Args:
der_encoded (byte string): A complete DER element.
Raises:
ValueError: in case of parsing errors.
uUnexpected DER tag
a_decodeLen
uUnexpected internal DER tag
uDecode a complete DER element from a file.
aDerObject
a__init__
l c
value
uInitialize the DER object as an INTEGER.
:Parameters:
value : integer
The value of the integer.
implicit : integer
The IMPLICIT tag to use for the encoded object.
It overrides the universal tag for INTEGER (2).
number
l  aself
T l
q  l aencode
uReturn the DER INTEGER, fully encoded as a
binary string.
decode
T astrict
uDecode a DER-encoded INTEGER, and re-initializes this
object with it.
Args:
der_encoded (byte string): A complete INTEGER DER element.
Raises:
ValueError: in case of parsing errors.
uInvalid encoding for DER INTEGER: empty payload
struct
unpack
u>H
:nl nuInvalid encoding for DER INTEGER: leading zero
l  abits
uDecode a complete DER INTEGER from a file.
uInitialize the DER object as a BOOLEAN.
Args:
value (boolean):
The value of the boolean. Default is False.
implicit (integer or byte):
The IMPLICIT tag number (< 0x1F) to use for the encoded object.
It overrides the universal tag for BOOLEAN (1).
It cannot be combined with the ``explicit`` parameter.
By default, there is no IMPLICIT tag.
explicit (integer or byte):
The EXPLICIT tag number (< 0x1F) to use for the encoded object.
It cannot be combined with the ``implicit`` parameter.
By default, there is no EXPLICIT tag.
d d
uReturn the DER BOOLEAN, fully encoded as a binary string.
uDecode a DER-encoded BOOLEAN, and re-initializes this object with it.
Args:
der_encoded (byte string): A DER-encoded BOOLEAN.
Raises:
ValueError: in case of parsing errors.
uInvalid encoding for DER BOOLEAN: payload is not 1 byte
uInvalid payload for DER BOOLEAN
uDecode a DER-encoded BOOLEAN from a file.
l a_seq
uInitialize the DER object as a SEQUENCE.
:Parameters:
startSeq : Python sequence
A sequence whose element are either integers or
other DER objects.
implicit : integer or byte
The IMPLICIT tag number (< 0x1F) to use for the encoded object.
It overrides the universal tag for SEQUENCE (16).
It cannot be combined with the ``explicit`` parameter.
By default, there is no IMPLICIT tag.
explicit : integer or byte
The EXPLICIT tag number (< 0x1F) to use for the encoded object.
It cannot be combined with the ``implicit`` parameter.
By default, there is no EXPLICIT tag.
max
append
insert
only_non_negative
uReturn the number of items in this sequence that are
integers.
Args:
only_non_negative (boolean):
If ``True``, negative integers are not counted in.
hasInts
uReturn ``True`` if all items in this sequence are integers
or non-negative integers.
This function returns False is the sequence is empty,
or at least one member is not an integer.
Args:
only_non_negative (boolean):
If ``True``, the presence of negative integers
causes the method to return ``False``.
aDerInteger
uReturn this DER SEQUENCE, fully encoded as a
binary string.
Raises:
ValueError: if some elements in the sequence are neither integers
nor byte strings.
a_nr_elements
hasOnlyInts
uSome members are not INTEGERs
uDecode a complete DER SEQUENCE, and re-initializes this
object with it.
Args:
der_encoded (byte string):
A complete SEQUENCE DER element.
nr_elements (None or integer or list of integers):
The number of members the SEQUENCE can have
only_ints_expected (boolean):
Whether the SEQUENCE is expected to contain only integers.
strict (boolean):
Whether decoding must check for strict DER compliancy.
Raises:
ValueError: in case of parsing errors.
DER INTEGERs are decoded into Python integers. Any other DER
element is not decoded. Its validity is not checked.
wpaset_bookmark
strict
data_since_bookmark
uUnexpected number of members (%d) in the sequence
uDecode a complete DER SEQUENCE from a file.
l uInitialize the DER object as an OCTET STRING.
:Parameters:
value : byte string
The initial payload of the object.
If not specified, the payload is empty.
implicit : integer
The IMPLICIT tag to use for the encoded object.
It overrides the universal tag for OCTET STRING (4).
l uInitialize the DER object as a NULL.
l uInitialize the DER object as an OBJECT ID.
:Parameters:
value : string
The initial Object Identifier (e.g. "1.2.0.0.6.2").
implicit : integer
The IMPLICIT tag to use for the encoded object.
It overrides the universal tag for OBJECT ID (6).
explicit : integer
The EXPLICIT tag to use for the encoded object.
split
T w.uNot a valid Object Identifier string
uFirst component must be 0, 1 or 2
l'uSecond component must be 39 at most
l(:l nnaencoding
l wvuReturn the DER OBJECT ID, fully encoded as a
binary string.
uDecode a complete DER OBJECT ID, and re-initializes this
object with it.
Args:
der_encoded (byte string):
A complete DER OBJECT ID.
strict (boolean):
Whether decoding must check for strict DER compliancy.
Raises:
ValueError: in case of parsing errors.
subcomps
uEmpty payload
:nl nlPw.uDecode a complete DER OBJECT ID from a file.
l uInitialize the DER object as a BIT STRING.
:Parameters:
value : byte string or DER object
The initial, packed bit string.
If not specified, the bit string is empty.
implicit : integer
The IMPLICIT tag to use for the encoded object.
It overrides the universal tag for BIT STRING (3).
explicit : integer
The EXPLICIT tag to use for the encoded object.
uReturn the DER BIT STRING, fully encoded as a
byte string.
uDecode a complete DER BIT STRING, and re-initializes this
object with it.
Args:
der_encoded (byte string): a complete DER BIT STRING.
strict (boolean):
Whether decoding must check for strict DER compliancy.
Raises:
ValueError: in case of parsing errors.
uNot a valid BIT STRING
:l nnuDecode a complete DER BIT STRING DER from a file.
l a_elemOctet
add
uInitialize the DER object as a SET OF.
:Parameters:
startSet : container
The initial set of integers or DER encoded objects.
implicit : integer
The IMPLICIT tag to use for the encoded object.
It overrides the universal tag for SET OF (17).
uNew element does not belong to the set
uAdd an element to the set.
Args:
elem (byte string or integer):
An element of the same type of objects already in the set.
It can be an integer or a DER encoded object.
uDecode a complete SET OF DER element, and re-initializes this
object with it.
DER INTEGERs are decoded into Python integers. Any other DER
element is left undecoded; its validity is not checked.
Args:
der_encoded (byte string): a complete DER BIT SET OF.
strict (boolean):
Whether decoding must check for strict DER compliancy.
Raises:
ValueError: in case of parsing errors.
setIdOctet
uNot all elements are of the same DER type
uDecode a complete DER SET OF from a file.
ordered
sort
uReturn this SET OF DER element, fully encoded as a
binary string.
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abyte_string
bchr
bord
uCrypto.Util.number
T along_to_bytes
bytes_to_long
L	aDerObject
aDerInteger
aDerBoolean
aDerOctetString
aDerNull
aDerSequence
aDerObjectId
aDerBitString
aDerSetOf
a__all__
T FT Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
