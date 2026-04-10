# Reconstructed from integrated Nuitka blob
# Module: ueth_utils.exceptions


Raised when something does not pass a validation check.
a__qualname__
a__orig_bases__
ueth_utils\exceptions.py
u<module eth_utils.exceptions>

a__spec__
.eth_utils.functional
k
O
u<lambda>
ucombine.<locals>.<lambda>
wfwgafn
aCallable
wTareturn
outer
uapply_to_return_value.<locals>.outer
wraps
inner
uapply_to_return_value.<locals>.outer.<locals>.inner
callback
a__doc__
a__file__
origin
has_location
a__cached__
collections
functools
itertools
aAny
aDict
aIterable
aList
aMapping
aSet
aTuple
aTypeVar
aUnion
toolz
T acompose
compose
a_compose
T wTavalue
identity
T aTGIn
aTGIn
T aTGOut
aTGOut
T aTFOut
aTFOut
combine
apply_to_return_value
T aTVal
aTVal
T aTKey
aTKey
T Otuple
to_tuple
T Olist
to_list
T Oset
to_set
T Odict
to_dict
aOrderedDict
to_ordered_dict
T Osorted
sort_return
chain
from_iterable
flatten_return
T Oreversed
reversed_return
ueth_utils\functional.py
T wxwfwgT wfwgu<module eth_utils.functional>
T acallback
outer
T avalue
T aargs
kwargs
callback
fn
T acallback
fn
T afn
inner
T acallback

a__spec__
.eth_utils.hexadecimal
%
4
is_text
uValue must be an instance of str
remove_0x_prefix
aHexStr
encode
T aascii
binascii
unhexlify
is_string
uValue must be an instance of str or unicode
T Obytes
Obytearray
hexlify
add_0x_prefix
decode
uis_0x_prefixed requires text typed arguments. Got:

startswith
T T u0x
u0X
is_0x_prefixed
:l nnu0x
a_HEX_REGEXP
fullmatch
uis_hex requires text typed arguments. Got:
a__doc__
a__file__
origin
has_location
a__cached__
re
aAny
aAnyStr
eth_typing
T aHexStr
types
T ais_string
is_text
compile
T u(0[xX])?[0-9a-fA-F]*
D avalue
return
Ostr
Obytes
decode_hex
value
return
encode_hex
D avalue
return
Ostr
Obool
is_hexstr
is_hex
ueth_utils\hexadecimal.py
u<module eth_utils.hexadecimal>
T avalue
T avalue
non_prefixed
ascii_hex
T avalue
ascii_bytes
binary_hex
a__spec__
.eth_utils.humanize
}
u0s
a_consume_leading_zero_units
a_humanize_seconds

take
l u<genexpr>
uhumanize_seconds.<locals>.<genexpr>
units_iter
seconds
aUNITS
remainder
aDISPLAY_HASH_CHARS
hex
u..
:nl nu0x
:l nnl ahumanize_bytes
is_ipfs_uri
u does not look like a valid IPFS uri. Currently, only CIDv0 hash schemes are supported.
parse
urlparse
netloc
uipfs://
scheme
ipfs
a_is_CIDv0_ipfs_hash
startswith
T aQm
sliding_window
values
a_find_breakpoints

Return a tuple of consecutive ranges of integers.
:param values: a sequence of ordered integers
- fn(1, 2, 3) -> ((1, 3),)
- fn(1, 2, 3, 7, 8, 9) -> ((1, 3), (7, 9))
- fn(1, 7, 8, 9) -> ((1, 1), (7, 9))
a_extract_integer_ranges
w-u(empty)
w|a_humanize_range

Return a concise, human-readable string representing a sequence of integers.
- fn((1, 2, 3)) -> '1-3'
- fn((1, 2, 3, 7, 8, 9)) -> '1-3|7-9'
- fn((1, 2, 3, 5, 7, 8, 9)) -> '1-3|5|7-9'
- fn((1, 7, 8, 9)) -> '1|7-9'
denoms
finney
ether
mwei
gwei
wei
from_wei
w a__doc__
a__file__
origin
has_location
a__cached__
aAny
aIterable
aIterator
aTuple
aUnion
urllib
T aparse
eth_typing
T aURI
aHash32
aURI
aHash32
ueth_utils.currency
T adenoms
from_wei
toolz
T asliding_window
take
T Ofloat
Oint
return
humanize_seconds
aSECOND
l<aMINUTE
l  aHOUR
l aDAY
l  aYEAR
l aMONTH
l aWEEK
wywmwwwdwhwsT Oint
Ostr
l D avalue
return
Obytes
Ostr
D avalue
return
Ostr
pahumanize_hexstr
value
humanize_hash
uri
humanize_ipfs_uri
D aipfs_hash
return
Ostr
Obool
T Oint
pabounds
values_iter
humanize_integer_sequence
D anumber
return
Oint
Ostr
humanize_wei
ueth_utils\humanize.py
T a.0
amount
unit
u<module eth_utils.humanize>
T aunits_iter
amount
unit
T avalues
left
right
chunk
T avalues
index
left
right
T abounds
left
right
T aseconds
remainder
duration
unit
num
T aipfs_hash
T avalue
value_as_hex
head
tail
T avalue
T avalue
tail
head
T avalues_iter
values
T auri
parsed
ipfs_hash
head
tail
T aseconds
unit_values
T anumber
unit
amount
wxT avalue
parsed
a__spec__
.eth_utils.logging
r
isEnabledFor
aDEBUG2_LEVEL_NUM
show_debug2
log
u<lambda>
uExtendedDebugLogger.debug2.<locals>.<lambda>
debug2
get_extended_debug_logger
name
logging
aDEBUG2
addLevelName

Installs the `DEBUG2` level logging levels to the main logging module.
getLoggerClass
setLoggerClass
logger_class
a_use_logger_class
cast
aTLogger
getLogger
a__enter__
a__exit__
aLogger
manager
loggerDict
T nnnaget_logger
aExtendedDebugLogger
logger
a__class__
a__new__
a__qualname__
uMissing __qualname__
assoc
a__name__
ueth_utils.logging
a__doc__
a__file__
origin
has_location
a__cached__
contextlib
cached_property
aAny
aDict
aIterator
aTuple
aType
aTypeVar
aUnion
toolz
T aassoc
l T aTLogger
T abound
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
