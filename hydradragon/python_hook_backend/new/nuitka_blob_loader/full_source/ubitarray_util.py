# Reconstructed from integrated Nuitka blob
# Module: ubitarray.util


A Node instance will either have a 'symbol' (leaf node) or
a 'child' (a tuple with both children) attribute.
The 'freq' attribute will always be present.
a__doc__
u_huffman_tree.<locals>.Node
a__qualname__
a__lt__
u_huffman_tree.<locals>.Node.__lt__
a__orig_bases__
items
symbol
freq
minheap
child
u_huffman_tree(dict, /) -> Node
Given a dict mapping symbols to their frequency, construct a Huffman tree
nd return its root node.
udict expected, got '%s'
w0w1ucannot create Huffman code with no symbols
traverse
uhuffman_code.<locals>.traverse
a_huffman_tree
uhuffman_code(dict, /, endian=None) -> dict
Given a frequency map, a dictionary mapping symbols to their frequency,
calculate the Huffman code, i.e. a dict mapping those symbols to
bitarrays (with given bit-endianness).  Note that the symbols are not limited
to being strings.  Symbols may be any hashable object (such as `None`).
result
b0
b1
T w0abig
T l
ucanonical_huffman.<locals>.traverse
sorted
u<lambda>
ucanonical_huffman.<locals>.<lambda>
T akey
max
int2ba
code
big
codedict
count
ucanonical_huffman(dict, /) -> tuple
Given a frequency map, a dictionary mapping symbols to their frequency,
calculate the canonical Huffman code.  Returns a tuple containing:
0. the canonical Huffman code as a dict mapping symbols to bitarrays
1. a list containing the number of symbols of each code length
2. a list of symbols in canonical order
Note: the two lists may be used as input for `canonical_decode()`.
code_length
u<genexpr>
ucanonical_huffman.<locals>.<genexpr>

Useful utilities for working with bitarrays.
a__file__
origin
has_location
a__cached__
absolute_import
os
sys
T abitarray
bits2bytes
ubitarray._util
T azeros
ones
count_n
parity
count_and
count_or
count_xor
any_and
subset
a_correspond_all
serialize
deserialize
ba2hex
hex2ba
ba2base
base2ba
sc_encode
sc_decode
vl_encode
vl_decode
canonical_decode
ones
count_n
parity
count_and
count_or
count_xor
any_and
subset
a_correspond_all
serialize
deserialize
ba2hex
hex2ba
ba2base
base2ba
sc_encode
sc_decode
vl_encode
vl_decode
canonical_decode
L azeros
ones
urandom
pprint
strip
count_n
parity
count_and
count_or
count_xor
any_and
subset
intervals
ba2hex
hex2ba
ba2base
base2ba
ba2int
int2ba
serialize
deserialize
sc_encode
sc_decode
vl_encode
vl_decode
huffman_code
canonical_huffman
canonical_decode
a__all__
T nT nl l lPT Faba2int
T nnFahuffman_code
canonical_huffman
ubitarray\util.py
T a.0
item
T aitem
u<module bitarray.util>
T a__class__
T aself
other
T	a__freq_map
heappush
heappop
aNode
minheap
sym
wfaleaf
parent
T a__a
signed
length
le
pad
res
T a__freq_map
sym
code_length
traverse
table
maxbits
codedict
count
code
wialength
T a__freq_map
endian
b0
b1
result
traverse
T
a__i
length
endian
signed
wmwaale
wbala
pad
T a__a
value
wnastop
start
Ta__a
stream
group
indent
width
a_pprint
gpl
epl
type_name
multiline
quotes
wiwbT a__a
mode
start
stop
T and
length
code_length
traverse
T acode_length
traverse
T and
prefix
result
traverse
b0
b1
T ab0
b1
result
traverse
T a__length
endian
waa__spec__
.brotli
aCompressor
T amode
quality
lgwin
lgblock
process
finish
uCompress a byte string.
Args:
string (bytes): The input data.
mode (int, optional): The compression mode can be MODE_GENERIC (default),
MODE_TEXT (for UTF-8 format text input) or MODE_FONT (for WOFF 2.0).
quality (int, optional): Controls the compression-speed vs compression-
density tradeoff. The higher the quality, the slower the compression.
Range is 0 to 11. Defaults to 11.
lgwin (int, optional): Base 2 logarithm of the sliding window size. Range
is 10 to 24. Defaults to 22.
lgblock (int, optional): Base 2 logarithm of the maximum input block size.
Range is 16 to 24. If set to 0, the value will be set based on the
quality. Defaults to 0.
Returns:
The compressed byte string.
Raises:
brotli.error: If arguments are invalid, or compressor fails.
uFunctions to compress and decompress data using the Brotli library.
a__doc__
a__file__
origin
has_location
a__cached__
a_brotli
a__version__
version
aMODE_GENERIC
aMODE_TEXT
aMODE_FONT
aDecompressor
l l acompress
decompress
error
ubrotli.py
u<module brotli>
T astring
mode
quality
lgwin
lgblock
compressor

a__spec__
.bs4._deprecation
f
:
return
aAny
u:meta private:
alias
u_deprecated_alias.<locals>.alias
setter
D avalue
return
Ostr
nuAlias one attribute name to another for backward compatibility
:meta private:
warnings
warn
uAccess to deprecated property
old_name

u. (Replaced by
new_name
u) -- Deprecated since version
version
w.aDeprecationWarning
D astacklevel
l uWrite to deprecated property
args
kwargs
u_deprecated_function_alias.<locals>.alias
uCall to deprecated method
func
aCallable
deprecate
u_deprecated.<locals>.deprecate
wraps
with_warning
u_deprecated.<locals>.deprecate.<locals>.with_warning
a__name__
replaced_by
uHelper functions for deprecation.
This interface is itself unstable and may change without warning. Do
not use these functions yourself, even as a joke. The underscores are
there for a reason. No support will be given.
In particular, most of this will go away without warning once
Beautiful Soup drops support for Python 3.11, since Python 3.12
defines a `@typing.deprecated()
decorator. <https://peps.python.org/pep-0702/>`_
a__doc__
a__file__
origin
has_location
a__cached__
functools
D aold_name
new_name
version
Ostr
ppa_deprecated_alias
a_deprecated_function_alias
a_deprecated
ubs4\_deprecation.py
u<module bs4._deprecation>
T areplaced_by
version
deprecate
T aold_name
new_name
version
alias
T aself
old_name
new_name
version
T anew_name
old_name
version
T aself
value
old_name
new_name
version
T aself
args
kwargs
old_name
new_name
version
T afunc
with_warning
T areplaced_by
version
T aargs
kwargs
func
replaced_by
version
T afunc
replaced_by
version
a__spec__
.bs4._typing
S
W
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
typing_extensions
T aruntime_checkable
aProtocol
aTypeAlias
runtime_checkable
aProtocol
aTypeAlias
aAny
aCallable
aDict
aIO
aIterable
aMapping
aOptional
aPattern
aTYPE_CHECKING
aUnion
a__prepare__
a_RegularExpressionProtocol
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
