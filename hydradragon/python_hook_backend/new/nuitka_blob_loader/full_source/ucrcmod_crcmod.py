# Reconstructed from integrated Nuitka blob
# Module: ucrcmod.crcmod

uCompute a Cyclic Redundancy Check (CRC) using the specified polynomial.
Instances of this class have the same interface as the algorithms in the
hashlib module in the Python standard library.  See the documentation of
this module for examples of how to use a Crc instance.
The string representation of a Crc instance identifies the polynomial,
initial value, XOR out value, and the current CRC value.  The print
statement can be used to output this information.
If you need to generate a C/C++ function for use in another application,
use the generateCode method.  If you need to generate code for another
language, subclass Crc and override the generateCode method.
The following are the parameters supplied to the constructor.
poly -- The generator polynomial to use in calculating the CRC.  The value
is specified as a Python integer.  The bits in this integer are the
coefficients of the polynomial.  The only polynomials allowed are those
that generate 8, 16, 24, 32, or 64 bit CRCs.
initCrc -- Initial value used to start the CRC calculation.  This initial
value should be the initial shift register value XORed with the final XOR
value.  That is equivalent to the CRC result the algorithm should return for
a zero-length string.  Defaults to all bits set because that starting value
will take leading zero bytes into account.  Starting with zero will ignore
ll leading zero bytes.
rev -- A flag that selects a bit reversed algorithm when True.  Defaults to
True because the bit reversed algorithms are more efficient.
xorOut -- Final value to XOR with the calculated CRC value.  Used by some
CRC algorithms.  Defaults to zero.
a__qualname__
T q tl
ta__init__
uCrc.__init__
a__str__
uCrc.__str__
T nuCrc.new
copy
uCrc.copy
uCrc.update
digest
uCrc.digest
hexdigest
uCrc.hexdigest
T nnagenerateCode
uCrc.generateCode
T q tl
a_crc8
a_crc8r
l a_crc16
a_crc16r
a_crc24
a_crc24r
a_crc32
a_crc32r
l@a_crc64
a_crc64r
T wBwHwIwLwQatypeCode
D l l l l l l l l@acalcsize
size
u256%s
u// Automatically generated CRC function
// %(poly)s
%(crcType)s
%(name)s(%(dataType)s *data, int len, %(crcType)s crc)
{
static const %(crcType)s table[256] = {%(crcTable)s
};
%(preCondition)s
while (len > 0)
{
crc = %(crcAlgor)s;
data++;
len--;
}%(postCondition)s
return crc;
}
ucrcmod\crcmod.py
u<module crcmod.crcmod>
T	aself
poly
initCrc
rev
xorOut
initialize
sizeBits
crcfun
table
T aself
lst
fmt
T wxwnwywiT acrc
poly
wnamask
wiT acrc
poly
wnwiamask
T	apoly
sizeBits
initCrc
rev
xorOut
tableList
a_fun
a_table
crcfun
T apoly
wnamask
table
T apoly
initCrc
xorOut
sizeBits
mask
T apoly
msg
wnalow
high
T aself
wcT adata
crc
table
fun
T adata
crc
table
fun
xorOut
T axorOut
T aself
wnacrc
lst
T aself
functionName
out
dataType
crcType
size
crcAlgor
shift
fmt
wnalst
wiaval
poly
preCondition
postCondition
parms
T apoly
initCrc
rev
xorOut
sizeBits
T aself
arg
wnT aself
data
a__spec__
.crcmod.predefined
lower
replace
T w-u
T w u
startswith
T acrc
:l nnaname

Reduce CRC definition name to a simplified form:
* lowercase
* dashes removed
* spaces removed
* any initial "CRC" string removed
a_crc_definitions_by_name
get
a_simplify_name
a_crc_definitions_by_identifier
uUnkown CRC name '{0}'
a_get_definition_by_name
a__class__
a__init__
poly
init
reverse
xor_out
T apoly
initCrc
rev
xorOut
crcmod
mkCrcFun

crcmod.predefined defines some well-known CRC algorithms.
To use it, e.g.:
import crcmod.predefined
crc32func = crcmod.predefined.mkPredefinedCrcFun("crc-32")
crc32class = crcmod.predefined.PredefinedCrc("crc-32")
crcmod.predefined.Crc is an alias for crcmod.predefined.PredefinedCrc
But if doing 'from crc.predefined import *', only PredefinedCrc is imported.
a__doc__
a__file__
origin
has_location
a__cached__
aPredefinedCrc
mkPredefinedCrcFun
a__all__
aREVERSE
aNON_REVERSE
ucrc-8
aCrc8
l  l  ucrc-8-darc
aCrc8Darc
l  l ucrc-8-i-code
aCrc8ICode
l  l  l~ucrc-8-itu
aCrc8Itu
lUl  ucrc-8-maxim
aCrc8Maxim
l  ucrc-8-rohc
aCrc8Rohc
l  l  ucrc-8-wcdma
aCrc8Wcdma
l  l%ucrc-16
aCrc16
l   l   ucrc-16-buypass
aCrc16Buypass
l   ucrc-16-dds-110
aCrc16Dds110
l   l   ucrc-16-dect
aCrc16Dect
l   ucrc-16-dnp
aCrc16Dnp
l   l   l   ucrc-16-en-13757
aCrc16En13757
l   ucrc-16-genibus
aCrc16Genibus
l   l   ucrc-16-maxim
aCrc16Maxim
l   ucrc-16-mcrf4xx
aCrc16Mcrf4xx
l   ucrc-16-riello
aCrc16Riello
l   l   ucrc-16-t10-dif
aCrc16T10Dif
l   l   ucrc-16-teledisk
aCrc16Teledisk
l   l  ucrc-16-usb
aCrc16Usb
l   ux-25
aCrcX25
l   axmodem
aCrcXmodem
l camodbus
aCrcModbus
l   akermit
aCrcKermit
l Cucrc-ccitt-false
aCrcCcittFalse
l Sucrc-aug-ccitt
aCrcAugCcitt
l :l   ucrc-24
aCrc24
l    l    l    ucrc-24-flexray-a
aCrc24FlexrayA
l
l    l    ucrc-24-flexray-b
aCrc24FlexrayB
l    l  |ucrc-32
aCrc32
g     &g       g       ucrc-32-bzip2
aCrc32Bzip2
g       ucrc-32c
aCrc32C
g       g       ucrc-32d
aCrc32D
g       g     9ucrc-32-mpeg
aCrc32Mpeg
l    aposix
aCrcPosix
l     ucrc-32q
aCrc32Q
g
l     ajamcrc
aCrcJamCrc
l     axfer
aCrcXfer
g    g       ucrc-64
aCrc64
g
g     j   Rucrc-64-we
aCrc64We
g     /     g            g            ucrc-64-jones
aCrc64Jones
g            g          0a_crc_definitions_table
a_crc_definitions
L aname
identifier
poly
reverse
init
xor_out
check
a_crc_table_headings
table_entry
crc_definition
append
uDuplicate entry for '{0}' in CRC table
aCrc
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
