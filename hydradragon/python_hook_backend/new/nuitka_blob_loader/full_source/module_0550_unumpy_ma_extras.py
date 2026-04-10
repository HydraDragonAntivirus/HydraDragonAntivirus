# Reconstructed from integrated Nuitka blob
# Module: unumpy.ma.extras

a_fromnxfunction
u_fromnxfunction.__init__
u_fromnxfunction.getdoc
a__call__
u_fromnxfunction.__call__
a__prepare__
a_fromnxfunction_single
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
u_fromnxfunction_single.__call__
a__orig_bases__
a_fromnxfunction_seq
u_fromnxfunction_seq.__call__
a_fromnxfunction_args
u_fromnxfunction_args.__call__
a_fromnxfunction_allargs
u_fromnxfunction_allargs.__call__
T aatleast_1d
atleast_1d
T aatleast_2d
atleast_2d
T aatleast_3d
atleast_3d
T avstack
vstack
row_stack
T ahstack
T acolumn_stack
column_stack
T adstack
dstack
T astack
stack
T ahsplit
hsplit
T adiagflat
diagflat
apply_along_axis
apply_over_axes
find
T aNotes
rstrip

Examples
--------
>>> import numpy as np
>>> a = np.ma.arange(24).reshape(2,3,4)
>>> a[:,0,1] = np.ma.masked
>>> a[:,1,:] = np.ma.masked
>>> a
masked_array(
data=[[[0, --, 2, 3],
[--, --, --, --],
[8, 9, 10, 11]],
[[12, --, 14, 15],
[--, --, --, --],
[20, 21, 22, 23]]],
mask=[[[False,  True, False, False],
[ True,  True,  True,  True],
[False, False, False, False]],
[[False,  True, False, False],
[ True,  True,  True,  True],
[False, False, False, False]]],
fill_value=999999)
>>> np.ma.apply_over_axes(np.ma.sum, a, [0,2])
masked_array(
data=[[[46],
[--],
[124]]],
mask=[[[False],
[ True],
[False]]],
fill_value=999999)
Tuple axis arguments to ufuncs are equivalent:
>>> np.ma.sum(a, axis=(0,2)).reshape((1,-1,1))
masked_array(
data=[[[46],
[--],
[124]]],
mask=[[[False],
[ True],
[False]]],
fill_value=999999)
T nnFaaverage
T nnFpacompress_rows
compress_cols
mask_cols
T nnaediff1d
T FpT Faintersect1d
setxor1d
isin
union1d
setdiff1d
T ntpT ntFtnacorrcoef
a__slots__
staticmethod
classmethod
uMAxisConcatenator.makemat
uMAxisConcatenator.__getitem__
mr_class
umr_class.__init__
mr_
T tanotmasked_edges
notmasked_contiguous
clump_unmasked
clump_masked
T nFnFunumpy\ma\extras.py
T a.0
left
right
T a.0
ax
waT a.0
ax
wsaaxis
u<module numpy.ma.extras>
T a__class__
T aself
args
params
T aself
args
params
func
res
wxa_d
a_m
T	aself
args
params
func
arrays
res
wxa_d
a_m
T aself
wxaargs
params
func
a_d
a_m
T aself
key
a__class__
T aself
funcname
T aself
T wxwyarowvar
allow_masked
xmask
axis
tup
xnm_dtype
xnotmask
ymask
common_mask
T amask
idx
wrT waaaxis
out
overwrite_input
fill_value
asorted
indexer
idx
odd
mid
wsacounts
whwlalh
low_high
replace_masked
T afunc1d
axis
arr
args
kwargs
nd
ind
wiaindlist
outshape
res
asscalar
dtypes
outarr
aNtot
wkwnwjaholdshape
max_dtypes
result
T afunc
waaaxes
val
wNaaxis
args
res
T waaaxis
weights
returned
keepdims
wmakeepdims_kw
avg
scl
wgt
result_dtype
T waamask
T waT wxaaxis
wmadata
ax
axes
T wxaaxis
T	wxwyarowvar
bias
allow_masked
ddof
msg
corr
std
T aarr
axis
wmT wxwyarowvar
bias
allow_masked
ddof
xnotmask
fact
mask
data
result
T aarr
to_end
to_begin
ed
arrays
T wawmwiaresult
wkwgwnT wawmaunmasked
T aseq
wkT aself
npfunc
doc
sig
T aar1
ar2
assume_unique
invert
rev_idx
ar
order
sar
bool_ar
flag
indx
T aar1
ar2
assume_unique
aux
T aelement
test_elements
assume_unique
invert
T aseq
T acls
arr
data
a__class__
T waaaxis
T waaaxis
wmamaskedval
T ashape
dtype
waT aarr
waT waaaxis
out
overwrite_input
keepdims
wmT waacompressed
it
mask
T waaaxis
nd
result
other
idx
wiT waaaxis
wmaidx
T
wxwyadeg
rcond
full
wwacov
wmamy
not_m
T wsarep
asorted
axis
T aasorted
axis
T aar1
ar2
assume_unique
T aar1
ar2
assume_unique
aux
auxf
flag
flag2
T aar1
ar2
T aar1
return_index
return_inverse
output
T wxwna_vander
wm.numpy.ma.mrecords
U
uf%i
T Otuple
Olist
split
T w,uillegal input names

new_names
descr
utoo many values to unpack (expected 3)
reserved_fields
l
ndescr
l anp
dtype
names
u|b1
empty
shape
T adtype
flat
recarray
a__new__
T	adtype
buf
offset
strides
formats
names
titles
byteorder
aligned
ma
make_mask_descr
nomask
size
a_mask
array
T acopy
utoo many values to unpack (expected 2)
resize
reshape
aMAError
uMask and data not compatible: data size is %i, mask size is %i.
a__setmask__
mask
a_sharedmask
ndarray
a__getattribute__
make_mask_none
view
update
T a_mask
a_update_from
a_baseclass
ndim
a_data
fields
:nl nT ETypeError
EKeyError
urecord array has no attribute
a__dict__
getfield
uMaskedRecords is currently limited tosimple records.
get
T a_mask
naany
aMaskedArray
a_isfield
T a_fill_value
na_fill_value
item
obj
T amask
fieldmask
a__setattr__
a_optinfo
ret
a__delattr__
fielddict
masked
filled
getmaskarray
setfield
a__setitem__
asarray
mrecarray
w(w,w)w[u,
w]u%%%is : %%s
max
l afmt
insert
T l
umasked_records(
extend
u    fill_value
fill_value
u              )
w
self
a__bases__
a__array__
output
a_hardmask
copy
tolist
D adtype
Oobject
flags
fnc
tobytes
utoo many values to unpack (expected 7)
a__setstate__
bool
a_mrreconstruct
T l
wba__getstate__
b1
T amask
dtype
getdata
atleast_1d
rec
fromarrays
T adtype
shape
formats
names
titles
aligned
byteorder
fromrecords
l :nnnuThe array should be 2D at most!
arr
T EValueError
ETypeError
vartypes
append
T Ocomplex
T Ofloat
T Oint
readline
uNo such file: '
w'u\x
seek
T l
paclose
uWow, binary file
a_NoValue
ufromtextfile() got multiple values for argument 'delimiter'
warnings
warn
uThe 'delimitor' keyword argument of numpy.ma.mrecords.fromtextfile() is deprecated since NumPy 1.22.0, use 'delimiter' instead.
aDeprecationWarning
D astacklevel
l aopenfile
ftext
find
commentchar
strip
delimiter
masked_array
a_guessvartypes
uAttempting to %i dtypes for %i fields! Reverting to default.
default_fill_value
wTutoo many values to unpack (expected 4)
T amask
dtype
fill_value
values
newdata
aMaskedRecords
newmask
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.ma
a_core
records
a_byteorderconv
core
a_check_fill_value
L aMaskedRecords
mrecarray
fromarrays
fromrecords
fromtextfile
addfield
a__all__
L a_data
a_mask
a_fieldmask
dtype
T na_checknames
a_get_fieldmask
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
