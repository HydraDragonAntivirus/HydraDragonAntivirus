# Reconstructed from integrated Nuitka blob
# Module: uscipy.integrate._ivp.bdf

a__qualname__
f    MbP?f       >uBDF.__init__
uBDF._validate_jac
a_step_impl
uBDF._step_impl
a_dense_output_impl
uBDF._dense_output_impl
a__orig_bases__
uBdfDenseOutput.__init__
a_call_impl
uBdfDenseOutput._call_impl
uscipy\integrate\_ivp\bdf.py
u<module scipy.integrate._ivp.bdf>
T a__class__
T aself
fun
t0
y0
t_bound
max_step
rtol
atol
jac
jac_sparsity
vectorized
first_step
extraneous
wfalu
solve_lu
wIakappa
wDa__class__
T aself
t_old
wtwhaorder
wDa__class__
T aself
wtwxwpwyT aself
T&aself
wtwDamax_step
min_step
h_abs
atol
rtol
order
alpha
gamma
error_const
wJaLU
current_jac
step_accepted
what_new
y_predict
scale
psi
converged
wcan_iter
y_new
wdafactor
safety
error
error_norm
wiaerror_m
error_m_norm
error_p
error_p_norm
error_norms
factors
delta_order
T aself
jac
sparsity
t0
y0
groups
jac_wrapped
wJT wDaorder
factor
wRwUaRU
T aorder
factor
wIwJwMT wtwywfwJaself
sparsity
T aself
sparsity
T wtwyaself
jac
y0
T ajac
self
y0
T wAaself
T afun
t_new
y_predict
wcapsi
aLU
solve_lu
scale
tol
wdwyady_norm_old
converged
wkwfady
dy_norm
rate
T aLU
wb.scipy.integrate._ivp.common
l
u`first_step` must be positive.
np
abs
u`first_step` exceeds bounds.
u`max_step` must be positive.
warn
uThe following arguments have no effect for a chosen solver:
u,
w.u
D astacklevel
l w`u<genexpr>
uwarn_extraneous.<locals>.<genexpr>
any
ldaEPS
uAt least one element of `rtol` is too small. Setting `rtol = np.maximum(rtol,
u)`.
maximum
asarray
ndim
shape
u`atol` has wrong shape.
u`atol` must be positive.
linalg
norm
size
f
?ainf
Z
f h     >f       >f{  G z ?amin
f V     <amax
f    MbP?l adiff
l q aall
u`ts` must be strictly increasing or decreasing.
n_segments
uNumbers of time stamps and interpolants don't match.
ts
interpolants
t_min
t_max
ascending
right
left
side
ts_sorted
:nnq asearchsorted
T aside
a_call_single
argsort
empty_like
arange
groupby
segments
utoo many values to unpack (expected 2)
group_start
self
ys
hstack
:nnnaempty
T T l
pafull
copy
real
astype
T Ofloat
nonzero
whwiafactor
l
a_dense_num_jac
a_sparse_num_jac
diag
T :nnnnaargmax
D aaxis
l
aNUM_JAC_DIFF_REJECT
utoo many values to unpack (expected 1)
aNUM_JAC_FACTOR_INCREASE
aNUM_JAC_DIFF_SMALL
aNUM_JAC_DIFF_BIG
aNUM_JAC_FACTOR_DECREASE
aNUM_JAC_MIN_FACTOR
equal
groups
h_vecs
wTafind
utoo many values to unpack (expected 3)
coo_matrix
T ashape
tocsc
array
T l
T aaxis
ravel
zeros
unique
D adtype
Oint
h_new_all
groups_map
data
repeat
indptr
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
itertools
T agroupby
warnings
T awarn
numpy
uscipy.sparse
T afind
coo_matrix
finfo
eps
validate_first_step
validate_max_step
warn_extraneous
validate_tol
select_initial_step
