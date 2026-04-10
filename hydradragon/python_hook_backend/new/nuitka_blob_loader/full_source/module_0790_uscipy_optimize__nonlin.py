# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._nonlin

uasjacobian.<locals>.Jac
a__qualname__
uasjacobian.<locals>.Jac.update
uasjacobian.<locals>.Jac.solve
uasjacobian.<locals>.Jac.matvec
uasjacobian.<locals>.Jac.rsolve
uasjacobian.<locals>.Jac.rmatvec
a__orig_bases__
broyden1
aBroydenFirst
broyden2
aBroydenSecond
anderson
aAnderson
diagbroyden
aDiagBroyden
linearmixing
aLinearMixing
excitingmixing
aExcitingMixing
krylov
aKrylovJacobian
uCannot convert object to a Jacobian
dot
wJaconj
wTuUnknown matrix type
last_f
last_x
alpha
f
?a_update
cs
ds
wnacollapsed
get_blas_funcs
axpy
scal
dotc
:nl nwvwwaidentity
wAwdazeros
wqaLowRankMatrix
a_matvec
a_solve
T :nnnnT n:nnnaappend
collapse
warnings
warn
uLowRankMatrix is scipy-internal code, `dtype` should only be None but was
u (not handled)
D astacklevel
l uLowRankMatrix is scipy-internal code, `copy` should only be None but was
aGm
copy_if_needed
T acopy
:nnnaself
wpaqr
D amode
economic
svd
D afull_matrices
Fainv
aGenericBroyden
a__init__
max_rank
:l nnareduce_params
uBroydenFirst.__init__.<locals>.<lambda>
a_reduce
simple
restart
uUnknown rank reduction method '
w'asvd_reduce
simple_reduce
restart_reduce
vdot
wMadf
w0
empty
wfadf_f
waaLinAlgError
wbapop
triu
full
diag
q aalphamax
beta
clip
T aout
preconditioner
bicgstab
gmres
lgmres
cgs
minres
tfqmr
method
maxiter
method_kw
setdefault
T aatol
l
gcrotmk
outer_k
outer_v
T aprepend_outer_v
tT astore_outer_Av
Fasignature
parameters
T aself
args
kwargs
startswith
T ainner_
uUnknown parameter
:l nnavalid_inner_params
get_close_matches
D wnl u Did you mean '
u'?
uOption '
u' is invalid for the inner method:
u. It will be ignored.Please check inner method documentation for valid options.
l aUserWarning
T astacklevel
category
f0
omega
uFunction returned non-finite results
rtol
op
a_update_diff_step
aslinearoperator
a_getfullargspec
utoo many values to unpack (expected 7)
u,
w=uUnexpected signature

def %(name)s(F, xin, iter=None %(kw)s, verbose=False, maxiter=None,
f_tol=None, f_rtol=None, x_tol=None, x_rtol=None,
tol_norm=None, line_search='armijo', callback=None, **kw):
jac = %(jac)s(%(kwkw)s **kw)
return nonlin_solve(F, xin, jac, iter, verbose, maxiter,
f_tol, f_rtol, x_tol, x_rtol, tol_norm, line_search,
callback)
name
kw
jac
kwkw
args
varargs
varkw
defaults
kwonlyargs
kwdefaults
w_akwargs
kw_str
kwkw_str
wrapper
ns
u<string>
exec
a_set_doc
a__file__
a__spec__
origin
has_location
a__cached__
sys
numpy
T aasarray
dot
vdot
uscipy.linalg
T anorm
solve
inv
qr
svd
aLinAlgError
uscipy.sparse.linalg
uscipy.sparse
T aget_blas_funcs
uscipy._lib._util
T acopy_if_needed
a_dedent_for_py313
a_dedent_for_py313
T agetfullargspec_no_self
getfullargspec_no_self
a_linesearch
T ascalar_search_wolfe1
scalar_search_armijo
T asignature
difflib
T aget_close_matches
aGenericAlias
L abroyden1
broyden2
anderson
linearmixing
diagbroyden
excitingmixing
newton_krylov
aBroydenFirst
aKrylovJacobian
aInverseJacobian
aNoConvergence
a__all__
T EException
params_basic
T u
F : function(x) -> f
Function whose root to find; should take and return an array-like
object.
xin : array_like
Initial guess for the solution
strip
params_extra
T u
iter : int, optional
Number of iterations to make. If omitted (default), make as many
s required to meet tolerances.
verbose : bool, optional
Print status to stdout on every iteration.
maxiter : int, optional
Maximum number of iterations to make. If more are needed to
meet convergence, `NoConvergence` is raised.
f_tol : float, optional
Absolute tolerance (in max-norm) for the residual.
If omitted, default is 6e-6.
f_rtol : float, optional
Relative tolerance for the residual. If omitted, not used.
x_tol : float, optional
Absolute minimum step size, as determined from the Jacobian
pproximation. If the step size is smaller than this, optimization
is terminated as successful. If omitted, not used.
x_rtol : float, optional
Relative minimum step size. If omitted, not used.
tol_norm : function(vector) -> scalar, optional
Norm to use in convergence check. Default is the maximum norm.
line_search : {None, 'armijo' (default), 'wolfe'}, optional
Which type of a line search to use to determine the step size in the
direction given by the Jacobian approximation. Defaults to 'armijo'.
callback : function, optional
Optional callback function. It is called on every iteration as
``callback(x, f)`` where `x` is the current solution and `f`
the corresponding residual.
Returns
-------
sol : ndarray
An array (of similar array type as `x0`) containing the final solution.
Raises
------
NoConvergence
When a solution was not found.
Takrylov
nFnnnnnnaarmijo
nFtanonlin_solve
T aarmijo
f: 0  yE>f{  G z ?uTerminationCondition.__init__
uTerminationCondition.check
a__class_getitem__
uJacobian.__init__
aspreconditioner
uJacobian.aspreconditioner
uJacobian.solve
uJacobian.update
uJacobian.setup
uInverseJacobian.__init__
uInverseJacobian.shape
uInverseJacobian.dtype
classmethod
uGenericBroyden.setup
uGenericBroyden._update
uGenericBroyden.update
uLowRankMatrix.__init__
uLowRankMatrix._matvec
uLowRankMatrix._solve
uLowRankMatrix.matvec
uLowRankMatrix.rmatvec
uLowRankMatrix.solve
uLowRankMatrix.rsolve
uLowRankMatrix.append
uLowRankMatrix.__array__
uLowRankMatrix.collapse
uLowRankMatrix.restart_reduce
uLowRankMatrix.simple_reduce
T nuLowRankMatrix.svd_reduce
T u
lpha : float, optional
Initial guess for the Jacobian is ``(-1/alpha)``.
reduction_method : str or tuple, optional
Method used in ensuring that the rank of the Broyden matrix
stays low. Can either be a string giving the name of the method,
or a tuple of the form ``(method, param1, param2, ...)``
that gives the name of the method and values for additional parameters.
Methods available:
- ``restart``: drop all matrix columns. Has no extra parameters.
- ``simple``: drop oldest matrix column. Has no extra parameters.
- ``svd``: keep only the most significant SVD components.
Takes an extra parameter, ``to_retain``, which determines the
number of SVD components to retain when rank reduction is done.
Default is ``max_rank - 2``.
max_rank : int, optional
Maximum rank for the Broyden matrix.
Default is infinity (i.e., no rank reduction).
broyden_params
T narestart
nuBroydenFirst.__init__
uBroydenFirst.setup
uBroydenFirst.todense
uBroydenFirst.solve
uBroydenFirst.matvec
uBroydenFirst.rsolve
uBroydenFirst.rmatvec
uBroydenFirst._update
uBroydenSecond._update
T nf{  G z ?l uAnderson.__init__
uAnderson.solve
uAnderson.matvec
uAnderson._update
uDiagBroyden.__init__
uDiagBroyden.setup
uDiagBroyden.solve
uDiagBroyden.matvec
uDiagBroyden.rsolve
uDiagBroyden.rmatvec
uDiagBroyden.todense
uDiagBroyden._update
uLinearMixing.__init__
uLinearMixing.solve
uLinearMixing.matvec
uLinearMixing.rsolve
uLinearMixing.rmatvec
uLinearMixing.todense
uLinearMixing._update
T nf
?uExcitingMixing.__init__
uExcitingMixing.setup
uExcitingMixing.solve
uExcitingMixing.matvec
uExcitingMixing.rsolve
uExcitingMixing.rmatvec
uExcitingMixing.todense
uExcitingMixing._update
T nalgmres
l nl
uKrylovJacobian.__init__
uKrylovJacobian._update_diff_step
uKrylovJacobian.matvec
uKrylovJacobian.solve
uKrylovJacobian.update
uKrylovJacobian.setup
a_nonlin_wrapper
newton_krylov
uscipy\optimize\_nonlin.py
T aself
reduce_params
T areduce_params
self
T wvwJT wJT wvatol
wJT wvatol
spsolve
wJT wJaspsolve
u<module scipy.optimize._nonlin>
T a__class__
T aself
dtype
copy
T aself
dtype
copy
aGm
wcwdT aself
alpha
w0
wMT aself
alpha
reduction_method
max_rank
reduce_params
T aself
alpha
T aself
alpha
alphamax
T aself
jacobian
T aself
kw
names
name
value
a__array__
T aself
rdiff
method
inner_maxiter
inner_M
outer_k
kw
valid_inner_params
key
value
inner_param_suggestions
suggestion_msg
T aself
alpha
wnadtype
T aself
f_tol
f_rtol
x_tol
x_rtol
aiter
norm
T wxax0
wrap
T wxT wvaalpha
cs
ds
axpy
scal
dotc
wwwcwdwaT afunc
wxaFx
dx
search_type
rdiff
smin
tmp_s
tmp_Fx
tmp_phi
s_norm
phi
derphi
wsaphi1
phi0
aFx_norm
T aname
jac
signature
args
varargs
varkw
defaults
kwonlyargs
kwdefaults
w_akwargs
kw_str
kwkw_str
wrapper
ns
func
T wvT aobj
T wvaalpha
cs
ds
axpy
dotc
c0
wAwiwdwjwcwqwwaqc
T aself
wxwfadx
df
dx_norm
df_norm
wnwawiwjawd
T
self
wxwfadx
df
dx_norm
df_norm
wvwcwdT aself
wxwfadx
df
dx_norm
df_norm
T aself
wxwfadx
df
dx_norm
df_norm
incr
T aself
mx
mf
T aself
wcwdT wJaspsolve
aJac
T aself
T aself
wfwxadx
f_norm
x_norm
dx_norm
T wsads
s_norm
rdiff
phi
T aphi
rdiff
s_norm
T wzwFax0
T wFax0
T aself
wfadx
wnadf_f
wkwbwiwjagamma
wmT aself
wfT aself
wvanv
sc
wrT aself
wvT aself
wvwmwJT wFax0
jacobian
aiter
verbose
maxiter
f_tol
f_rtol
x_tol
x_rtol
tol_norm
line_search
callback
full_output
raise_exception
condition
func
wxadx
aFx
aFx_norm
gamma
eta_max
eta_treshold
eta
wnastatus
tol
wsaFx_norm_new
eta_A
info
T wsastore
xt
wvwpatmp_s
tmp_phi
wxadx
func
tmp_Fx
T adx
func
tmp_Fx
tmp_phi
tmp_s
wxT aself
rank
T aself
wfatol
T aself
wvatol
T aself
wvatol
wmwJaspsolve
T aself
wxwFafunc
T aself
x0
f0
func
normf0
T aself
wxwfafunc
T	aself
wfatol
dx
wnadf_f
wkagamma
wmT aself
wfatol
wrT aself
rhs
tol
sol
info
Taself
max_rank
to_retain
wpwqwmwCwDwRwUwSaWH
wkT aself
wxwfadf
dx
T aself
wxwFT aself
wxwf.scipy.optimize._numdiff
u1-sided
np
ones_like
D adtype
Obool
u2-sided
abs
zeros_like
u`scheme` must be '1-sided' or '2-sided'.
all
inf
whacopy
maximum
q aminimum
f
?ah_adjusted
finfo
float64
eps
issubdtype
inexact
dtype
itemsize
x0_itemsize
T u2-point
cs
T u3-point
fUUUUUU ?uUnknown step method, should be one of {'2-point', '3-point', 'cs'}
l
astype
T Ofloat
l l a_eps_for_method
f
?awhere
utoo many values to unpack (expected 2)
ndim
resize
shape
lb
ub
asarray
D adtype
Ofloat
u<genexpr>
u_prepare_bounds.<locals>.<genexpr>
issparse
csc_array
atleast_2d
int32
u`A` must be 2-dimensional.
isscalar
random
aRandomState
permutation
u`order` has incorrect shape.
:nnnaorder
group_sparse
indices
indptr
group_dense
T u2-point
u3-point
cs
uUnknown method '

u'.
D anfev
naarray_namespace
xpx
atleast_nd
T andim
xp
isdtype
ureal floating
u`x0` must have at most 1 dimension.
a_prepare_bounds
uInconsistent shapes between bounds and `x0`.
isinf
uBounds not supported when `as_linear_operator` is True.
a_Fun_Wrapper
atleast_1d
u`f0` passed has more than 1 dimension.
any
u`x0` violates bound constraints.
f0
a_linear_operator_difference
a_compute_absolute_step
method
u2-point
a_adjust_scheme_to_bounds
u3-point
cs
aMapWrapper
a__enter__
a__exit__
a_dense_difference
use_one_sided
group_columns
tocsc
a_sparse_difference
T nnnanfev
wJasize
matvec
u_linear_operator_difference.<locals>.matvec
uNever be here.
aLinearOperator
array_equal
zeros
wmanorm
x0
fun
JZ
f
?aimag
empty
x_generator2
u_dense_difference.<locals>.x_generator2
x_generator3
u_dense_difference.<locals>.x_generator3
dx
df
f
l ax_generator_cs
u_dense_difference.<locals>.x_generator_cs
df_dx
aJ_transposed
ravel
wTwnax1
x2
T Ocomplex
tT acopy
max
e_generator
u_sparse_difference.<locals>.e_generator
u_sparse_difference.<locals>.x_generator2
u_sparse_difference.<locals>.x_generator3
u_sparse_difference.<locals>.x_generator_cs
nonzero
utoo many values to unpack (expected 1)
find
utoo many values to unpack (expected 3)
xs
f_evals
q arow_indices
col_indices
fractions
hstack
isspmatrix
csr_matrix
T ashape
csr_array
n_groups
equal
groups
args
kwargs
wxu`fun` return value has more than 1 dimension.
approx_derivative
T abounds
sparsity
args
kwargs
T abounds
args
kwargs
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
functools
numpy
unumpy.linalg
T anorm
uscipy.sparse.linalg
T aLinearOperator
sparse
T aissparse
isspmatrix
find
csc_array
csr_array
csr_matrix
a_group_columns
T agroup_dense
group_sparse
uscipy._lib._array_api
T aarray_namespace
uscipy._lib._util
T aMapWrapper
uscipy._lib
T aarray_api_extra
array_api_extra
lru_cache
T l
