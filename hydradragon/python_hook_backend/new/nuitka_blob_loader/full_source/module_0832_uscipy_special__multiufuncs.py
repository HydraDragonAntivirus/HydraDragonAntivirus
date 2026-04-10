# Reconstructed from integrated Nuitka blob
# Module: uscipy.special._multiufuncs

aMultiUFunc
a__qualname__
T nnD aforce_complex_output
Fa__init__
uMultiUFunc.__init__
uMultiUFunc.__doc__
a_override_key
uMultiUFunc._override_key
a_override_ufunc_default_args
uMultiUFunc._override_ufunc_default_args
a_override_ufunc_default_kwargs
uMultiUFunc._override_ufunc_default_kwargs
a_override_resolve_out_shapes
uMultiUFunc._override_resolve_out_shapes
a_override_finalize_out
uMultiUFunc._override_finalize_out
uMultiUFunc._resolve_ufunc
a__call__
uMultiUFunc.__call__
usph_legendre_p(n, m, theta, *, diff_n=0)
Spherical Legendre polynomial of the first kind.
Parameters
----------
n : ArrayLike[int]
Degree of the spherical Legendre polynomial. Must have ``n >= 0``.
m : ArrayLike[int]
Order of the spherical Legendre polynomial.
theta : ArrayLike[float]
Input value.
diff_n : Optional[int]
A non-negative integer. Compute and return all derivatives up
to order ``diff_n``. Default is 0.
Returns
-------
p : ndarray or tuple[ndarray]
Spherical Legendre polynomial with ``diff_n`` derivatives.
Notes
-----
The spherical counterpart of an (unnormalized) associated Legendre polynomial has
the additional factor
.. math::
\sqrt{\frac{(2 n + 1) (n - m)!}{4 \pi (n + m)!}}
It is the same as the spherical harmonic :math:`Y_{n}^{m}(\theta, \phi)`
with :math:`\phi = 0`.
D adiff_n
l
w_usph_legendre_p_all(n, m, theta, *, diff_n=0)
All spherical Legendre polynomials of the first kind up to the
specified degree ``n``, order ``m``, and all derivatives up
to order ``diff_n``.
Output shape is ``(diff_n + 1, n + 1, 2 * m + 1, ...)``. The entry at
``(i, j, k)`` corresponds to the ``i``-th derivative, degree ``j``, and
order ``k`` for all ``0 <= i <= diff_n``, ``0 <= j <= n``, and
``-m <= k <= m``.
See Also
--------
sph_legendre_p
uassoc_legendre_p(n, m, z, *, branch_cut=2, norm=False, diff_n=0)
Associated Legendre polynomial of the first kind.
Parameters
----------
n : ArrayLike[int]
Degree of the associated Legendre polynomial. Must have ``n >= 0``.
m : ArrayLike[int]
order of the associated Legendre polynomial.
z : ArrayLike[float | complex]
Input value.
branch_cut : Optional[ArrayLike[int]]
Selects branch cut. Must be 2 (default) or 3.
2: cut on the real axis ``|z| > 1``
3: cut on the real axis ``-1 < z < 1``
norm : Optional[bool]
If ``True``, compute the normalized associated Legendre polynomial.
Default is ``False``.
diff_n : Optional[int]
A non-negative integer. Compute and return all derivatives up
to order ``diff_n``. Default is 0.
Returns
-------
p : ndarray or tuple[ndarray]
Associated Legendre polynomial with ``diff_n`` derivatives.
Notes
-----
The normalized counterpart of an (unnormalized) associated Legendre
polynomial has the additional factor
.. math::
\sqrt{\frac{(2 n + 1) (n - m)!}{2 (n + m)!}}
D abranch_cut
norm
diff_n
l Fl
uassoc_legendre_p_all(n, m, z, *, branch_cut=2, norm=False, diff_n=0)
All associated Legendre polynomials of the first kind up to the
specified degree ``n``, order ``m``, and all derivatives up
to order ``diff_n``.
Output shape is ``(diff_n + 1, n + 1, 2 * m + 1, ...)``. The entry at
``(i, j, k)`` corresponds to the ``i``-th derivative, degree ``j``, and
order ``k`` for all ``0 <= i <= diff_n``, ``0 <= j <= n``, and
``-m <= k <= m``.
See Also
--------
ssoc_legendre_p
ulegendre_p(n, z, *, diff_n=0)
Legendre polynomial of the first kind.
Parameters
----------
n : ArrayLike[int]
Degree of the Legendre polynomial. Must have ``n >= 0``.
z : ArrayLike[float]
Input value.
diff_n : Optional[int]
A non-negative integer. Compute and return all derivatives up
to order ``diff_n``. Default is 0.
Returns
-------
p : ndarray or tuple[ndarray]
Legendre polynomial with ``diff_n`` derivatives.
See Also
--------
legendre
References
----------
.. [1] Zhang, Shanjie and Jin, Jianming. "Computation of Special
Functions", John Wiley and Sons, 1996.
https://people.sc.fsu.edu/~jburkardt/f77_src/special_functions/special_functions.html
ulegendre_p_all(n, z, *, diff_n=0)
All Legendre polynomials of the first kind up to the specified degree
``n`` and all derivatives up to order ``diff_n``.
Output shape is ``(diff_n + 1, n + 1, ...)``. The entry at ``(i, j)``
corresponds to the ``i``-th derivative and degree ``j`` for all
``0 <= i <= diff_n`` and ``0 <= j <= n``.
See Also
--------
legendre_p
usph_harm_y(n, m, theta, phi, *, diff_n=0)
Spherical harmonics. They are defined as
.. math::
Y_n^m(\theta,\phi) = \sqrt{\frac{2 n + 1}{4 \pi} \frac{(n - m)!}{(n + m)!}}
P_n^m(\cos(\theta)) e^{i m \phi}
where :math:`P_n^m` are the (unnormalized) associated Legendre polynomials.
Parameters
----------
n : ArrayLike[int]
Degree of the harmonic. Must have ``n >= 0``. This is
often denoted by ``l`` (lower case L) in descriptions of
spherical harmonics.
m : ArrayLike[int]
Order of the harmonic.
theta : ArrayLike[float]
Polar (colatitudinal) coordinate; must be in ``[0, pi]``.
phi : ArrayLike[float]
Azimuthal (longitudinal) coordinate; must be in ``[0, 2*pi]``.
diff_n : Optional[int]
A non-negative integer. Compute and return all derivatives up
to order ``diff_n``. Default is 0.
Returns
-------
y : ndarray[complex] or tuple[ndarray[complex]]
Spherical harmonics with ``diff_n`` derivatives.
Notes
-----
There are different conventions for the meanings of the input
rguments ``theta`` and ``phi``. In SciPy ``theta`` is the
polar angle and ``phi`` is the azimuthal angle. It is common to
see the opposite convention, that is, ``theta`` as the azimuthal angle
nd ``phi`` as the polar angle.
Note that SciPy's spherical harmonics include the Condon-Shortley
phase [2]_ because it is part of `sph_legendre_p`.
With SciPy's conventions, the first several spherical harmonics
re
.. math::
Y_0^0(\theta, \phi) &= \frac{1}{2} \sqrt{\frac{1}{\pi}} \\
Y_1^{-1}(\theta, \phi) &= \frac{1}{2} \sqrt{\frac{3}{2\pi}}
e^{-i\phi} \sin(\theta) \\
Y_1^0(\theta, \phi) &= \frac{1}{2} \sqrt{\frac{3}{\pi}}
\cos(\theta) \\
Y_1^1(\theta, \phi) &= -\frac{1}{2} \sqrt{\frac{3}{2\pi}}
e^{i\phi} \sin(\theta).
References
----------
.. [1] Digital Library of Mathematical Functions, 14.30.
https://dlmf.nist.gov/14.30
.. [2] https://en.wikipedia.org/wiki/Spherical_harmonics#Condon.E2.80.93Shortley_phase
D aforce_complex_output
diff_n
tl
usph_harm_y_all(n, m, theta, phi, *, diff_n=0)
All spherical harmonics up to the specified degree ``n``, order ``m``,
nd all derivatives up to order ``diff_n``.
Returns a tuple of length ``diff_n + 1`` (if ``diff_n > 0``). The first
entry corresponds to the spherical harmonics, the second entry
(if ``diff_n >= 1``) to the gradient, and the third entry
(if ``diff_n >= 2``)  to the Hessian matrix. Each entry is an array of
shape ``(n + 1, 2 * m + 1, ...)``, where the entry at ``(i, j)``
corresponds to degree ``i`` and order ``j`` for all ``0 <= i <= n``
nd ``-m <= j <= m``.
See Also
--------
sph_harm_y
uscipy\special\_multiufuncs.py
T a.0
ufunc_arg
T a.0
ufunc_out_dtype
T a.0
ufunc_out_shape
ufunc_out_dtype
T a.0
wxT aargs
kwargs
u<module scipy.special._multiufuncs>
T a__class__
T abranch_cut
norm
diff_n
T adiff_n
T wnwmatheta_shape
nout
diff_n
T wnwmatheta_shape
phi_shape
nout
kwargs
diff_n
T wnwmaz_shape
branch_cut_shape
nout
kwargs
diff_n
T wnaz_shape
nout
diff_n
T aout
Taself
args
kwargs
ufunc
ufunc_args
ufunc_kwargs
ufunc_arg_shapes
ufunc_out_shapes
ufunc_arg_dtypes
ufunc_dtypes
ufunc_out_dtypes
ufunc_out_dtype
out
T aself
T	aself
ufunc_or_ufuncs
name
doc
force_complex_output
default_kwargs
ufuncs_iter
seen_input_types
ufunc
T aself
func
T aself
kwargs
ufunc_key
.scipy.special._orthogonal
w
wfunc
sqrt
eval_func
uorthopoly1d.__init__.<locals>.eval_func
f
?anp
poly1d
D wrta__init__
coeffs
array
weights
weight_func
limits
normcoef
a_eval_func
evf
knn
a__call__
a_coeffs
u<lambda>
uorthopoly1d._scale.<locals>.<lambda>
wpascipy
T alinalg
l
linalg
arange
D adtype
wdazeros
l :l nnT l
:l nnT l :nnnaeigvals_banded
D aoverwrite_a_band
tl alog
abs
exp
max
min
f
@:nnq asum
wxun must be a positive integer.
q ualpha and beta must be greater than -1.
Z
roots_legendre
roots_gegenbauer
f
?l  a_ufuncs
beta
T f
@abetaln
an_func
uroots_jacobi.<locals>.an_func
bn_func
uroots_jacobi.<locals>.bn_func
wfuroots_jacobi.<locals>.f
df
uroots_jacobi.<locals>.df
a_gen_roots_and_weights
where
wbwaaeval_jacobi
un must be nonnegative.
ujacobi.<locals>.wfunc
orthopoly1d
T q l aones_like
T aeval_func
roots_jacobi
D amu
tutoo many values to unpack (expected 3)
a_gam
ujacobi.<locals>.<lambda>
alpha
wnu(p - q) must be greater than -1, and q must be greater than 0.
ush_jacobi.<locals>.wfunc
roots_sh_jacobi
utoo many values to unpack (expected 2)
T l
l ush_jacobi.<locals>.<lambda>
T awfunc
limits
monic
eval_func
wqaeval_sh_jacobi
ualpha must be greater than -1.
gamma
wduroots_genlaguerre.<locals>.an_func
uroots_genlaguerre.<locals>.bn_func
uroots_genlaguerre.<locals>.f
uroots_genlaguerre.<locals>.df
eval_genlaguerre
ualpha must be > -1
roots_genlaguerre
ugenlaguerre.<locals>.wfunc
T L
painf
ugenlaguerre.<locals>.<lambda>
T amu
roots_laguerre
ulaguerre.<locals>.<lambda>
eval_laguerre
pi
l  uroots_hermite.<locals>.an_func
uroots_hermite.<locals>.bn_func
eval_hermite
uroots_hermite.<locals>.df
a_roots_hermite_asy
f
@afloor
f
@u_compute_tauk.<locals>.f
u_compute_tauk.<locals>.df
xi
sin
wcacos
a_compute_tauk
f
@f
?a_specfun
airyzo
f<n=  e ?fUUUUUU ?f< =a   ?fUUUUUU  fP uP u ?fE '    ?l f
fH g    ?f`A     ?l f        f ^PTxt?l f  J  _ ?f r   ( ?f        f_ Dj i ?f
@aaround
astype
T Oint
a_initial_nodes_a
a_initial_nodes_b
hstack
fUUUUUU ?T l areshape
T T q l T l :nnnf
@f
8@f
" T l :nnnf
o@T l :nnnf
b@f
@f
T l	:nnnf
@  @T l :nnnf
@T l :nnnf
Af
Af
P Af
@  @T l
:nnnf
AT l :nnnf
0  AT l :nnnf
8 J Af
H ; Af
\hAf
Af
AT l :nnnf
d j AT l:nnnf
m6  AT l :nnnf
Af
P /  Af
f!Bf
;Bf
h d  Bf
Af
.@f
pt@f
a@f
`  @f
Af
f
j  Af
Af
H$i Af
Al    f
. Af
(  Af
Af
5 e Bf
d{>Bg       aairy
utoo many values to unpack (expected 4)
fUUUUUU ?T l l l fr  q G  T l
:nnnf        f@ 9SsM  fk~X  X  l f       ?f H x i ?f9  8 c ?f_  cJ6 ?fd      ?l fUUUUUU ?f: (,a(  l aarccos
a_pbcf
theta
mu
f +     =aud
a_initial_nodes
a_newton
:q l
q aroots_hermite
uhermite.<locals>.wfunc
uhermite.<locals>.<lambda>
uroots_hermitenorm.<locals>.an_func
uroots_hermitenorm.<locals>.bn_func
eval_hermitenorm
uroots_hermitenorm.<locals>.df
T l aroots_hermitenorm
uhermitenorm.<locals>.wfunc
uhermitenorm.<locals>.<lambda>
f
ualpha must be greater than -0.5.
roots_chebyt
l  L fF 90 (+?f&  {  X fk     D f  3T  s?f
?f
f
?amu0
inv_alpha
uroots_gegenbauer.<locals>.an_func
uroots_gegenbauer.<locals>.bn_func
uroots_gegenbauer.<locals>.f
uroots_gegenbauer.<locals>.df
eval_gegenbauer
isfinite
u`alpha` must be a finite number greater than -1/2
jacobi
T amonic
a_scale
ugegenbauer.<locals>.<lambda>
a_sinpi
full_like
uchebyt.<locals>.wfunc
uchebyt.<locals>.<lambda>
eval_chebyt
f
?aroots_chebyc
uchebyc.<locals>.<lambda>
T q l T awfunc
limits
monic
eval_chebyc
roots_chebyu
roots_chebys
uchebys.<locals>.<lambda>
eval_chebys
sh_jacobi
T f
?f
?uroots_legendre.<locals>.an_func
uroots_legendre.<locals>.bn_func
eval_legendre
uroots_legendre.<locals>.df
ulegendre.<locals>.<lambda>
ush_legendre.<locals>.wfunc
ush_legendre.<locals>.<lambda>
roots_sh_legendre
T alimits
monic
eval_func
eval_sh_legendre
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
T aexp
inf
pi
sqrt
floor
sin
cos
around
hstack
arccos
arange
uscipy.special
T aairy

T a_specfun
T a_ufuncs
L alegendre
chebyt
chebyu
chebyc
chebys
jacobi
laguerre
genlaguerre
hermite
hermitenorm
gegenbauer
sh_legendre
sh_chebyt
sh_chebyu
sh_jacobi
a_polyfuns
D aroots_legendre
roots_chebyt
roots_chebyu
roots_chebyc
roots_chebys
roots_jacobi
roots_laguerre
roots_genlaguerre
roots_hermite
roots_hermitenorm
roots_gegenbauer
roots_sh_legendre
roots_sh_chebyt
roots_sh_chebyu
roots_sh_jacobi
p_roots
t_roots
u_roots
c_roots
s_roots
j_roots
l_roots
la_roots
h_roots
he_roots
cg_roots
ps_roots
ts_roots
us_roots
js_roots
a_rootfuns_map
a__all__
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
