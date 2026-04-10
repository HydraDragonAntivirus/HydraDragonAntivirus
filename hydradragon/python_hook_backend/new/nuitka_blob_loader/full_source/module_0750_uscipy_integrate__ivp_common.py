# Reconstructed from integrated Nuitka blob
# Module: uscipy.integrate._ivp.common

aOdeSolution
a__qualname__
T Fa__init__
uOdeSolution.__init__
uOdeSolution._call_single
a__call__
uOdeSolution.__call__
f
?f
?f
?f
@ @f       ?T nanum_jac
uscipy\integrate\_ivp\common.py
T a.0
wxu<module scipy.integrate._ivp.common>
T aself
wtaorder
reverse
t_sorted
segments
ys
group_start
segment
group
group_end
wyT aself
ts
interpolants
alt_segment
wdT aself
wtaind
segment
T afun
wtwywfwhafactor
y_scale
wnah_vecs
f_new
diff
max_ind
wramax_diff
scale
diff_too_small
ind
new_factor
h_new
diff_new
max_diff_new
scale_new
update
update_ind
T&afun
wtwywfwhafactor
y_scale
structure
groups
wnan_groups
h_vecs
group
weaf_new
df
wiwjw_adiff
max_ind
wramax_diff
scale
diff_too_small
ind
new_factor
h_new
h_new_all
groups_unique
groups_map
wkadiff_new
max_ind_new
max_diff_new
scale_new
update
update_ind
T wxT afun
wtwywfathreshold
factor
sparsity
wnaf_sign
y_scale
whwiastructure
groups
T afun
t0
y0
t_bound
max_step
f0
direction
order
rtol
atol
interval_length
scale
d0
d1
h0
y1
f1
d2
h1
T afirst_step
t0
t_bound
T amax_step
T artol
atol
wnT aextraneous
.scipy.integrate._ivp
\
/
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
uintegrate\_ivp
T aNUITKA_PACKAGE_scipy_integrate
u\not_existing
a_ivp
T aNUITKA_PACKAGE_scipy_integrate__ivp
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
ivp
T asolve_ivp
l asolve_ivp
l
rk
T aRK23
aRK45
aDOP853
aRK23
aRK45
aDOP853
radau
T aRadau
aRadau
bdf
T aBDF
aBDF
lsoda
T aLSODA
aLSODA
common
T aOdeSolution
aOdeSolution
base
T aDenseOutput
aOdeSolver
aDenseOutput
aOdeSolver
uscipy\integrate\_ivp\__init__.py
u<module scipy.integrate._ivp>

.scipy.integrate._ivp.dop853_coefficients
1 a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
l
np
l aN_STAGES
l aN_STAGES_EXTENDED
l aINTERPOLATOR_POWER
array
L Z
f:  8h  ?f , * 2 ?f C ?5L ?f   I   ?fUUUUUU ?f
?f ;  ;  ?fuM tM  ?f333333 ?f  m  m ?f
?f
?f       ?f       ?f9  8   ?wCazeros
wAf:  8h  ?T l l
f , * 2 ?T l l
f C ?5L ?T l l f C ?5L ?T l l
fA   '  ?T l l f   ~  ?T l l
f    :N  T l l f   z=  ?T l l fh/     ?T l l
f6m ;   ?T l l f  f?S  ?T l l f
?T l l
f G3    ?T l l fM 2    ?T l l f
T l l f       ?T l l
fr]Y #  ?T l l f   @ u ?T l l f/    _  T l l fq  .   ?T l l f X     ?T l l
f
T l l f    s   T l l fU     ;@T l l fi   p'4@T l l f B\   E T l l fU !    ?T l	l
f  K     T l	l f        T l	l f U   :5@T l	l f X    .@T l	l f      @ T l	l fv       T l	l f 9      T l
l
f   i   @T l
l f .y  v ?T l
l f     L  T l
l f u  # 2 T l
l f:   O 6@T l
l f   w   @T l
l f,W+ _  T l
l	f  	; / @T l l
fU  c  % T l l f r 5
T l l f 0  | 1 T l l f      ;@T l l f   }:   T l l f 3    ! T l l fa  B  (@T l l	f  Sb   ?T l l
f|  hc  ?T l l
f Z     @T l l f   E C ?T l l fC   n4  T l l f       ?T l l f  C  z  T l l	f-  iW  ?T l l
f k PO  ?T l l fH      ?T ll
f 5  X9 ?T ll f> w     T ll f  \U    T ll f  -    ?T ll	f,e8    ?T ll
f k9   ~?T ll f0H      T ll fc {  L ?T l l
fE      ?T l l f  |  i ?T l l fi  /    T l l fS    g  T l l
f # Rz 9?T l l f     P6 T l l f       ?T l lf `+y	s  T l l
f   D]   T l l f       @T l l f  WD F @T l l fD  D   ?T l l f qH   V T l l f  ?    @T l lf"" mJM" T l l wBl aE3
copy
:nq nf    |> ?l fWQ   { ?l f       ?aE5
f ~`    ?f  Z =   l fr       l f	   I  ?fq~   k  f 9x 0c ?l	f5  T   ?l
f k PO   l wDf  7     T l
pf   e " ?T l
l fvS  5   T l
l f b     @T l
l f
@T l
l f  J p   T l
l	f   uj  @T l
l
f 3   5 ?T l
l f|       T l
l f X3u &2@T l
lf  `  c" T l
l f X R    T l
l f D i  $@fg W] In@T l l fKC  j d@T l l f5N   hw T l l f  XE  6 T l l f# 3    @T l l	f "   > T l l
f
*  " T l l f| %e d/@T l l fS    #? T l lf ef   " T l l f
C  A@T l l f 8 s, 3@f!%   0x T l l f9M N  g T l l f j, w~ @T l l f o   %' T l l f    a  @T l l	fh g}z   T l l
f13=    ?T l l f V   9  T l l f  0O- N T l lf (    U@T l l f  t  '@T l l f      9 f ` k Fc T l l f 	    l T l l f    9Zv@T l l fp<   YW@T l l f  !U  B T l l	f  U ` Z@T l l
f  Rx  =@T l l f~ 7NH E T l l f   }  X@T l lf      C T l l f  >B b T l l uscipy\integrate\_ivp\dop853_coefficients.py
u<module scipy.integrate._ivp.dop853_coefficients>

.scipy.integrate._ivp.ivp
n
callable
np
empty
utoo many values to unpack (expected 2)
terminal
direction
l
uThe `terminal` attribute of each event must be a boolean or positive integer.
inf
max_events
uscipy.optimize
T abrentq
brentq
u<lambda>
usolve_event_equation.<locals>.<lambda>
l aEPS
T axtol
rtol
event
sol
solve_event_equation
t_old
wtaasarray
any
argsort
nonzero
l aactive_events
aMETHODS
inspect
isclass
aOdeSolver
u`method` must be one of

u or OdeSolver class.
uSupplied 'args' cannot be unpacked. Please supply `args` as a tuple (e.g. `args=(
u,)`)
fun
usolve_ivp.<locals>.fun
jac
usolve_ivp.<locals>.<lambda>
ndim
u`t_eval` must be 1-dimensional.
min
max
uValues in `t_eval` are not within `t_span`.
diff
uValues in `t_eval` are not properly sorted.
:nnq ashape
method
vectorized
t_eval
prepare_events
utoo many values to unpack (expected 3)
zeros
events
t0
y0
status
solver
step
finished
failed
q wyadense_output
interpolants
find_active_events
wgaevent_dir
size
event_count
handle_events
append
ts
ys
pop
searchsorted
D aside
right
t_eval_i
D aside
left
ti
aMESSAGES
get
message
array
vstack
wTahstack
aOdeSolution
aBDF
aLSODA
T aalt_segment
aOdeResult
nfev
njev
nlu
T wtwyasol
t_events
y_events
nfev
njev
nlu
status
message
success
args
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
bdf
T aBDF
radau
T aRadau
aRadau
rk
T aRK23
aRK45
aDOP853
aRK23
aRK45
aDOP853
lsoda
T aLSODA
T aOptimizeResult
aOptimizeResult
common
T aEPS
aOdeSolution
base
T aOdeSolver
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
D l
l uThe solver successfully reached the end of the integration interval.
uA termination event occurred.
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
