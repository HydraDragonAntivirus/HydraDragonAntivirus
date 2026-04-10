# Reconstructed from integrated Nuitka blob
# Module: unumba.np.polynomial.polynomial_core

a__qualname__
uPolynomialModel.__init__
a__orig_bases__
type_polynomial
impl_polynomial1
impl_polynomial3
unbox_polynomial
box_polynomial
unumba\np\polynomial\polynomial_core.py
u<module numba.np.polynomial.polynomial_core>
T a__class__
T aself
dmm
fe_type
members
a__class__
Tatyp
val
wcaret_ptr
fail_obj
stack
polynomial
coef_obj
domain_obj
window_obj
class_obj
res1
res3
T acontext
builder
sig
args
to_double
const_impl
typ
polynomial
sig_coef
coef_cast
sig_domain
sig_window
domain_cast
window_cast
T acontext
builder
sig
args
to_double
typ
polynomial
coef_sig
domain_sig
window_sig
coef_cast
domain_cast
window_cast
domain_helper
window_helper
i64
two
s1
s2
pred1
pred2
T aarr
T acoef
T acontext
typer
T	acoef
domain
window
default_domain
double_domain
default_window
double_window
double_coef
msg
T atyp
obj
wcais_error_ptr
polynomial
stack
natives
name
attr
wtanative

.numba.np.polynomial.polynomial_functions
dtype
types
aInteger
np
float64
as_dtype
roots_impl
uroots_impl.<locals>.roots_impl
shape
uInput must be a 1d array.
nonzero
l
zeros
cast_t
T l
T adtype
q l adiag
ones
wT:l nnT l
:nnnalinalg
eigvals
hstack
type_can_asarray
errors
aTypingError
T uThe argument "seq" must be array-like
aBaseTuple
uUnsupported type %r for argument "seq"
ndim
aNumbaValueError
T uCoefficient array is not 1-d
impl
upolyutils_trimseq.<locals>.impl
wiT uThe argument "alist" must be array-like
aBoolean
T uThe argument "trim" must be boolean
aList
any
array
a_poly_result_dtype
a_get_list_type
result_type
l T tupolyutils_as_series.<locals>.impl
tuple_input
literal_unroll
arrays
atleast_1d
asarray
astype
res_dtype
list_input
min
size
uCoefficient array is empty
pu
trimseq
aNumber
aArray
T uInput dtype must be scalar
append
aNumbaNotImplementedError
T uInput dtype must be scalar.
from_dtype
T uThe argument "c1" must be array-like
T uThe argument "c2" must be array-like
unumpy_polyadd.<locals>.impl
as_series
utoo many values to unpack (expected 2)
concatenate
arr1
arr2
unumpy_polysub.<locals>.impl
unumpy_polymul.<locals>.impl
convolve
T uThe argument "x" must be array-like
T uThe argument "c" must be array-like
aBooleanLiteral
aRequireLiteralValue
T uThe argument "tensor" must be boolean
T l aliteral_value
upoly_polyval.<locals>.impl
x_nd_array
tensor_arg
reshape
new_shape
wyainputs
T uThe argument "m" must be an integer
issubdtype
number
uInput dtype must be scalar. Found

u instead
upoly_polyint.<locals>.impl
wcaempty
cdt
tmp
is1D
unumpy_polydiv.<locals>.impl
:nl n:nq nwja__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.polynomial
T apolynomial
polynomial
poly
T apolyutils
polyutils
numba
T aliteral_unroll
unumba.core
T atypes
errors
unumba.core.extending
T aoverload
overload
unumba.np.numpy_support
T atype_can_asarray
as_dtype
from_dtype
roots
polyutils_trimseq
polyutils_as_series
polyadd
numpy_polyadd
polysub
numpy_polysub
polymul
numpy_polymul
polyval
D aprefer_literal
tapoly_polyval
polyint
poly_polyint
polydiv
numpy_polydiv
unumba\np\polynomial\polynomial_functions.py
u<module numba.np.polynomial.polynomial_functions>
T wladt
T aargs
res_dtype
item
s1
msg
wlT ac1
c2
arr1
arr2
diff
zr
val
T
c1
c2
arr1
arr2
l1
l2
dlen
scl
wiwjT ac1
c2
arr1
arr2
val
T	wcwmacdt
wiwnatmp
wjares_dtype
is1D
T ais1D
res_dtype
T wxwcatensor
arr
inputs
wlwywiares_dtype
x_nd_array
tensor_arg
new_shape
T anew_shape
res_dtype
tensor_arg
x_nd_array
T	aalist
trim
arrays
item
alist_arr
ret
tuple_input
res_dtype
list_input
T alist_input
res_dtype
tuple_input
T aseq
wiT ac1
c2
msg
impl
T wcwmamsg
res_dtype
is1D
impl
T	wxwcatensor
msg
res_dtype
x_nd_array
new_shape
tensor_arg
impl
T aalist
trim
msg
res_dtype
tuple_input
list_input
dt
impl
T aseq
msg
impl
T wpaty
cast_t
roots_impl
T wpanon_zero
tz
wnwAaroots
cast_t
T acast_t
.numba.np.random._constants
|`
K
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
l
np
ctypes
array
uint64
T L  g   w    l
g   `     g   m     g   r     g   u     g   w    g   x   Wg   y     g   z     g   {     g   {     g   {     g   |   cg   |     g   |     g   |   >g   }     g   }     g   }     g   }     g   }   jg   }     g   }     g   }     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~   ]g   ~   =g   ~     g   ~     g   ~     g   ~     g   ~    g   ~   Ag   ~     g   ~     g   ~   g   ~     g         g         g         g       eg         g       .g       }g         g         g         g         g         g         g         g         g         g         g         g         g         g         g        g         g       kg         g         g         g         g         g         g       Ng         g         g         g         g         g         g         g         g       /g         g         g       /g         g         g         g         g         g         g         g         g       $g         g         g         g         g         g       "g         g         g         g       |g         g         g         g         g         g       5g         g         g         g         g       	g       |g         g         g         g         g         g         g         g         g         g         g         g       Zg         g         g         g         g         g         g         g         g       pg         g         g        g         g         g         g         g         g         g         g         g       Ug         g         g         g         g         g         g         g       sg         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g       vg         g         g         g         g         g       hg         g         g         g         g         g       Dg         g       Pg         g         g         g         g         g         g         g         g         g         g         g       lg         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g         g        g        g         g   ~     g   ~     g   ~   Ng   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~     g   ~   #g   ~     g   ~     g   ~     g   }    g   }     g   }     g   |     g   |     g   {     g   x     T adtype
ki_double
float64
T L  fy  x;I <f       <f [,< P <fa;D8 | <f  /    <f  L. # <f a8/M
<ftrtZ/  <f  L-H2 <f   '2M <fC] ;   <fw6A    <f  z  ' <f  c8.  <f  W ?< <f/      <fU    9 <f  =6   <ft  bu% <f       <f ~  1  <f=| a k <fp
<f  F  6 <fw*     <fC F E  <fw
CS U <f v{ d  <f  N .  <f  , Gc <fF 8    <f,      <fY wmgb <f0  n   <f l m   <f)zB  U <f: R 6  <f2  *   <f NY p> <fa;2    <f &r    <fH      <f   ) g <f  #
<fSv  :  <f     = <f
oz3   <f    :  <f&b    <f   T Q <f    m  <f . }S  <f 4B V <f  9 @. <f     N <f  r[Vo <f  q    <f a  }  <f  Kf=  <fk  K   <f   2   <f  1 G- <fA   >L <f     k <f4 x    <f m Q   <f *  f  <f.      <f  @    <f   re  <f   } > <f k   [ <f   f*y <f       <f . b   <fS  b   <f       <f Hn
<f0    ' <f ^&pDD <f R   ` <fjX  j} <fd  o   <f =  ;  <f  V    <f Zr    <ft  q
<f]t - & <f 0<
C <f]  s ^ <f6 f  z <f/ H2   <f]A     <f    I  <f  8
<fbU^    <fZ
M! <fOfj  < <f   NwX <fx_U
t <f       <fY $#   <f=s} r  <f  /{   <f8^  O  <f   `   <f     4 <f &   O <fr  W j <f71  B  <f  P)   <f C     <fR (ab  <fT a1   <f h  '  <f  iQ * <f  p  E <f s 5ea <fI    | <f    M  <f	  <   <f "  L  <f  s    <f    g  <fv
" <f     = <f    NY <f ~zo u <f- G_   <fC      <f    e  <f'jDQI  <f  s):
<fG ( 8  <f
F8 <f   ybT <f  p  p <f1*.    <f  ?    <f,   y  <f to+   <fJ  &r  <f 6 9   <f[  ! 7 <f     T <f  JrZq <f=1 dL  <f   >V  <f  Z x  <f6      <f   O   <f[   |  <f
> <f = A [ <f' ? }y <f<   d  <fn%  k  <f  .k   <f       <f   lH  <f-z   . <f n  M <f    fl <f    f  <f  6    <f  ;    <f7 h0^  <fn  2 	 <f  7  ( <fG 3  H <f#    i <f    s  <fpn  	  <f I     <f7.R    <f  I   <f F  t. <f     P <f%  /
r <f
*K!  <f o     <f:  v#  <f   a   <f!S  2  <fmM   B <fh   _f <f    f  <f "q    <f  / `  <f    Y  <fu  G   <fG    ! <f     4 <f  >N G <f~   ;[ <fh& # n <f .c    <fT      <f  qu   <fH   =  <f0= 4   <f e     <f       <fAp  n  <f5]  !) <fm	 i ? <f;.`HdU <f   ; k <fa  t   <f  NV   <f / w   <f  q    <f9      <f       <f       <f  ozG- <f$   EG <f Xv  a <f.Y   | <fx w .  <fR
*S7  <f   1   <f x    <f  V    <f  h^{* <f     I <f@ 3z i <f
AV    <f   pu  <f    '  <fu `    <f       <f ^T  = <f : D d <f C ub  <f'Zk s  <f   %  <fA  S   <fB~:R @ <f  J  q <f  q    <f  :$   <fL   i  <f j
{ S <f    @  <f2 	 k  <f4z_ (' <fs 	V y <f    -  <f4 )  9 <f |     <f Do  . <f W@    <fZw x   <f  x8   <f3 	  ; <awi_double
T L  f
?f  y jD ?f  l[T  ?fw '  ? ?f    o  ?f  W  p ?f   xI  ?f -  3  ?f x  ^j ?f       ?f   N   ?fR  :e  ?f  4 :> ?f  l?*  ?f %z    ?f  P  t ?f     4 ?f  e ;  ?f  $ "  ?f zaWF} ?fGz   B ?fOq1    ?f
OU  ?f   H   ?f  7  a ?fn V  , ?f   K   ?fXh w   ?f   <   ?fV p  \ ?f m?  ) ?f z  P  ?f Zc X  ?f*;Q^   ?f#  *'g ?f  U  7 ?fe&  $	 ?fj Jo   ?f \  )  ?f  L&   ?fF    S ?f leZ & ?fg      ?f NIO?  ?fxR r!  ?f P _hy ?fy6IJ O ?f _5  % ?f [X ~  ?f 1  >  ?f  b U  ?f
+   ?f P   X ?f5:p  0 ?f 8d    ?f ; U   ?fJ      ?f       ?f   ) m ?f   Z]G ?f  / |! ?f       ?fi T    ?f  ?Wq  ?fP< p   ?f 9   h ?f  ^  C ?f8 1H   ?f Y2    ?f BA    ?f  p    ?f ]  v  ?f6<  }n ?f.?   K ?f*   1) ?f       ?f  { w  ?f
?f z/ )B ?f  ~q   ?fT   n  ?f  Nj#z ?f  _ 88 ?f	:vG   ?f V 2   ?f3 &d t ?f    64 ?fm[     ?fH  sU  ?f
t ?f , o 5 ?f ja|   ?f mq    ?f   x z ?f 1 b < ?fR   N  ?f Z_:)  ?f   JS  ?fM    H ?f> F9   ?f   ^   ?f       ?f     Y ?f  3    ?f       ?f   ?i  ?f Z  8o ?f   O5 ?f       ?f    P  ?f R  9  ?f   igP ?fLa ;   ?f L     ?f!      ?f  %  o ?f  {7=8 ?f   t
?fD vC   ?f    6  ?f
=p \ ?f ;S o& ?f m  j  ?f   W   ?f j     ?f $   O ?f z5    ?f       ?f C |P  ?fy  h | ?f   % H ?f/ ZM   ?ff !w;  ?f ? >   ?f  MA z ?f     G ?f   y   ?f    .  ?fP  9   ?f TT  } ?fg 4  K ?f#$ O   ?f 	 Y   ?f B  M  ?f6C  ;  ?f  B"_U ?f~t   $ ?f       ?f52     ?f   l ' ?fD   T  ?f <(  i ?f qE 8
?f
U   ?fOQ   M ?f o^    ?fS q    ?fG    5 ?f   zx  ?f 1 zd} ?f:  R ! ?f  W g  ?f~&  ~k ?f=~-2   ?fZ      ?f'|j_ ] ?fi t    ?f[      ?f8    R ?fuq b   ?f# h    ?f  z |J ?f G ~`  ?f\ !>   ?f    GF ?f   vJ  ?fl      ?f5h  mE ?f       ?f-  l   ?f u   G ?f 1i %  ?f       ?f     M ?fe*|    ?f  z    ?f ^   V ?f4< %F  ?fB}u    ?fc-  @c ?f n     ?f 	R=   ?f   K r ?f*} T # ?f,"k >  ?f  R)   ?fK   {o ?f  va   ?f     8 ?f
t;I_  ?f   h   ?f3  x k ?f3      ?f b 3 < ?f [     ?f   u0  ?fR(   { ?f  >    ?fv  Z9S ?fLJisk  ?f M $a. ?f ftW   ?f +     ?f " @ | ?f  &#   ?fp>   _ ?f 1  f  ?f  D E ?f}      ?f     / ?f%  ,   ?f  0    ?f5nl+,& ?f Q G   ?fb   .	 ?f,*( >  ?fp_8    ?fcU)    ?f  h*   ?f ' w   ?fd      ?f   <   ?f]'  ]  ?f       ?f  = |  ?f j     ?f   .   ?f       ?fu      ?f 	   0 ?f  "N R ?f
y ?f       ?fd      ?f ^  8 ?f 0`4 I ?fI rO*  ?f  O'   ?fx   A ?f   B   ?f / )   ?f7h  ` |?f]     v?f      p?fg  C _e?f      T?afi_double
uint32
T L  l    l
l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    aki_float
float32
T L  fy  x;I >f      [>f [,< Pb>fa;D8 |e>f  /   h>f  L. #j>f a8/M
l>ftrtZ/ m>f  L-H2o>f   '2Mp>fC] ;  p>fw6A   q>f  z  'r>f  c8. r>f  W ?<s>f/     s>fU    9t>f  =6  t>ft  bu%u>f      u>f ~  1 v>f=| a kv>fp
v>f  F  6w>fw*    w>fC F E w>fw
CS Ux>f v{ d x>f  N . y>f  , Gcy>fF 8   y>f,     z>fY wmgbz>f0  n  z>f l m  {>f)zB  U{>f: R 6 {>f2  *  {>f NY p>|>fa;2   |>f &r   |>fH     }>f   ) g}>f  #
}>fSv  : }>f     =~>f
oz3  ~>f    : ~>f&b    >f   T Q >f    m  >f . }S  >f 4B V >f  9 @. >f     N >f  r[Vo >f  q    >f a  }  >f  Kf=  >fk  K   >f   2   >f  1 G- >fA   >L >f     k >f4 x    >f m Q   >f *  f  >f.      >f  @    >f   re  >f   } > >f k   [ >f   f*y >f       >f . b   >fS  b   >f       >f Hn
>f0    ' >f ^&pDD >f R   ` >fjX  j} >fd  o   >f =  ;  >f  V    >f Zr    >ft  q
>f]t - & >f 0<
C >f]  s ^ >f6 f  z >f/ H2   >f]A     >f    I  >f  8
>fbU^    >fZ
M! >fOfj  < >f   NwX >fx_U
t >f       >fY $#   >f=s} r  >f  /{   >f8^  O  >f   `   >f     4 >f &   O >fr  W j >f71  B  >f  P)   >f C     >fR (ab  >fT a1   >f h  '  >f  iQ * >f  p  E >f s 5ea >fI    | >f    M  >f	  <   >f "  L  >f  s    >f    g  >fv
" >f     = >f    NY >f ~zo u >f- G_   >fC      >f    e  >f'jDQI  >f  s):
>fG ( 8  >f
F8 >f   ybT >f  p  p >f1*.    >f  ?    >f,   y  >f to+   >fJ  &r  >f 6 9   >f[  ! 7 >f     T >f  JrZq >f=1 dL  >f   >V  >f  Z x  >f6      >f   O   >f[   |  >f
> >f = A [ >f' ? }y >f<   d  >fn%  k  >f  .k   >f       >f   lH  >f-z   . >f n  M >f    fl >f    f  >f  6    >f  ;    >f7 h0^  >fn  2 	 >f  7  ( >fG 3  H >f#    i >f    s  >fpn  	  >f I     >f7.R    >f  I   >f F  t. >f     P >f%  /
r >f
*K!  >f o     >f:  v#  >f   a   >f!S  2  >fmM   B >fh   _f >f    f  >f "q    >f  / `  >f    Y  >fu  G   >fG    ! >f     4 >f  >N G >f~   ;[ >fh& # n >f .c    >fT      >f  qu   >fH   =  >f0= 4   >f e     >f       >fAp  n  >f5]  !) >fm	 i ? >f;.`HdU >f   ; k >fa  t   >f  NV   >f / w   >f  q    >f9      >f       >f       >f  ozG- >f$   EG >f Xv  a >f.Y   | >fx w .  >fR
*S7  >f   1   >f x    >f  V    >f  h^{* >f     I >f@ 3z i >f
AV    >f   pu  >f    '  >fu `    >f       >f ^T  = >f : D d >f C ub  >f'Zk s  >f   %  >fA  S   >fB~:R @ >f  J  q >f  q    >f  :$   >fL   i  >f j
{ S >f    @  >f2 	 k  >f4z_ (' >fs 	V y >f    -  >f4 )  9 >f |     >f Do  . >f W@    >fZw x   >f  x8   >f3 	  ; >awi_float
fi_float
T L  g          l
g          g        qg          g          g        |g          g          g          g          g          g          g        Kg          g          g        =g          g          g          g          g          g          g        bg          g        }g          g          g          g          g          g        Ng          g         g          g          g          g          g          g          g          g          g          g          g          g          g        Mg          g          g          g         g          g          g          g          g        dg          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g         g          g        Gg          g          g          g          g          g          g          g          g          g          g         g          g        Fg          g          g          g          g          g        -g          g          g          g          g          g          g          g          g        Rg          g        4g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g        ig          g          g          g          g          g        >g        pg          g          g          g          g          g          g          g          g          g          g          g          g          g        Ig          g          g         g          g        tg          g          g        Zg          g          g          g          g          g          g          g          g        ,g          g        8g          g          g          g          g          g          g         g          g          g          g          g          g        dg          g          g          g          g        6g          g          g          g        Lg          g          g          g          g        ;g         g        Jg          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g          g        xg          g         g          g          g          g          g          g        #g          g          g          g          g          g          ake_double
T L  f ]   d <f A]  X`<f+M[I  j<f  [ 5 q<fs*J  "u<f z   Px<f  y  8{<f  m   }<f<\ I ; <fp  $ p <f3&     <f n=    <f!      <f J     <f +  @  <f       <fo` TY  <f 7"U   <f R]    <f     } <f ?  {_ <f6| M = <fZs xf  <f O_    <f	2h]   <fXuj vK <f   GH  <f  I    <f  K    <f I> &  <f. 8e G <f h#    <fK &    <f  m  m <f b! S  <fHgp (. <f  5_\  <f   k   <fMox) J <f   =   <f .     <f h m-a <fD  bS  <f  yy   <fsy #nt <fr ~|o  <f   S * <f  +/w  <f*  P   <fD   S8 <f8  B   <f   u,  <fJ   BD <fa  S%  <f $ D   <f  Ly_N <f  ?    <f  Y    <f  p  W <f Z +   <f       <f k   ^ <fW Bju  <f 1|    <fD    e <fb   A  <f       <f  W+Fl <f   e   <f <    <fb  ]9 <f vr  e <fr
K    <f7 q    <ff/z |  <f   9R  <f }po0@ <f  w  l <f #= 	  <f R=    <f       <f    '  <f)   MH <f   ; t <f   t   <f]; d!  <f!      <f v |
& <f     R <f    F  <f   L   <fm3     <f 	O    <f lF  2 <f lq  _ <f    <  <f  k    <f E     <f
<f  , gC <f'o1 Aq <f  Nk=  <f5   [  <f& V    <f. s  * <f  \  X <f    E  <f < ~   <f  Y $  <f  P S  <f   a C <f0 w 1s <f
$ v   <f  }k   <fwr     <f*    3 <f  aY c <fT   .  <f ` H   <f       <f s  \' <f  5  X <f  @9   <f]   }  <fQ      <f-Y   ! <f  V5 S <f   2   <fze     <f    (  <f  n    <fB%   T <f O2{   <f &  x  <f  - @  <f- BNS' <f     \ <f ## _  <fl   \  <f q     <f  0AM5 <f    Cl <f
S   <f 5 J7  <f P& 7  <fR  | K <f #  O  <fxvJ k  <fh [    <f   n 0 <f ^Q  k <f       <f
<f   z7  <f 9  4, <f $  kJ <f &   h <f  :    <f  3 s  <fo
<f   P   <f   f   <fJ  j $ <f+:o  D <f    Ee <f  o    <f x    <fZ*x a  <fp3     <f       <fP OR3. <f ;@  P <f   a s <f+SB    <fQ E    <fp-  |  <feY&Y   <f  *  ' <fe ;  L <fV    r <fCQ4    <f   zD  <f       <f    /  <f B   3 <f,    [ <f2      <fL ]    <f'  {0  <f    O  <f   q + <fZ   1W <faD L   <f  8 a  <f    d  <fy
<f .{$U8 <f2  `Og <f H J   <f { /e  <f %     <f  \ }* <f q  <] <f qk    <f v }G  <f  n    <f   , 0 <fBsh 9h <f [i    <f 6;    <fDu  Z  <f * 4 O <f       <f  $:   <fx I>V
<f;L C%K <f    h  <f E  3  <f
<f   P ] <f^ v    <fw K T  <f   A > <f   B   <f       <f 8'k 1 <f ; o   <f  N P  <f`	 n ; <f   *   <fJ Pg   <f    nb <f   C   <f. b    <f     V <fN      <f H]x1  <f  C    <f*DugxV <f       <f|      <f  Y += <f  I    <f  D    <f^  ' T <fa   N  <fb  f 7 <f QG    <f s < J <f  s z  <fr Kmg  <f/   P  <f       <f {H   <f q Q   <f  ~)   <awe_double
T L  f
?f7   E  ?f   P   ?f'{ {
?f*    ! ?f  b  v ?f mU    ?f9 U 1T ?f/  v   ?f   x ] ?f&1$-   ?f~ 	 n  ?fcK [ ! ?f   I   ?f \Om g ?ff      ?fu Li=  ?fs    l ?f  x    ?f  Q f  ?fi   j  ?f%    C ?f   +   ?f   D   ?f     z ?f c E#; ?f^ E #  ?f$O     ?f 2  m  ?f P " K ?f >     ?f {  s  ?f%;     ?f o m o ?f  3  ; ?f   J9  ?f+ +    ?f* T [  ?f}; 1 s ?fHe   C ?f$ `    ?fvE! =  ?f    -r ?fMB     ?f   K=  ?fQ }6Ei ?f 7 u   ?f !     ?fz  } k ?f  ~    ?f  @    ?f`    x ?f     * ?f    8  ?f   Qi  ?fo T  C ?f_ (4   ?f       ?f@  j e ?f !u v  ?f 7Zi   ?f {	    ?f     I ?f ]T    ?f9]     ?f ?   } ?f8aD  : ?fY  i   ?f       ?f r^sSw ?f   0 7 ?f  d>[  ?f   %   ?f    { ?f 'HB > ?fvX  #  ?fl 1&   ?f  :l   ?f   ! O ?f       ?f  &    ?f       ?f   +	j ?f A   1 ?fN 0 Z  ?f   0H  ?f } G   ?f   ( V ?f5$1  ! ?fpB9    ?fb" FS  ?f)vEW(  ?f vG}rO ?f ~  /  ?f 	{ ^  ?fZ      ?f       ?f     S ?f    i" ?fl  R   ?f3S  n  ?f > N   ?f  ]  b ?f,|y  2 ?fjG  >  ?fT  L   ?f~> \ O ?f       ?f @Y
H  ?f  /  @ ?f9O"H   ?f    >  ?f 1   7 ?f   8   ?f   Ox  ?f   ] 4 ?f5D9g   ?f  r|   ?f>   $8 ?f [ B/  ?fI< K   ?f \  *A ?f       ?f# >    ?f     O ?fy %d
?f bP    ?f     c ?f   PR  ?f    j  ?f F   } ?f9(  Q1 ?f   c   ?f(  ^w  ?f  0U^Q ?f1j     ?f  T	   ?f x.BTv ?fI  mb. ?f  <X   ?f 0     ?f  -  Y ?f j8    ?f    w  ?f   &   ?f    BE ?fn}  g  ?f4
?f@ `r*{ ?fx  { 8 ?fe =    ?ff 1 o  ?fx   yt ?f/q   3 ?f       ?f/ T{i  ?f    Pu ?f  nz 6 ?f       ?f   f u ?f<      ?f    F  ?f  a z  ?f       ?f M     ?fW  k[  ?f  .  . ?f &qW   ?fHe5T F ?feTe C  ?f 8 =]a ?f( F M  ?fpk3G   ?f t     ?f;SZ    ?f  ;,`4 ?f    s  ?f <  W[ ?f   H   ?f  0    ?f   \   ?f>      ?f6 Y  J ?f)      ?f\ C  } ?f  % d  ?f    w  ?f    SN ?f   v   ?fp   a  ?f  ,Q & ?f@ o    ?f Su Fe ?fP V    ?f;      ?f     I ?fv i    ?f4 D    ?f  .  g ?f X1I   ?fJy     ?f ! d J ?f    z  ?f  j    ?f8  G ; ?fL|{    ?fmw n   ?fk9:  9 ?f       ?fR  y   ?fA &  E ?f    U  ?f    <
?f k&  _ ?f   G   ?f  ?~ # ?f  V #  ?f   _   ?f     S ?fQ | z  ?f  Y & ?f     $ ?fhtQz   ?f  3T   ?fpX P   ?f N     ?fH*  g  ?fg  S(u ?f    1c ?fw@ r T ?fQ   =I ?f    QA ?f ]1% < ?f2:   ; ?f__rTE> ?f   	RD ?f       ?fW'n    ?f- BU   ?f   h   ?f t   4 ?f     n ?fboQ    ?fqv  i  ?f  _) N ?f ]t QW}?f6H   #z?f 6 7  w?f "    s?fC@Wi= q?f K   Xl?f      f?f$   k a?f%> T +Y?f
O?fK  2  =?afe_double
T L  l    l
l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    l    ake_float
T L  f  h  d >f>62  X@>f  1I  J>f    5 Q>f     "U>f 3&  PX>f     8[>f
0    ]>f,a I ;`>f P $ pa>f 4"   b>f      c>f l>   d>fK ^   e>fi0  @ f>f CN   g>f I UY h>f V T  i>f      j>f  u  }k>f*U  {_l>f   M =m>f>- xf n>f r{   n>f   \  o>f    vKp>f  {GH p>f {    q>fo &   q>f9"N & q>f O e Gr>f      r>f      s>f  O  ms>ff3  S s>f    (.t>f Hm_\ t>f   l  t>f-  ) Ju>f T =  u>f      v>f   l-av>f   bS v>f   y  w>f   #ntw>f   |o w>f - S *x>f y /w x>fJb P  x>f j  S8y>f D B  y>ftr7v, y>f3
: BDz>f 4 S% z>f z B  z>fpe {_N{>f      {>f=f2   {>f     W|>f   ,  |>f      }>f@    ^}>f ` lu }>f  D   ~>f     e~>fSU  A ~>f |0    >fr l,Fl >f]O f   >f _    >f
]9 >fP    e >f1)     >f  `    >fA1  |  >f   8R  >f 0 o0@ >f
l >f    	  >fy      >f m\    >fq ' '  >f'n0 MH >fl  < t >f   s   >f   c!  >f qx    >f }_|
& >f{    R >f =  F  >f_  K   >f       >f  o    >f <c  2 >f l   _ >f    <  >f G     >f       >f G     >fu	  gC >f T  Aq >f : k=  >fb,	 [  >f  ^    >f     * >fS O  X >f {  E  >f ; }   >f f  $  >f G< S  >f   a C >f    1s >f\  w   >fA  k   >f }F    >f \_  3 >f   X c >f ]  .  >f  \I   >f       >f *  \' >f 2U  X >f  *8   >f18  }  >fG      >fT    ! >fTE 5 S >f  43   >f       >f    (  >f       >f     T >fZV z   >fm   x  >f
C  @  >f + NS' >f )   \ >f*   _  >f^ 5 \  >f
>f_p @M5 >fr e Cl >f M R   >fK hJ7  >f D  7  >f K3| K >fL   O  >fY   k  >f  9    >f   n 0 >f{    k >f       >f/
>fx  z7  >f k  4, >f    kJ >f__   h >f>2     >f +  s  >f RW    >f   P   >f 1 f   >f   j $ >f 5   D >f  , Ee >f3 g    >f  *   >f w  a  >f BZ    >f
h    >f  ?R3. >fQSj  P >fLw b s >f 6     >f  K    >f T% |  >f ] X   >f z   ' >f     L >f!we  r >f  v    >fh5 {D  >f  G    >f&   /  >f6Fy  3 >f< S  [ >fsp     >f@d     >f9  z0  >f 0  O  >fb  q + >f    1W >f   K   >f    a  >f    d  >f M
>fs[ #U8 >f l `Og >f  `J   >fj  /e  >f       >fXg  }* >fSd  <] >f  '    >f   |G  >f $     >f%  , 0 >f i  9h >f       >fF~     >f    Z  >f%  5 O >f       >f   9   >f  *>V
>f  0D%K >f    h  >f4 X 3  >fm v    >f   P ] >f f    >f h  T  >f a A > >f%lGB   >fq      >f  Mk 1 >fG!lp   >fQv  P  >f   n ; >f)  *   >f   g   >f    nb >f atC   >f       >f>X   V >f9      >fb  x1  >f       >f d gxV >f       >f5      >fa   += >f  K    >f       >f b ' T >fl   N  >f 7 f 7 >f  ~    >f   < J >f  : z  >f/  mg  >f #  P  >fO      >fz	u   >f   R   >f qa)   >awe_float
T L  f
?f    E  ?f 4 P   ?f   {
?f ,   ! ?f 	   v ?fB      ?f qY 1T ?f N v   ?f g x ] ?f:&-   ?f!   n  ?fM' [ ! ?f  I   ?f- Cm g ?f       ?f H(i=  ?f _   l ?f  m    ?fB   f  ?fR'T j  ?f j   C ?f E +   ?frx D   ?ff    z ?f 0 D#; ?f 8p #  ?f       ?fc G m  ?f a " K ?f H     ?f dc s  ?fd]]    ?f t m o ?f  2  ; ?f   I9  ?f ^-    ?f 4" [  ?fr  2 s ?f     C ?f9 v    ?f    =  ?ff]/ -r ?fJH     ?fj  K=  ?f  s6Ei ?f * u   ?f Jb    ?f K ~ k ?f       ?f #     ?f     x ?f  9  * ?f  s 8  ?f  IQi  ?fI/-  C ?f  )4   ?f       ?f   j e ?f WK v  ?f C i   ?f>      ?f:T   I ?f  X    ?f <     ?f  3  } ?f     : ?f b j   ?fq N    ?fv  sSw ?f  O0 7 ?f  r>[  ?f  	&   ?fx M  { ?f ( B > ?fA @ #  ?f2  &   ?f  2l   ?f   ! O ?f       ?f      ?f       ?f ] +	j ?f     1 ?f  n Z  ?fp  0H  ?fmBnG   ?f  U) V ?f  ,  ! ?fq      ?f5  FS  ?f'  V(  ?f   }rO ?fjF  /  ?f^ 9 ^  ?f r     ?fT x    ?f     S ?f M  i" ?f   S   ?fV   n  ?f};.O   ?f 4U  b ?fY0u  2 ?f
- >  ?fG  M   ?fT M\ O ?f      ?f    G  ?f:>4  @ ?f  1G   ?f    >  ?f H   7 ?f   8   ?fQ$ Ox  ?f   ^ 4 ?fx  f   ?f
tI|   ?fv   $8 ?f   B/  ?f  WL   ?f  = *A ?f @     ?f u     ?fG    O ?f   d
?f ']    ?f DE  c ?f)  OR  ?fv   j  ?fr i  } ?f    Q1 ?f>  d   ?f   _w  ?f   T^Q ?f       ?f q     ?f4
CTv ?fzMLmb. ?f   X   ?fz~     ?fj >  Y ?f [m
?f K% w  ?f   &   ?fUz  BE ?f F  g  ?f  G
?f I r*{ ?fk' z 8 ?fq      ?f  | o  ?f    yt ?f &m! 3 ?f M"    ?f}>Szi  ?f0   Pu ?f  }y 6 ?f%      ?f F4h u ?f UB    ?fq   F  ?fb y z  ?f  |    ?fb:     ?f<  l[  ?f# p  . ?f ; U   ?f k S F ?f @  C  ?f   =]a ?f  r M  ?fZ SG   ?f       ?f(      ?fg V,`4 ?f    s  ?f    W[ ?f  yH   ?f  T    ?f   \   ?fm$n    ?f 8O  J ?f       ?f]    } ?f  # d  ?f    w  ?f t  SN ?f   v   ?f    a  ?f  UQ & ?f 	q    ?f 4] Fe ?f  f    ?f       ?fR    I ?fO V    ?fr      ?f 4   g ?f   H   ?f<9B    ?fP`:d J ?f`   z  ?f  y    ?f  ~G ; ?f       ?fp  n   ?f <   9 ?f l     ?f =ny   ?f
k  E ?fk   U  ?fe   <
?f     _ ?f V G   ?f5 z~ # ?f {~ #  ?f   _   ?f     S ?f "i z  ?fy IY & ?f7    $ ?f+  y   ?f   T   ?fM NQ   ?f       ?fEb  g  ?f   S(u ?fr k 1c ?f i r T ?f  # =I ?f    QA ?fB l$ < ?f =   ; ?f   SE> ?f(5n RD ?f  "    ?fA*R    ?f1 /T   ?f   g   ?f     4 ?f|    n ?f l;    ?f S  i  ?f4Iq) N ?fBk4 QW}?f q   #z?f _ 8  w?fy     s?f. Hi= q?f f   Xl?f >$   f?f6 ^ k a?f   S +Y?f  _
O?f   2  =?afe_float
f3 	  ;@aziggurat_nor_r
f   l   ?aziggurat_nor_inv_r
f  ~)   @aziggurat_exp_r
T f3 	  ;@aziggurat_nor_r_f
T f   l   ?aziggurat_nor_inv_r_f
T f  ~)   @aziggurat_exp_r_f
f -DT !	@aM_PI
g            aINT64_MAX
l  aUINT8_MAX
l   aUINT16_MAX
g       aUINT32_MAX
g            aUINT64_MAX
l l asizeof
c_long
aLONG_MAX
f  d  g ?aLS2PI
fUUUUUU ?aTWELFTH
unumba\np\random\_constants.py
u<module numba.np.random._constants>

.numba.np.random
Y
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numba
u\not_existing
unp\random
T aNUITKA_PACKAGE_numba_np
u\not_existing
random
T aNUITKA_PACKAGE_numba_np_random
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
unumba\np\random\__init__.py
u<module numba.np.random>

.numba.np.random.distributions
np
log1p
float32
sqrt
f
@arandom_standard_exponential
expm1
next_uint64
bitgen
l  l l g         awi_double
ki_double
l
ziggurat_nor_inv_r
next_double
ziggurat_nor_r
fi_double
exp
f
next_uint32
l	l    awi_float
ki_float
ziggurat_nor_inv_r_f
np_log1pf
next_float
ziggurat_nor_r_f
fi_float
T f
?l awe_double
ke_double
ziggurat_exp_r
np_log1p
fe_double
we_float
ke_float
ziggurat_exp_r_f
fe_float
log
T f
?f
?Z
shape
pow
fUUUUUU ?arandom_standard_normal
wcfm   {  ?wbf
?arandom_standard_exponential_f
T Z
f32_one
T f
@T f
"@arandom_standard_normal_f
T fm   {  ?arandom_standard_gamma
random_standard_gamma_f
waamin
random_chisquare
np_expm1
wUarandom_normal
l l asum
prod
wqwXaceil
random_geometric_search
random_geometric_inversion
floor
f
am1
aINT64_MAX
aUmin
L
fUUUUUU ?f l  l f f      J?f 8  8 C f$  +  K?f <   j_ f  A  Az?f S   B  f   8   ?f5   gG  f
@l ;l
l	l agl0
x2
f  d  g ?agl
x0
f n     ?f=
p= @fh  |?5  f[   	m ?f$   ~  ?fr      ?f333333 @fr      ?fB>     @afabs
lam
f  Q    ?f Q     ?f9  v   ?ainvalpha
loglam
random_loggam
l
random_poisson_ptrs
random_poisson_mult
random_gamma
random_poisson
isnan
nan
random_noncentral_chisquare
wraint64
f   (\  @fffffff @f   x & ?f
4@f      .@acase
wnap4
p1
l axm
l<wuap2
l axl
wvwml2ap3
l(alaml
xr
lamr
wyanrq
l4wFwswkf
@f
?fUUUUUU ?f
@f
|@f
`@f
X@f
a@f
M Af
1 @f
$@apx
qn
wpf
>@arandom_binomial_inversion
random_binomial_btpe
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumba.core.extending
T aregister_jitable
register_jitable
unumba.np.random._constants
T awi_double
ki_double
ziggurat_nor_r
fi_double
wi_float
ki_float
ziggurat_nor_inv_r_f
ziggurat_nor_r_f
fi_float
we_double
ke_double
ziggurat_exp_r
fe_double
we_float
ke_float
ziggurat_exp_r_f
fe_float
aINT64_MAX
ziggurat_nor_inv_r
unumba.np.random.generator_core
T anext_double
next_float
next_uint32
next_uint64
numba
T afloat32
int64
unumba.np.numpy_support
T anumpy_version
numpy_version
random_rayleigh
random_standard_exponential_inv
random_standard_exponential_inv_f
random_normal_f
random_exponential
random_uniform
random_gamma_f
random_beta
random_f
random_standard_cauchy
random_pareto
random_weibull
random_power
random_laplace
random_logistic
random_lognormal
random_standard_t
random_wald
random_geometric
T l l arandom_zipf
random_triangular
random_negative_binomial
random_noncentral_f
random_logseries
random_binomial
unumba\np\random\distributions.py
u<module numba.np.random.distributions>
T wxTabitgen
wawbwUwVwXwYaXpY
logX
logY
logM
aGa
aGb
T abitgen
wnwpwqT'abitgen
wnwpwrwqafm
wmap1
xm
xl
xr
wcwaalaml
lamr
p2
p3
p4
case
wywkanrq
wuwvwxwswFwiarho
wtwAax1
f1
wzwwax2
f2
z2
w2
T
bitgen
wnwpwqaqn
a_np
bound
wXapx
wUT abitgen
df
T abitgen
scale
T abitgen
dfnum
dfden
T abitgen
shape
scale
T abitgen
wpT abitgen
wpwXasum
prod
wqwUT abitgen
loc
scale
wUT	wxwawnax0
x2
lg2pi
gl0
wkagl
T abitgen
mean
sigma
T abitgen
wpwrwVwUwqaresult
T abitgen
wnwpwYT abitgen
df
nonc
aChi2
wnwiT abitgen
dfnum
dfden
nonc
wtT abitgen
loc
scale
scaled_normal
T abitgen
waT abitgen
lam
T abitgen
lam
enlam
wXaprod
wUT abitgen
lam
slam
loglam
wbwaainvalpha
vr
wUwVaus
wkT abitgen
mode
T abitgen
T abitgen
ri
idx
wxT abitgen
shape
wUwVwXwYwbwcT	abitgen
shape
f32_one
wUwVwXwYwbwcT abitgen
wraidx
sign
rabs
wxaxx
yy
T abitgen
df
num
denom
T
bitgen
left
mode
right
base
leftbase
ratio
leftprod
rightprod
wUT abitgen
lower
range
scaled_uniform
T abitgen
mean
scale
mu_2l
wYwXwUT abitgen
waaam1
wbwUwVwXwTT
bitgen
waaam1
wbaUmin
aU01
wUwVwXwTu
.numba.np.random.generator_core
l
parent
types
pyobject
state_address
uintp
state
fnptr_next_uint64
fnptr_next_uint32
fnptr_next_double
bit_generator
aNumPyRngBitGeneratorModel
a__init__
a_bit_gen_type
meminfo
aMemInfoPointer
voidptr
aNumPyRandomGeneratorTypeModel
intrinsic
intrin_NumPyRandomBitGeneratorType_next_ty
u_generate_next_binding.<locals>.intrin_NumPyRandomBitGeneratorType_next_ty
overload
ol_next_ty
u_generate_next_binding.<locals>.ol_next_ty
return_type
codegen
u_generate_next_binding.<locals>.intrin_NumPyRandomBitGeneratorType_next_ty.<locals>.codegen
overloadable_function
a__name__
cgutils
create_struct_proxy
inst
l
T avalue
fnptr_

get_value_type
inttoptr
ir
aFunctionType
get_or_insert_function
module
bitcast
type
call
aNumPyRandomBitGeneratorType
impl
u_generate_next_binding.<locals>.ol_next_ty.<locals>.impl
ctypes
next_double
next_uint32
next_uint64
float32
l T f
?T f
pAanp_float32
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
llvmlite
T air
unumba.core
T acgutils
types
config
config
unumba.core.extending
T aintrinsic
make_attribute_wrapper
models
overload
register_jitable
register_model
make_attribute_wrapper
models
register_jitable
register_model
aStructModel
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
