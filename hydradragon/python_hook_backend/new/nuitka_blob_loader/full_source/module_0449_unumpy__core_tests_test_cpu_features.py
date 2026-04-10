# Reconstructed from integrated Nuitka blob
# Module: unumpy._core.tests.test_cpu_features

aAbstractTest
a__qualname__
uAbstractTest.load_flags
test_features
uAbstractTest.test_features
uAbstractTest.cpu_have
uAbstractTest.load_flags_cpuinfo
uAbstractTest.get_cpuinfo_item
uAbstractTest.load_flags_auxv
mark
skipif
T FuThe subprocess module is not available on WASM platforms and therefore this test class cannot be properly executed.
T areason
aTestEnvPrivation
aPath
parent
resolve
cwd
pop
T aNPY_ENABLE_CPU_FEATURES
na_enable
T aNPY_DISABLE_CPU_FEATURES
na_disable
capture_output
text
check
unavailable_feats

def main():
from numpy._core._multiarray_umath import (
__cpu_features__,
__cpu_dispatch__
)
detected = [feat for feat in __cpu_dispatch__ if __cpu_features__[feat]]
print(detected)
if __name__ == "__main__":
main()
fixture
T tT aautouse
setup_class
uTestEnvPrivation.setup_class
uTestEnvPrivation._run
T uFailed to generate error
uTestEnvPrivation._expect_error
setup_method
uTestEnvPrivation.setup_method
test_runtime_feature_selection
uTestEnvPrivation.test_runtime_feature_selection
parametrize
uenabled, disabled
T afeature
feature
T afeature
same
test_both_enable_disable_set
uTestEnvPrivation.test_both_enable_disable_set
D areason
uNPY_*_CPU_FEATURES only parsed if `__cpu_dispatch__` is non-empty
action
aENABLE
aDISABLE
test_variable_too_long
uTestEnvPrivation.test_variable_too_long
test_impossible_feature_disable
uTestEnvPrivation.test_impossible_feature_disable
test_impossible_feature_enable
uTestEnvPrivation.test_impossible_feature_enable
is_linux
is_cygwin
u^(amd64|x86|i386|i686)
aIGNORECASE
is_x86
a__prepare__
aTest_X86_Features
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
D areason
uOnly for Linux and x86
L aMMX
aSSE
aSSE2
aSSE3
aSSSE3
aSSE41
aPOPCNT
aSSE42
aAVX
aF16C
aXOP
aFMA4
aFMA3
aAVX2
aAVX512F
aAVX512CD
aAVX512ER
aAVX512PF
aAVX5124FMAPS
aAVX5124VNNIW
aAVX512VPOPCNTDQ
aAVX512VL
aAVX512BW
aAVX512DQ
aAVX512VNNI
aAVX512IFMA
aAVX512VBMI
aAVX512VBMI2
aAVX512BITALG
aAVX512FP16
dict
T L aAVX512F
aAVX512CD
aAVX512ER
aAVX512PF
L aAVX512F
aAVX512CD
aAVX512ER
aAVX512PF
aAVX5124FMAPS
aAVX5124VNNIW
aAVX512VPOPCNTDQ
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512VNNI
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512IFMA
aAVX512VBMI
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512IFMA
aAVX512VBMI
aAVX512VNNI
aAVX512VBMI2
aAVX512BITALG
aAVX512VPOPCNTDQ
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512IFMA
aAVX512VBMI
aAVX512VNNI
aAVX512VBMI2
aAVX512BITALG
aAVX512VPOPCNTDQ
aAVX512FP16
T aAVX512_KNL
aAVX512_KNM
aAVX512_SKX
aAVX512_CLX
aAVX512_CNL
aAVX512_ICL
aAVX512_SPR
D aAVX512_KNL
aAVX512_KNM
aAVX512_SKX
aAVX512_CLX
aAVX512_CNL
aAVX512_ICL
aAVX512_SPR
L aAVX512F
aAVX512CD
aAVX512ER
aAVX512PF
L aAVX512F
aAVX512CD
aAVX512ER
aAVX512PF
aAVX5124FMAPS
aAVX5124VNNIW
aAVX512VPOPCNTDQ
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512VNNI
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512IFMA
aAVX512VBMI
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512IFMA
aAVX512VBMI
aAVX512VNNI
aAVX512VBMI2
aAVX512BITALG
aAVX512VPOPCNTDQ
L aAVX512F
aAVX512CD
aAVX512BW
aAVX512DQ
aAVX512VL
aAVX512IFMA
aAVX512VBMI
aAVX512VNNI
aAVX512VBMI2
aAVX512BITALG
aAVX512VPOPCNTDQ
aAVX512FP16
T aPNI
aSSE4_1
aSSE4_2
aFMA
aAVX512_VNNI
aAVX512_BITALG
aAVX512_VBMI2
aAVX512_4FMAPS
aAVX512_4VNNIW
aAVX512_VPOPCNTDQ
aAVX512_FP16
T aSSE3
aSSE41
aSSE42
aFMA3
aAVX512VNNI
aAVX512BITALG
aAVX512VBMI2
aAVX5124FMAPS
aAVX5124VNNIW
aAVX512VPOPCNTDQ
aAVX512FP16
D aSSE3
aSSE41
aSSE42
aFMA3
aAVX512VNNI
aAVX512BITALG
aAVX512VBMI2
aAVX5124FMAPS
aAVX5124VNNIW
aAVX512VPOPCNTDQ
aAVX512FP16
aPNI
aSSE4_1
aSSE4_2
aFMA
aAVX512_VNNI
aAVX512_BITALG
aAVX512_VBMI2
aAVX512_4FMAPS
aAVX512_4VNNIW
aAVX512_VPOPCNTDQ
aAVX512_FP16
uTest_X86_Features.load_flags
a__orig_bases__
u^(powerpc|ppc)64
is_power
aTest_POWER_Features
D areason
uOnly for Linux and Power
L aVSX
aVSX2
aVSX3
aVSX4
T aARCH_2_07
aARCH_3_00
aARCH_3_1
T aVSX2
aVSX3
aVSX4
D aVSX2
aVSX3
aVSX4
aARCH_2_07
aARCH_3_00
aARCH_3_1
uTest_POWER_Features.load_flags
u^(s390x)
is_zarch
aTest_ZARCH_Features
D areason
uOnly for Linux and IBM Z
aVX
aVXE
aVXE2
uTest_ZARCH_Features.load_flags
u^(arm|aarch64)
is_arm
aTest_ARM_Features
D areason
uOnly for Linux and ARM
L aSVE
aNEON
aASIMD
aFPHP
aASIMDHP
aASIMDDP
aASIMDFHM
T L aNEON
aHALF
L aNEON
aVFPV4
T aNEON_FP16
aNEON_VFPV4
D aNEON_FP16
aNEON_VFPV4
L aNEON
aHALF
L aNEON
aVFPV4
uTest_ARM_Features.load_flags
unumpy\_core\tests\test_cpu_features.py
T a.0
wfaself
u<module numpy._core.tests.test_cpu_features>
T a__class__
T aself
msg
err_type
no_error_msg
weaassertion_message
T aself
T atxt
out
T aactual
desired
fname
a__tracebackhide__
detected
fd
cpuinfo
err
subprocess
auxv
textwrap
error_report
T aself
feature_name
map_names
T aself
magic_key
values
fd
line
flags_value
T aself
arch
is_rootfs_v8
T aself
auxv
at
hwcap_value
T aself
magic_key
T aself
tmp_path_factory
file
T aself
enabled
disabled
msg
err_type
T aself
gname
features
test_features
feature_name
cpu_have
npy_have
T aself
bad_feature
msg
err_type
T aself
bad_feature
msg
err_type
feats
T aself
out
non_baseline_features
feature
enabled_features
T aself
action
aMAX_VAR_LENGTH
msg
err_type
.numpy._core.tests.test_custom_dtypes
N
np
empty
uint8
T l T adtype
:l nnaview
float64
f
?f
@f
@:nnnaarray
waaSF
T f
?ascaled_by
T f
@T f
@adiscover_array_params
T L f
?f
@f
@utoo many values to unpack (expected 2)
assert_array_equal
dtype
T aid
Oint
value
T f
?aastype
a_get_array
T f
q l f u
< G~apytest
raises
T ETypeError
uerror raised inside the core-loop: non-finite factor!
T amatch
a__enter__
a__exit__
T fY    n  T nnnT ETypeError
result_type
int64
T f
@aadd
reduce
D ainitial
Z
T ETypeError
uthe resolved dtypes are not compatible
multiply
copy
at
l T aout
arange
T l T f
D acasting
equiv
D acasting
no
D acasting
safe
safe
T aout
casting
Z
l
T Ofloat
shape
D adtype
Oint
equiv
hypot
D akeepdims
tT L f
?f
@f
@Oobject
a_ScaledFloatTestDType
aNamedTemporaryFile
T awb
Fu.npz
T adelete
suffix
warns
aUserWarning
savez
name
load
D aallow_pickle
taarr_0
larr
flat
testing
f
@apickle
dumps
loads
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
tempfile
T aNamedTemporaryFile
numpy
unumpy.testing
T aassert_array_equal
unumpy._core._multiarray_umath
T a_discover_array_parameters
a_get_sfloat_dtype
a_discover_array_parameters
a_get_sfloat_dtype
