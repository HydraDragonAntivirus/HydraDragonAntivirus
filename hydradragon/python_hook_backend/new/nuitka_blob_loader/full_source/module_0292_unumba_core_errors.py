# Reconstructed from integrated Nuitka blob
# Module: unumba.core.errors

a__qualname__
T ntuNumbaWarning.__init__
a__orig_bases__
aNumbaPerformanceWarning
aNumbaDeprecationWarning
aPendingDeprecationWarning
aNumbaPendingDeprecationWarning
aNumbaParallelSafetyWarning
aNumbaTypeSafetyWarning
aNumbaExperimentalFeatureWarning
aNumbaInvalidConfigWarning
aNumbaPedanticWarning
uNumbaPedanticWarning.__init__
aNumbaIRAssumptionWarning
aNumbaDebugInfoWarning
aNumbaSystemWarning
metaclass
aABCMeta
T a_ColorScheme
T
a_ColorScheme
u_ColorScheme.code
u_ColorScheme.errmsg
u_ColorScheme.filename
u_ColorScheme.indicate
u_ColorScheme.highlight
u_ColorScheme.reset
T nu_DummyColorScheme.__init__
u_DummyColorScheme.code
u_DummyColorScheme.errmsg
u_DummyColorScheme.filename
u_DummyColorScheme.indicate
u_DummyColorScheme.highlight
u_DummyColorScheme.reset
colorama
a__version__
u0.0.0
colorama_version
split
T w.T l
l l	uInsufficiently recent colorama version found. Numba requires colorama >= 0.3.9
environ
T aNUMBA_DISABLE_ERROR_MESSAGE_HIGHLIGHTING
nuNOPColorScheme.__init__
uNOPColorScheme.code
uNOPColorScheme.errmsg
uNOPColorScheme.filename
uNOPColorScheme.indicate
uNOPColorScheme.highlight
uNOPColorScheme.reset
T ainit
reinit
deinit
aFore
aStyle
aFore
T Oobject
uColorShell.__init__
uColorShell.__enter__
uColorShell.__exit__
ureset_terminal.__init__
ureset_terminal.__enter__
ureset_terminal.__exit__
D acode
errmsg
filename
indicate
highlight
reset
nnnnnnano_color
aBLUE
aYELLOW
aWHITE
aGREEN
aRED
dark_bg
aBLACK
aMAGENTA
light_bg
aCYAN
blue_bg
jupyter_nb
default_theme
uHighlightColorScheme.__init__
aBRIGHT
uHighlightColorScheme._markup
uHighlightColorScheme.code
uHighlightColorScheme.errmsg
uHighlightColorScheme.filename
uHighlightColorScheme.indicate
uHighlightColorScheme.highlight
uHighlightColorScheme.reset

This warning came from an internal pedantic check. Please report the warning
message and traceback, along with a minimal reproducer at:
https://github.com/numba/numba/issues/new?template=bug_report.md

Please report the error message and traceback, along with a minimal reproducer
t: https://github.com/numba/numba/issues/new?template=bug_report.md
If more help is needed please feel free to speak to the Numba core developers
directly at: https://gitter.im/numba/numba
Thanks in advance for your help in improving Numba!
feedback_details

Unsupported functionality was found in the code Numba was trying to compile.
If this functionality is important to you please file a feature request at:
https://github.com/numba/numba/issues/new?template=feature_request.md
unsupported_error_info

Unsupported Python functionality was found in the code Numba was trying to
compile. This error could be due to invalid code, does the code work
without Numba? (To temporarily disable Numba JIT, set the `NUMBA_DISABLE_JIT`
environment variable to non-zero, and then rerun the code).
If the code is valid and the unsupported functionality is important to you
please file a feature request at:
https://github.com/numba/numba/issues/new?template=feature_request.md
To see Python/NumPy features supported by the latest release of Numba visit:
https://numba.readthedocs.io/en/stable/reference/pysupported.html
nd
https://numba.readthedocs.io/en/stable/reference/numpysupported.html
interpreter_error_info

Numba could not make a constant out of something that it decided should be
a constant. This could well be a current limitation in Numba's internals,
however please first check that your code is valid for compilation,
particularly with respect to string interpolation (not supported!) and
the requirement of compile time constants as arguments to exceptions:
https://numba.readthedocs.io/en/stable/reference/pysupported.html?highlight=exceptions#constructs
If the code is valid and the unsupported functionality is important to you
please file a feature request at:
https://github.com/numba/numba/issues/new?template=feature_request.md
If you think your code should work with Numba. %s
constant_inference_info

This is not usually a problem with Numba itself but instead often caused by
the use of unsupported features or an issue in resolving types.
To see Python/NumPy features supported by the latest release of Numba visit:
https://numba.readthedocs.io/en/stable/reference/pysupported.html
nd
https://numba.readthedocs.io/en/stable/reference/numpysupported.html
For more information about typing errors and how to debug them visit:
https://numba.readthedocs.io/en/stable/user/troubleshoot.html#my-code-doesn-t-compile
If you think your code should work with Numba, please report the error message
nd traceback, along with a minimal reproducer at:
https://github.com/numba/numba/issues/new?template=bug_report.md
typing_error_info

-------------------------------------------------------------------------------
This should not have happened, a problem has occurred in Numba's internals.
You are currently using Numba version %s.
%s
reportable_issue_info
error_extras
unsupported_error
typing
reportable
interpreter
constant_inference
deprecated
aWarningsFixer
uWarningsFixer.__init__
contextmanager
T nnuWarningsFixer.flush
uWarningsFixer.__enter__
uWarningsFixer.__exit__
T EException
uNumbaError.__init__
property
uNumbaError.contexts
uNumbaError.add_context
patch_message
uNumbaError.patch_message
aUnsupportedError
aUnsupportedBytecodeError
uUnsupportedBytecodeError.__init__
aUnsupportedRewriteError
aIRError
aRedefinedError
uNotDefinedError.__init__
aVerificationError
aDeprecationError
uLoweringError.__init__
aUnsupportedParforsError
aForbiddenConstruct
aTypingError
uUntypedAttributeError.__init__
uByteCodeSupportError.__init__
aCompilerError
uConstantInferenceError.__init__
uInternalError.__init__
aInternalTargetMismatchError
uInternalTargetMismatchError.__init__
aNonexistentTargetError
aRequireLiteralValue
uForceLiteralArg.__init__
bind_fold_arguments
uForceLiteralArg.bind_fold_arguments
uForceLiteralArg.combine
a__or__
uForceLiteralArg.__or__
aLiteralTypingError
aNumbaValueError
aNumbaTypeError
aNumbaAttributeError
aNumbaAssertionError
aNumbaNotImplementedError
aNumbaKeyError
aNumbaIndexError
aNumbaRuntimeError
T w_unumba\core\errors.py
u<module numba.core.errors>
T a__class__
T aself
T aself
exc_detail
T aself
exc_type
exc_value
traceback
T aself
msg
loc
a__class__
T aself
value
loc
a__class__
T aself
arg_indices
fold_arguments
loc
a__class__
T aself
theme
T aself
exception
a__class__
T aself
kind
target_hw
hw_clazz
msg
a__class__
T aself
name
loc
msg
a__class__
T aself
msg
loc
highlighting
highlight
new_msg
a__class__
T aself
msg
kwargs
a__class__
T aself
msg
loc
highlighting
highlight
a__class__
T aself
value
attr
loc
module
msg
a__class__
T aself
category
T aself
other
T afmt
args
kwargs
T aself
msg
color
style
features
mu
T aself
msg
wfanewmsg
T aself
fold_arguments
chain_exception
weT aself
filename
lineno
wlist
wwamsg
T aself
msg
T aself
other
wmT aself
lst
T afunc
wrapper
T asubst
T aarg
subst
decorator
T aself
key
filename
lineno
category
messages
msg
T wxT aarg
T afmt_
args
kwargs
loc
weT aself
new_message
T ascheme
T aargs
kwargs
msg
subst
func
T afunc
subst
.numba.core.event
O
startswith
T unumba:
a_builtin_kinds

u is not a valid event kind, it starts with the reserved prefix 'numba:'
a_guard_kind
a_kind
a_status
a_data
l
a_exc_details
aEventStatus
aSTART
aEND
data
a__qualname__
aNone
uEvent(
u,
u, data:
w)a_registered
append
remove
kind
notify
event
is_start
on_start
is_end
on_end
unreachable
a_depth
timer
a_ts
l a_duration
buffer
time
register
listener
unregister
install_listener
aTimingListener
a__enter__
a__exit__
T nnnadone
callback
duration
install_timer
aRecordingListener
install_recorder
aEvent
T akind
status
data
broadcast
T akind
status
data
exc_details
aExitStack
push
on_exit
utrigger_event.<locals>.on_exit
start_event
T adata
trigger_event
end_event
T adata
exc_details
getpid
threading
get_native_id
utoo many values to unpack (expected 2)
l  =wBwEaname
cat
pid
tid
ts
ph
args
evs
unumba:run_pass
config
aCHROME_TRACE
atexit
a_write_chrome_trace
u_setup_chrome_trace_exit_handler.<locals>._write_chrome_trace
a_prepare_chrome_trace_data
filename
wwajson
dump
utils
a_LazyJSONEncoder
T acls
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
os
abc
enum
timeit
T adefault_timer
default_timer
contextlib
T acontextmanager
aExitStack
contextmanager
collections
T adefaultdict
defaultdict
unumba.core
T aconfig
utils
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
