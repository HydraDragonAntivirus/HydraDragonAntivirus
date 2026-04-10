# Reconstructed from integrated Nuitka blob
# Module: ukeyboard._keyboard_event

a__qualname__
T nnnnna__init__
uKeyboardEvent.__init__
T Fato_json
uKeyboardEvent.to_json
a__repr__
uKeyboardEvent.__repr__
a__eq__
uKeyboardEvent.__eq__
a__orig_bases__
ukeyboard\_keyboard_event.py
T a.0
attr
self
u<module keyboard._keyboard_event>
T a__class__
T aself
other
T aself
event_type
scan_code
name
time
device
modifiers
is_keypad
T aself
T aself
ensure_ascii
attrs

.keyboard._keyboard_tests
H
aKeyboardEvent
dummy_keys
l
T aevent_type
scan_code
name
time
keyboard
a_listener
direct_callback
output_events
append
send_instant_event
make_event
aKEY_DOWN
aKEY_UP
l  T aevent_type
scan_code
name
press
T l  aunhook_all
input_events
:nnna_recording
a_pressed_events
clear
a_physically_pressed_keys
a_logically_pressed_keys
a_hotkeys
init
a_word_listeners
extend
pop
T l
u<lambda>
uTestKeyboard.do.<locals>.<lambda>
assertEqual
queue
join
w+aevent_type
wdwuw_ascan_code
u<genexpr>
uTestKeyboard.do.<locals>.<lambda>.<locals>.<genexpr>
u   '"
json
loads
to_json
all_modifiers
self
assertTrue
is_modifier
;l
l
l T l l l l aitems
utoo many values to unpack (expected 2)
T anone
duplicated
key_to_scan_codes
uTestKeyboard.test_key_to_scan_codes_brute.<locals>.<genexpr>
T waT l T wAT l q T ashift
T l l T aSHIFT
T actrl
T aCONTROL
T uleft shift
T l T uright shift
T l T w_T l T aright_shift
assertRaises
T EValueError
a__enter__
a__exit__
T nT nnnT u
l
l waT l
l l T anone
T aduplicated
T l aparse_hotkey
T T T l T T T l q T w+T aplus
T w,T acomma
T uleft shift + a
T T T l T l T uleft shift+a
T ua,b
T T T l T T l T ua, b
T ua+b, b+c
T T T l T l T T l T l T aalt
T wbT wcT ualt+shift+a, alt+b, c
l l l T T T l T l T l wbwcaassertFalse
is_pressed
do
d_a
T l T q au_a
d_b
d_shift
T ushift+a
send
T watpT ado_press
do_release
T watFT waFtT waFparelease
press_and_release
T uctrl+a
tpad_ctrl
u_ctrl
T uctrl+shift+a
Ftau_shift
fn
uTestKeyboard.test_call_later.<locals>.fn
call_later
T l l f{  G z ?atime
sleep
T f       ?atriggered
T twiacount
uTestKeyboard.test_hook_nonblocking.<locals>.count
hook
D asuppress
Faunhook
l aname
uTestKeyboard.test_hook_blocking.<locals>.count
D asuppress
taassertIn
on_press
uTestKeyboard.test_on_press_nonblocking.<locals>.<lambda>
uTestKeyboard.test_on_press_blocking.<locals>.<lambda>
wAq aon_release
uTestKeyboard.test_on_release.<locals>.<lambda>
hook_key
invalid
uTestKeyboard.test_hook_key_invalid.<locals>.<lambda>
uTestKeyboard.test_hook_key_nonblocking.<locals>.count
unhook_key
uTestKeyboard.test_hook_key_blocking.<locals>.count
on_press_key
uTestKeyboard.test_on_press_key_nonblocking.<locals>.<lambda>
u_b
uTestKeyboard.test_on_press_key_blocking.<locals>.<lambda>
on_release_key
uTestKeyboard.test_on_release_key.<locals>.<lambda>
block_key
unblock_key
remap_key
T wawbad_c
unremap_key
T wAwbT waushift+b
sorted
stash_state
restore_state
restore_modifiers
write
T waFT aexact
T aab
FT aAb
FT aab
f{  G z ?FT adelay
exact
assertGreater
f    Q  ?T aab
tT u  b
Fu
start_recording
stop_recording
a_queue
aQueue
process
uTestKeyboard.test_record.<locals>.process
threading
T aThread
aThread
T atarget
daemon
start
T f{  G z ?adu_a
du_b
du_space
get
T f
?T atimeout
put
record
T aspace
tT asuppress
play
ldfq=
Y@f{  G zt?adu_backspace
du_ctrl
get_typed_strings
uaA
ab
uAB
du_capslock
uaAb
get_hotkey_name
shift
ctrl
uctrl+shift+a
aSHIFT
uleft ctrl
uctrl+shift
plus
L w+uleft ctrl
shift
aWIN
uright alt
uctrl+alt+shift+windows+plus
L actrl
wbw!wauctrl+!+a+b
du_c
uctrl+a+b
uTestKeyboard.test_read_hotkey.<locals>.process
read_hotkey
uTestKeyboard.test_read_event.<locals>.process
read_event
uTestKeyboard.test_read_key.<locals>.process
read_key
uTestKeyboard.test_wait_infinite.<locals>.process
wait
uTestKeyboard.test_wait_until_success.<locals>.process
uTestKeyboard.test_wait_until_fail.<locals>.process
T watafail
add_hotkey
uTestKeyboard.test_add_hotkey_single_step_suppress_allow.<locals>.<lambda>
triggered_event
trigger
uTestKeyboard.test_add_hotkey_single_step_suppress_args_allow.<locals>.<lambda>
T aargs
suppress
assertIs
arg
remove_hotkey
uctrl+a
filtered_modifiers
ushift+a
blocking_hotkeys
values
assertNotEqual
ushift+a, b
D asuppress
trigger_on_release
tpD atimeout
suppress
l tua, b
D atimeout
suppress
f{  G z ?tT f    Q  ?D atimeout
suppress
f       ?tua, b, a
uTestKeyboard.test_add_hotkey_multi_step_allow.<locals>.<lambda>
uctrl+shift+a+b
uTestKeyboard.test_add_hotkey_single_step_nonsuppress.<locals>.<lambda>
uTestKeyboard.test_add_hotkey_single_step_nonsuppress_repeated.<locals>.<lambda>
uTestKeyboard.test_add_hotkey_single_step_nosuppress_with_modifiers_out_of_order.<locals>.<lambda>
u_c
remap_hotkey
T wauctrl+b, c
T uctrl+shift+a
wbT wawbtT atrigger_on_release
parse_hotkey_combinations
T l T T T l T T T l l T l l T ushift+ctrl+a
T T T l l l T l l l T ushift+a, b
T T T l l T l l T T l ua, b, c
ua, a, c
free
uTestKeyboard.test_add_word_listener_success.<locals>.free
add_word_listener
abc
uTestKeyboard.test_add_word_listener_no_trigger_fail.<locals>.free
aEmpty
uTestKeyboard.test_add_word_listener_timeout_fail.<locals>.free
D atimeout
l D aname
time
space
l uTestKeyboard.test_add_word_listener_remove.<locals>.free
remove_word_listener
T aabc
uTestKeyboard.test_add_word_listener_suffix_success.<locals>.free
D amatch_suffix
tuTestKeyboard.test_add_word_listener_suffix_fail.<locals>.free
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
print_function
unittest
a_keyboard_event
T aKeyboardEvent
aKEY_DOWN
aKEY_UP
D aspace
wawbwcwAwBwCaalt
uleft alt
uleft shift
uright shift
uleft ctrl
backspace
ucaps lock
w+w,w_anone
duplicated
L T l
L
L T l L
L T l L
L T l L
L T l L ashift
T q L
L T l L ashift
T q L
L T l L ashift
T q L
L T l L
L T l L
L T l L
L T l L
L T l L
L T l L
L T l	L
L T l
L
L T l L
L T l L
L
L T l L
T l L
T nl
a_os_keyboard
listen
a__getitem__
map_name
type_unicode
uleft shift
du_shift
alt
d_alt
u_alt
du_alt
backspace
ucaps lock
space
d_space
u_space
D ascan_code
l  aTestCase
a__prepare__
aTestKeyboard
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
