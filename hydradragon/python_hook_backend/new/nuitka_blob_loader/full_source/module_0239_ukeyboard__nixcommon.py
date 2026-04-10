# Reconstructed from integrated Nuitka blob
# Module: ukeyboard._nixcommon

a__qualname__
a__init__
uEventDevice.__init__
property
uEventDevice.input_file
uEventDevice.output_file
uEventDevice.read_event
uEventDevice.write_event
a__orig_bases__
T nuAggregatedEventDevice.__init__
uAggregatedEventDevice.read_event
uAggregatedEventDevice.write_event
collections
T anamedtuple
namedtuple
T aDeviceDescription
uevent_file is_mouse is_keyboard
aDeviceDescription
uN: Name="([^"]+?)".+?H: Handlers=([^\n]+)
aggregate_devices
ensure_root
ukeyboard\_nixcommon.py
u<module keyboard._nixcommon>
T a__class__
T aself
devices
output
start_reading
device
thread
T aself
path
T atype_name
uinput
fake_device
weawarnings
devices_from_proc
devices_from_by_id
T aself
weatry_close
T aname_suffix
by_id
path
T atype_name
wfadescription
devices
name
handlers
path
T afcntl
struct
uinput
aUI_SET_EVBIT
aUI_SET_KEYBIT
wiaBUS_USB
uinput_user_dev
axis
aUI_DEV_CREATE
aUI_DEV_DESTROY
T aself
T aself
data
seconds
microseconds
type
code
value
T adevice
self
T aself
type
code
value
T
self
type
code
value
integer
fraction
seconds
microseconds
data_event
sync_event

.keyboard._nixkeyboard
z
lstrip
T w+astartswith
T aKP_
T aMeta_
aControl_
dead_
aKP_
name
aRemove
aDelete
aBackspace
endswith
T a_r
uright
:nq nT a_l
uleft
normalize_name
all_modifiers
:nq nuUnknown modifier {}
to_name
append
from_name
ensure_root
D ashift
ualt gr
ctrl
alt
l l l l acheck_output
T L adumpkeys
u--keys-only
tT auniversal_newlines
re
findall
u^keycode\s+(\d+)\s+=(.*?)$
aMULTILINE
utoo many values to unpack (expected 2)
strip
split
sorted
cleanup_key
register_key
scan_code
keypad_scan_codes
add
ukeypad
T l}T
alt
T T l}T
windows
T l~T
T T l~T
windows
T l T
T T l T
menu
T L adumpkeys
u--long-info
tu^(\S+)\s+for (.+)$
extend
wiu<genexpr>
ubuild_tables.<locals>.<genexpr>
device
aggregate_devices
T akbd
build_device
build_tables
read_event
utoo many values to unpack (expected 5)
aEV_KEY
aKEY_DOWN
aKEY_UP
pressed_modifiers
unknown
l
discard
callback
aKeyboardEvent
T aevent_type
scan_code
name
time
device
is_keypad
modifiers
write_event
T w l T aleft
right
l amap_name
:l nnT actrl
shift
wuapress
release
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
struct
traceback
time
T atime
now
collections
T anamedtuple
namedtuple
a_keyboard_event
T aKeyboardEvent
aKEY_DOWN
aKEY_UP
a_canonical_names
T aall_modifiers
normalize_name
a_nixcommon
T aEV_KEY
aggregate_devices
ensure_root
cleanup_modifier
subprocess
T acheck_output
T adefaultdict
defaultdict
T Olist
init
listen
type_unicode
ukeyboard\_nixkeyboard.py
T a.0
modifier
bit
wiu<module keyboard._nixkeyboard>
T amodifiers_bits
keycode_template
dump
str_scan_code
str_names
scan_code
wiastr_name
modifiers
name
is_keypad
synonyms_template
synonym_str
original_str
synonym
w_aoriginal
T aname
is_keypad
mod
T amodifier
T acallback
time
type
code
value
device_id
scan_code
event_type
pressed_modifiers_tuple
names
name
is_keypad
T aname
entry
parts
T ascan_code
T akey_and_modifiers
name
T acharacter
codepoint
hexadecimal
key
scan_code
w_T ascan_code
is_down

.keyboard._nixmouse
m
s
display
window
x11
ctypes
cdll
aLoadLibrary
util
find_library
T aX11
aXInitThreads
aXOpenDisplay
T naXDefaultRootWindow
build_display
c_uint32
utoo many values to unpack (expected 2)
c_int
utoo many values to unpack (expected 4)
c_uint
aXQueryPointer
byref
value
aXWarpPointer
l
aXFlush
device
ensure_root
aggregate_devices
T amouse
build_device
read_event
utoo many values to unpack (expected 5)
aEV_SYN
aEV_MSC
aEV_KEY
aButtonEvent
aDOWN
aUP
button_by_code
get
w?aEV_REL
struct
unpack
wiapack
wIutoo many values to unpack (expected 1)
aREL_WHEEL
aWheelEvent
aREL_X
aREL_Y
get_position
aMoveEvent
queue
put
write_event
code_by_button
l g
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
subprocess
T acheck_output
check_output
re
a_nixcommon
T aEV_KEY
aEV_REL
aEV_MSC
aEV_SYN
aEV_ABS
aggregate_devices
ensure_root
aEV_ABS
a_mouse_event
T
aButtonEvent
aWheelEvent
aMoveEvent
aLEFT
aRIGHT
aMIDDLE
wXaX2
aUP
aDOWN
aLEFT
aRIGHT
aMIDDLE
wXaX2
uctypes.util
move_to
l aREL_Z
l aREL_HWHEEL
l aABS_X
aABS_Y
l  aBTN_MOUSE
aBTN_LEFT
l  aBTN_RIGHT
l  aBTN_MIDDLE
l  aBTN_SIDE
l  aBTN_EXTRA
init
listen
press
release
move_relative
T l awheel
ukeyboard\_nixmouse.py
u<module keyboard._nixmouse>
T aroot_id
child_id
root_x
root_y
win_x
win_y
mask
ret
T
queue
time
type
code
value
device_id
event
arg
wxwyT wxwyT abutton
T adelta

.keyboard._winkeyboard
scan_code
vk
is_extended
keypad_keys
official_virtual_keys
l
l  ashift
modifiers
keyboard_state
l ualt gr
l l l ucaps lock
l unum lock
l  uscroll lock
l  aToUnicode
unicode_buffer
value
aGetKeyNameText
l aname_buffer
l  auser32
aMapVirtualKeyW
aMAPVK_VK_TO_CHAR
l  achr
get_event_names
tables_lock
a__enter__
a__exit__
to_name
;l
l  l aMapVirtualKeyExW
aMAPVK_VSC_TO_VK_EX
aMAPVK_VK_TO_VSC_EX
utoo many values to unpack (expected 2)
scan_code_to_vk
T l
l adistinct_modifiers
lower
normalize_name
from_name
append
entry
l  l  aextended
T nnnadefaultdict
l
u<lambda>
u_setup_name_tables.<locals>.<lambda>
update
D T
T ashift
T ualt gr
T actrl
T aalt
l
l l l l aorder_key
u_setup_name_tables.<locals>.order_key
items
sorted
T akey
utoo many values to unpack (expected 4)
modifiers_preference
a_setup_name_tables
process_key
uprepare_intercept.<locals>.process_key
low_level_keyboard_handler
uprepare_intercept.<locals>.low_level_keyboard_handler
c_int
T laLowLevelKeyboardProc
aGetModuleHandleW
T naDWORD
T l
aSetWindowsHookEx
atexit
register
aUnhookWindowsHookEx
l  aignore_next_right_alt
T ashift
shift_is_pressed
T ualt gr
altgr_is_pressed
T unum lock
aGetKeyState
T l  T ucaps lock
T l T uscroll lock
T l  ashift_vks
aKEY_DOWN
callback
aKeyboardEvent
T aevent_type
scan_code
name
is_keypad
contents
vk_code
aLLKHF_INJECTED
l aVK_PACKET
flags
keyboard_event_types
q aprint
T uError in keyboard hook:
traceback
print_exc
aCallNextHookEx
prepare_intercept
aLPMSG
aGetMessage
msg
aTranslateMessage
aDispatchMessage
get
name
uKey name {} is not mapped to any known key.
map_name
keybd_event
a_send_event
l aencode
T uutf-16le
aKEYBDINPUT
l aKEYEVENTF_UNICODE
presses
aINPUT
aINPUT_KEYBOARD
a_INPUTunion
T aki
aKEYEVENTF_KEYUP
releases
sizeof
aSendInput
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unicode_literals
re
threading
T aLock
aLock
collections
T adefaultdict
a_keyboard_event
T aKeyboardEvent
aKEY_DOWN
aKEY_UP
aKEY_UP
a_canonical_names
T anormalize_name
unichr
ctypes
c_short
c_char
c_uint8
c_int32
c_uint
c_uint32
c_long
aStructure
aCFUNCTYPE
aPOINTER
aWORD
aBOOL
aHHOOK
aMSG
aLPWSTR
aWCHAR
aWPARAM
aLPARAM
aLONG
aHMODULE
aLPCWSTR
aHINSTANCE
aHWND
aULONG_PTR
aWinDLL
T akernel32
tT ause_last_error
kernel32
restype
argtypes
T auser32
tl  aINPUT_MOUSE
aINPUT_HARDWARE
l a__prepare__
aKBDLLHOOKSTRUCT
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
