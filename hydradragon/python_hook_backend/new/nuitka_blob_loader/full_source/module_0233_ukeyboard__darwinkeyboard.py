# Reconstructed from integrated Nuitka blob
# Module: ukeyboard._darwinkeyboard

uKeyMap.__init__.<locals>.CFRange
a__qualname__
loc
aCFIndex
len
a_fields_
a__orig_bases__
in_dll
aCarbon
kTISPropertyUnicodeKeyLayoutData
l aCFDataGetBytes
argtypes
restype
aCFDataGetLength
aCFRelease
aLMGetKbdType
aTISCopyCurrentKeyboardInputSource
aTISCopyCurrentASCIICapableKeyboardLayoutInputSource
aTISGetInputSourceProperty
aPOINTER
aUCKeyTranslate
create_string_buffer
byref
;l
l  l aUniChar4
aUniCharCount
k_layout_buffer
kUCKeyActionDisplay
kUCKeyTranslateNoDeadKeysBit

value
l aself
layout_specific_keys
klis
unichr
non_shifted_char
uKeyMap.__init__.<locals>.<genexpr>
shifted_char
non_layout_keys
character
lower
l ashift
uUnrecognized character: {}
uInvalid scan code: {}
aKeyMap
key_map
D ashift
caps
alt
ctrl
cmd
Fppppacurrent_modifiers
D aKEYTYPE_SOUND_UP
aKEYTYPE_SOUND_DOWN
aKEYTYPE_BRIGHTNESS_UP
aKEYTYPE_BRIGHTNESS_DOWN
aKEYTYPE_CAPS_LOCK
aKEYTYPE_HELP
aPOWER_KEY
aKEYTYPE_MUTE
aUP_ARROW_KEY
aDOWN_ARROW_KEY
aKEYTYPE_NUM_LOCK
aKEYTYPE_CONTRAST_UP
aKEYTYPE_CONTRAST_DOWN
aKEYTYPE_LAUNCH_PANEL
aKEYTYPE_EJECT
aKEYTYPE_VIDMIRROR
aKEYTYPE_PLAY
aKEYTYPE_NEXT
aKEYTYPE_PREVIOUS
aKEYTYPE_FAST
aKEYTYPE_REWIND
aKEYTYPE_ILLUMINATION_UP
aKEYTYPE_ILLUMINATION_DOWN
aKEYTYPE_ILLUMINATION_TOGGLE
l
l l l l l l l l l	l
l l ll l l l l l l l l l amedia_keys
l  aNSEvent
otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2_
l T l
pl  l l q aQuartz
aCGEventPost
aCGEvent
kCGEventFlagMaskShift
caps
kCGEventFlagMaskAlphaShift
alt
kCGEventFlagMaskAlternate
ctrl
kCGEventFlagMaskControl
cmd
kCGEventFlagMaskCommand
l7l8l<l9l:l;aCGEventCreateKeyboardEvent
aCGEventSetFlags
kCGHIDEventTap
time
sleep
T f{  G z ?l  acharacter_to_vk
scan_code
vk_to_character
blocking
callback
listening
tap
aCGEventTapCreate
kCGSessionEventTap
kCGHeadInsertEventTap
kCGEventTapOptionDefault
aCGEventMaskBit
kCGEventKeyDown
kCGEventKeyUp
kCGEventFlagsChanged
handler
aCFMachPortCreateRunLoopSource
aCFRunLoopGetCurrent
aCFRunLoopAddSource
kCFRunLoopDefaultMode
aCGEventTapEnable
aCFRunLoopRunInMode
l aCGEventGetIntegerValueField
kCGKeyboardEventKeycode
name_from_scancode
aCGEventGetFlags
kCGEventFlagMaskNumericPad
down
up
endswith
T ashift
ucaps lock
T aoption
T aalt
command
aKeyboardEvent
T aname
is_keypad
aKeyController
key_controller
press
release
map_char
name
map_name
map_scan_code
geteuid
uError 13 - Must be run as administrator
aKeyEventListener
run
aCGEventSourceCreate
kCGEventSourceStateHIDSystemState
aCGEventKeyboardSetUnicodeString
encode
T uutf-16-le
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uctypes.util
os
threading
aAppKit
T aNSEvent
a_keyboard_event
T aKeyboardEvent
aKEY_DOWN
aKEY_UP
aKEY_DOWN
aKEY_UP
a_canonical_names
T anormalize_name
chr
cdll
aLoadLibrary
util
find_library
T aCarbon
T Oobject
dict
D/l$l0l1l3l5l7l8l9l:l;l<l=l>l?l@lHlIlJlOlPlZl`lalblcldlelgliljlklmlolqlrlsltlulvlwlxlylzl{l|l}l~areturn
tab
space
delete
escape
command
shift
capslock
option
control
uright shift
uright option
uright control
function
f17
uvolume up
uvolume down
mute
f18
f19
f20
f5
f6
f7
f3
f8
f9
f11
f13
f16
f14
f10
f12
f15
help
home
upage up
uforward delete
f4
end
f2
upage down
f1
left
right
down
up
a__init__
uKeyMap.__init__
uKeyMap.character_to_vk
uKeyMap.vk_to_character
uKeyController.__init__
uKeyController.press
uKeyController.release
uKeyController.map_char
uKeyController.map_scan_code
T FuKeyEventListener.__init__
uKeyEventListener.run
uKeyEventListener.handler
init
listen
type_unicode
ukeyboard\_darwinkeyboard.py
T a.0
vk
name
T a.0
wianon_shifted_char
T a.0
wiashifted_char
u<module keyboard._darwinkeyboard>
T a__class__
aCFIndex
T a__class__
T aself
T aself
callback
blocking
T aself
aCFTypeRef
aCFDataRef
aCFIndex
aOptionBits
aUniCharCount
aUniChar
aUniChar4
aCFRange
kTISPropertyUnicodeKeyLayoutData
shiftKey
alphaKey
optionKey
controlKey
kUCKeyActionDisplay
kUCKeyTranslateNoDeadKeysBit
klis
k_layout
k_layout_size
k_layout_buffer
key_code
non_shifted_char
shifted_char
keys_down
char_count
retval
non_shifted_key
shifted_key
T aself
character
vk
T
self
proxy
e_type
event
refcon
scan_code
key_name
flags
event_type
is_keypad
T akey_controller
T acallback
T aself
character
T aname
T aself
scan_code
character
T ascan_code
T aself
key_code
ev
event_flags
event
T aself
loopsource
loop
T acharacter
aOUTPUT_SOURCE
event
T aself
vk
modifiers
.keyboard._darwinmouse
blocking
callback
listening
aQuartz
aCGEventTapCreate
kCGSessionEventTap
kCGHeadInsertEventTap
kCGEventTapOptionDefault
aCGEventMaskBit
kCGEventLeftMouseDown
kCGEventLeftMouseUp
kCGEventRightMouseDown
kCGEventRightMouseUp
kCGEventOtherMouseDown
kCGEventOtherMouseUp
kCGEventMouseMoved
kCGEventScrollWheel
handler
tap
aCFMachPortCreateRunLoopSource
l
aCFRunLoopGetCurrent
aCFRunLoopAddSource
kCFRunLoopDefaultMode
aCGEventTapEnable
self
aCFRunLoopRunInMode
l aCGEventGetIntegerValueField
kCGKeyboardEventKeycode
name_from_scancode
aCGEventGetFlags

kCGEventFlagMaskNumericPad
kCGEventKeyDown
down
kCGEventKeyUp
up
aKeyboardEvent
T aname
is_keypad
geteuid
uError 13 - Must be run as administrator
aMouseEventListener
u<lambda>
ulisten.<locals>.<lambda>
threading
aThread
run
T atarget
args
daemon
start
queue
put
is_allowed
name
event_type
aKEY_UP
get_position
a_button_mapping
utoo many values to unpack (expected 4)
aCGEventCreateMouseEvent
a_last_click
time
datetime
now
timedelta
T f333333 ?T aseconds
button
position
min
l aclick_count
l aCGEventSetIntegerValueField
kCGMouseEventClickState
aCGEventPost
kCGHIDEventTap
a_button_state
T l   T amicroseconds
kCGMouseButtonLeft
aCGEventCreateScrollWheelEvent
kCGScrollEventUnitLine
weaCGEventCreate
T naCGEventGetLocation
wxwya__doc__
a__file__
a__spec__
origin
has_location
a__cached__
os
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
aButtonEvent
aWheelEvent
aMoveEvent
aLEFT
aRIGHT
aMIDDLE
wXaX2
aUP
aDOWN
kCGEventLeftMouseDragged
kCGMouseButtonRight
kCGEventRightMouseDragged
kCGMouseButtonCenter
kCGEventOtherMouseDragged
D atime
button
position
click_count
nnnl
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
