// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.keyboard_at_11871636
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl__Event__wait( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_KEY_DOWN = NULL;
    PyObject *var_KEY_UP = NULL;
    PyObject *var_KeyboardEvent = NULL;
    PyObject *var_all_modifiers = NULL;
    PyObject *var_sided_modifiers = NULL;
    PyObject *var_normalize_name = NULL;
    PyObject *var_False = NULL;
    PyObject *var_True = NULL;
    PyObject *var_free = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_True = NULL;
    PyObject *var_None = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_free = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_suppressed = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_allowed = NULL;
    PyObject *var_True = NULL;
    PyObject *var_None = NULL;
    PyObject *var_llowed = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_llowed = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('platform');
    PyObject *tuple_1 = MAKE_TUPLE("('_winkeyboard',)");
    PyObject *str_const_2 = MAKE_STRING('Linux');
    PyObject *tuple_3 = MAKE_TUPLE("('_nixkeyboard',)");
    PyObject *tuple_4 = MAKE_TUPLE("('_darwinkeyboard',)");
    PyObject *str_const_5 = MAKE_STRING("Unsupported platform '{}'");
    PyObject *str_const_6 = MAKE_STRING('KeyboardEvent');
    PyObject *tuple_7 = MAKE_TUPLE("('GenericListener',)");
    PyObject *str_const_8 = MAKE_STRING('GenericListener');
    // Discovered Timeout Logic
    time_sleep((double)151 / 1000.0);
    // Discovered Timeout Logic
    time_sleep((double)110 / 1000.0);
    PyObject *str_const_11 = MAKE_STRING('pending');
    PyObject *str_const_12 = MAKE_STRING('allowed');
    PyObject *str_const_13 = MAKE_STRING('suppressed');
    PyObject *str_const_14 = MAKE_STRING('suppressed');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl__KeyboardListener__init( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("pre_process_event"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl__KeyboardListener__pre_process_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl__KeyboardListener__direct_callback( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl__KeyboardListener__listen( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_active_modifiers = NULL;
    PyObject *var_blocking_hooks = NULL;
    PyObject *var_blocking_keys = NULL;
    PyObject *var_nonblocking_keys = NULL;
    PyObject *var_blocking_hotkeys = NULL;
    PyObject *var_nonblocking_hotkeys = NULL;
    PyObject *var_filtered_modifiers = NULL;
    PyObject *var_is_replaying = NULL;
    PyObject *var_modifier_states = NULL;
    PyObject *var_True = NULL;
    PyObject *var_None = NULL;
    PyObject *var_False = NULL;
    PyObject *var_False = NULL;
    PyObject *var_True = NULL;
    PyObject *var_False = NULL;
    PyObject *var_True = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_escape = NULL;
    PyObject *var_False = NULL;
    PyObject *var_None = NULL;
    PyObject *var_False = NULL;
    PyObject *var_hook = NULL;
    PyObject *var_event = NULL;
    PyObject *var_None = NULL;
    PyObject *var_name = NULL;
    PyObject *var_scan_code = NULL;
    PyObject *var_pressed_scan_codes = NULL;
    PyObject *var_None = NULL;
    PyObject *var_aleft_scan_codes = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_key = NULL;
    PyObject *var_step = NULL;
    PyObject *var_combine_step = NULL;
    PyObject *var_scan_codes = NULL;
    PyObject *var_modifier = NULL;
    PyObject *var_state = NULL;
    PyObject *var_scan_code = NULL;
    PyObject *var_callback = NULL;
    PyObject *var_args = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_event_type = NULL;
    PyObject *var_callback = NULL;
    PyObject *var_event_type = NULL;
    PyObject *var_delay = NULL;
    PyObject *var_fn = NULL;
    PyObject *var_args = NULL;
    PyObject *var_args = NULL;
    PyObject *var_delay = NULL;
    PyObject *var_fn = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_handler = NULL;
    PyObject *var_combinations = NULL;
    PyObject *var_suppress = NULL;
    PyObject *var_container = NULL;
    PyObject *var_scan_codes = NULL;
    PyObject *var_scan_code = NULL;
    PyObject *var_remove = NULL;
    PyObject *var_source_text = NULL;
    PyObject *var_replacement_text = NULL;
    PyObject *var_match_suffix = NULL;
    PyObject *var_timeout = NULL;
    PyObject *var_replacement = NULL;
    PyObject *var_callback = NULL;
    PyObject *var_hotkey = NULL;
    PyObject *var_callback = NULL;
    PyObject *var_args = NULL;
    PyObject *var_suppress = NULL;
    PyObject *var_timeout = NULL;
    PyObject *var_trigger_on_release = NULL;
    PyObject *var_steps = NULL;
    PyObject *var_event_type = NULL;
    PyObject *var_handler = NULL;
    PyObject *var_remove_step = NULL;
    PyObject *var_remove_ = NULL;
    PyObject *var_state = NULL;
    PyObject *var_catch_misses = NULL;
    PyObject *var_set_index = NULL;
    PyObject *var_allowed_keys_by_step = NULL;
    PyObject *var_word = NULL;
    PyObject *var_callback = NULL;
    PyObject *var_triggers = NULL;
    PyObject *var_match_suffix = NULL;
    PyObject *var_timeout = NULL;
    PyObject *var_state = NULL;
    PyObject *var_handler = NULL;
    PyObject *var_hooked = NULL;
    PyObject *var_remove = NULL;
    PyObject *var_fn = NULL;
    PyObject *var_args = NULL;
    PyObject *var_delay = NULL;
    PyObject *var_thread = NULL;
    PyObject *var_event = NULL;
    PyObject *var_force_fail = NULL;
    PyObject *var_index = NULL;
    PyObject *var_event_type = NULL;
    PyObject *var_state = NULL;
    PyObject *var_allowed_keys_by_step = NULL;
    PyObject *var_timeout = NULL;
    PyObject *var_set_index = NULL;
    PyObject *var_allowed_keys_by_step = NULL;
    PyObject *var_event_type = NULL;
    PyObject *var_set_index = NULL;
    PyObject *var_state = NULL;
    PyObject *var_timeout = NULL;
    PyObject *var_self = NULL;
    PyObject *var_event = NULL;
    PyObject *var_event_type = NULL;
    PyObject *var_scan_code = NULL;
    PyObject *var_hotkey = NULL;
    PyObject *var_key_hook = NULL;
    PyObject *var_accept = NULL;
    PyObject *var_origin = NULL;
    PyObject *var_modifiers_to_update = NULL;
    PyObject *var_callback_results = NULL;
    PyObject *var_key = NULL;
    PyObject *var_transition_tuple = NULL;
    PyObject *var_should_press = NULL;
    PyObject *var_new_accept = NULL;
    PyObject *var_new_state = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('True',)");
    PyObject *str_const_1 = MAKE_STRING('nd_release');
    PyObject *str_const_2 = MAKE_STRING('is_pressed');
    PyObject *str_const_3 = MAKE_STRING('call_later');
    PyObject *str_const_4 = MAKE_STRING('on_press');
    PyObject *str_const_5 = MAKE_STRING('on_release');
    PyObject *str_const_6 = MAKE_STRING('on_press_key');
    PyObject *str_const_7 = MAKE_STRING('on_release_key');
    PyObject *str_const_8 = MAKE_STRING('unhook_key');
    PyObject *str_const_9 = MAKE_STRING('unhook_all');
    PyObject *str_const_10 = MAKE_STRING('block_key');
    PyObject *str_const_11 = MAKE_STRING('unblock_key');
    PyObject *str_const_12 = MAKE_STRING('remap_key');
    PyObject *str_const_13 = MAKE_STRING('unremap_key');
    PyObject *str_const_14 = MAKE_STRING('register_hotkey');
    PyObject *str_const_15 = MAKE_STRING('unregister_hotkey');
    PyObject *str_const_16 = MAKE_STRING('clear_hotkey');
    PyObject *str_const_17 = MAKE_STRING('unregister_all_hotkeys');
    PyObject *str_const_18 = MAKE_STRING('remove_all_hotkeys');
    PyObject *str_const_19 = MAKE_STRING('clear_all_hotkeys');
    PyObject *str_const_20 = MAKE_STRING('remap_hotkey');
    PyObject *str_const_21 = MAKE_STRING('unremap_hotkey');
    PyObject *str_const_22 = MAKE_STRING('read_key');
    PyObject *str_const_23 = MAKE_STRING('read_hotkey');
    PyObject *str_const_24 = MAKE_STRING('ord');
    PyObject *tuple_25 = MAKE_TUPLE("('1.0',)");
    PyObject *str_const_26 = MAKE_STRING('play');
    PyObject *str_const_27 = MAKE_STRING('replay');
    PyObject *val_28 = MAKE_INT(2);
    PyObject *str_const_29 = MAKE_STRING('remove_word_listener');
    PyObject *str_const_30 = MAKE_STRING('add_abbreviation');
    PyObject *str_const_31 = MAKE_STRING('register_word_listener');
    PyObject *str_const_32 = MAKE_STRING('register_abbreviation');
    PyObject *str_const_33 = MAKE_STRING('remove_abbreviation');
    PyObject *str_const_34 = MAKE_STRING('keyboard\\__init__.py');
    // Discovered Timeout Logic
    time_sleep((double)84 / 1000.0);
    PyObject *str_const_36 = MAKE_STRING('scan_code');
    PyObject *str_const_37 = MAKE_STRING('modifier');
    PyObject *tuple_38 = MAKE_TUPLE("('dst',)");
    PyObject *tuple_39 = MAKE_TUPLE("('None',)");
    PyObject *tuple_40 = MAKE_TUPLE("('replacement',)");
    PyObject *tuple_41 = MAKE_TUPLE("('args',)");
    PyObject *str_const_42 = MAKE_STRING('callback');
    PyObject *tuple_43 = MAKE_TUPLE("('None',)");
    PyObject *str_const_44 = MAKE_STRING('modifiers');
    PyObject *tuple_45 = MAKE_TUPLE("('modifiers',)");
    PyObject *str_const_46 = MAKE_STRING('callback');
    PyObject *tuple_47 = MAKE_TUPLE("('callback',)");
    PyObject *str_const_48 = MAKE_STRING('queue');
    PyObject *tuple_49 = MAKE_TUPLE("('queue',)");
    PyObject *tuple_50 = MAKE_TUPLE("('lock',)");
    PyObject *str_const_51 = MAKE_STRING('<module keyboard>');
    PyObject *tuple_52 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_53 = MAKE_TUPLE("('step',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
