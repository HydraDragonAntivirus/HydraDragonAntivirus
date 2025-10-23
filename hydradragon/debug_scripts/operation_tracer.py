import sys
import threading
import time
import traceback
import os
from hydradragon.antivirus_scripts.hydra_logger import logger

_tracing_active = False
_original_sys_trace = None
_original_threading_trace = None
_start_time = None
_log_counter = 0
_MAX_LOG_LINES = 1_000_000

# Files from your directory listing (the "cd list")
_TARGET_MODULES = {
    "antivirus.py",
    "clamav.py",
    "detect_type.py",
    "notify_user.py",
    "path_and_variables.py",
    "pattern.py",
    "pe_feature_extractor.py",
    "pipe_events.py",
    "reference_registry.py",
    "utils_and_helpers.py",
    "engine.py",
    "hydra_logger.py",
    # add more names here if you want
}

def trace_calls(frame, event, arg):
    """Trace function for sys.settrace and threading.settrace."""
    global _log_counter
    try:
        if not _tracing_active or _log_counter >= _MAX_LOG_LINES:
            if _tracing_active and _log_counter == _MAX_LOG_LINES:
                try:
                    logger.critical("[TRACE] Log limit reached. Stopping trace logging.")
                except:
                    pass
                _log_counter += 1
            return None

        filename = frame.f_code.co_filename
        base = os.path.basename(filename)

        # match any target module by basename for robustness
        if base not in _TARGET_MODULES:
            return trace_calls  # skip everything else

        timestamp = time.time() - _start_time if _start_time else 0
        thread_id = threading.get_ident()
        func_name = frame.f_code.co_name
        lineno = frame.f_lineno

        log_msg = f"[TRACE|{timestamp:.4f}|Thd-{thread_id}] {event: <8} {filename}:{lineno} ({func_name})"

        # Log function arguments on call (optional)
        if event == "call":
            try:
                # Keep args small to avoid blowing up logs
                args = {k: repr(v)[:50] for k, v in frame.f_locals.items()}
                log_msg += f" | args={args}"
            except Exception:
                pass
        elif event == "return":
            try:
                log_msg += f" -> return={repr(arg)[:100]}"
            except Exception:
                pass
        elif event == "exception":
            try:
                exc_type, exc_value, _ = arg
                log_msg += f" -> exception={exc_type.__name__}: {exc_value}"
            except Exception:
                pass

        logger.debug(log_msg)
        _log_counter += 1

    except Exception as e:
        try:
            print(f"[TRACE-ERROR] {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        except Exception:
            pass

    return trace_calls


def _attach_trace_to_existing_threads():
    """Attach trace to all currently running threads (best-effort)."""
    current_thread_id = threading.get_ident()
    for thread in threading.enumerate():
        if thread.ident in (None, current_thread_id):
            continue
        try:
            if hasattr(sys, "_set_trace_for_tid"):
                sys._set_trace_for_tid(thread.ident, trace_calls)
            elif hasattr(thread, "_set_trace"):
                thread._set_trace(trace_calls)
        except Exception as e_thread:
            logger.warning(f"Failed to set trace for thread {thread.name} ({thread.ident}): {e_thread}")


def start_global_tracing():
    global _tracing_active, _original_sys_trace, _original_threading_trace, _start_time, _log_counter
    if _tracing_active:
        logger.warning("Tracing already active.")
        return

    logger.critical(">>> Starting GLOBAL operation tracing <<<")
    logger.warning("!!! THIS WILL SEVERELY IMPACT PERFORMANCE AND GENERATE LARGE LOGS !!!")
    logger.warning(f"!!! Log output limited to {_MAX_LOG_LINES} lines !!!")

    _start_time = time.time()
    _log_counter = 0
    _original_sys_trace = sys.gettrace()
    _original_threading_trace = threading.gettrace()
    _tracing_active = True

    # Trace current and future threads
    sys.settrace(trace_calls)
    threading.settrace(trace_calls)

    logger.debug("Attaching trace to existing threads...")
    _attach_trace_to_existing_threads()
    logger.info(f"Tracing attached to all existing threads (targets: {', '.join(sorted(_TARGET_MODULES))})")


def stop_global_tracing():
    global _tracing_active, _original_sys_trace, _original_threading_trace, _start_time
    if not _tracing_active:
        return

    logger.critical(">>> Stopping GLOBAL operation tracing <<<")
    _tracing_active = False
    _start_time = None

    sys.settrace(_original_sys_trace)
    threading.settrace(_original_threading_trace)

    current_thread_id = threading.get_ident()
    for thread in threading.enumerate():
        if thread.ident in (None, current_thread_id):
            continue
        try:
            if hasattr(sys, "_set_trace_for_tid"):
                sys._set_trace_for_tid(thread.ident, _original_sys_trace)
            elif hasattr(thread, "_set_trace"):
                thread._set_trace(_original_sys_trace)
        except Exception:
            pass

    _original_sys_trace = None
    _original_threading_trace = None
    logger.info("Global tracing stopped.")
