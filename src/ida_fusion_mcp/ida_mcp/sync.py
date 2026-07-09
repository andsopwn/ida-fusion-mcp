import logging
import queue
import functools
import os
import sys
import threading
import time
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""
    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 15.0
_deadline_state = threading.local()


def get_tool_deadline() -> float | None:
    """Return the monotonic deadline for the current synchronized tool call."""
    return getattr(_deadline_state, "deadline", None)


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC



call_stack: list[tuple[object, str]] = []


def _sync_wrapper(ff):
    """Run ff on IDA's main thread and return errors through the result channel."""
    res_container = queue.Queue(maxsize=1)

    def runned():
        if call_stack:
            active_name = call_stack[-1][1]
            res_container.put(
                IDASyncError(
                    f"Call stack is not empty while calling the function "
                    f"{ff.__name__} from {active_name}"
                )
            )
            return

        entry = (object(), ff.__name__)
        call_stack.append(entry)
        old_batch = None
        result = None
        try:
            old_batch = idc.batch(1)
            result = ff()
        except Exception as exc:
            result = exc
        finally:
            try:
                if old_batch is not None:
                    idc.batch(old_batch)
            except Exception as exc:
                result = exc
            finally:
                if call_stack and call_stack[-1] is entry:
                    call_stack.pop()
                res_container.put(result)

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    result = res_container.get()
    if isinstance(result, Exception):
        raise result
    return result

def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    cancel_event = get_current_cancel_event()
    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()

    if timeout > 0 or cancel_event is not None:
        def timed_ff():
            previous_deadline = getattr(_deadline_state, "deadline", None)
            old_profile = sys.getprofile()
            deadline: float | None = None
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            timer_started = False
            cancel_armed = threading.Event()
            try:
                deadline = time.monotonic() + timeout if timeout > 0 else None
                _deadline_state.deadline = deadline
                ida_kernwin.clr_cancelled()
                if deadline is not None:
                    cancel_armed.set()

                    def fire_native_cancel():
                        if not cancel_armed.is_set():
                            return
                        cancel_fired_at[0] = time.monotonic()
                        ida_kernwin.set_cancelled()

                    native_timer = threading.Timer(timeout, fire_native_cancel)
                    native_timer.daemon = True
                    native_timer.start()
                    timer_started = True

                def profilefunc(frame, event, arg):
                    if cancel_event is not None and cancel_event.is_set():
                        raise CancelledError("Request was cancelled")
                    fired_at = cancel_fired_at[0]
                    if fired_at is not None and time.monotonic() < fired_at + 5.0:
                        return
                    if deadline is not None and time.monotonic() >= deadline:
                        raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

                sys.setprofile(profilefunc)
                return ff()
            finally:
                try:
                    sys.setprofile(old_profile)
                finally:
                    cancel_armed.clear()
                    try:
                        if native_timer is not None:
                            native_timer.cancel()
                            if timer_started:
                                native_timer.join()
                    finally:
                        try:
                            ida_kernwin.clr_cancelled()
                        finally:
                            _deadline_state.deadline = previous_deadline

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff)
    return _sync_wrapper(ff)


def idasync(f):
    """Run the function on the IDA main thread in write mode.
    
    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


# Backwards compatibility aliases
idaread = idasync
idawrite = idasync


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """
    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func
    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    
    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets
    
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
