from typing import Annotated
import ast
import io
import os
import sys
import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref

from .rpc import tool, unsafe
from .sync import idasync
from .utils import parse_address, get_function

# ============================================================================
# Shared execution context
# ============================================================================


def _restricted_ida_import(
    name,
    globals=None,
    locals=None,
    fromlist=(),
    level=0,
):
    if not isinstance(name, str):
        raise TypeError("module name must be a string")
    if level != 0:
        raise ImportError("Relative imports are not allowed")
    if not (
        name.startswith("ida_")
        or name in {"idaapi", "idautils", "idc"}
    ):
        raise ImportError(
            f"Module '{name}' is not allowed. "
            "Only IDA modules (ida_*, idaapi, idautils, idc) are permitted."
        )
    return __import__(name, globals, locals, fromlist, level)


def _optional_ida_import(module_name):
    try:
        return _restricted_ida_import(module_name)
    except ImportError:
        return None


def _validate_restricted_python(code: str, filename: str = "<string>") -> None:
    """Reject direct dunder traversal before restricted code is evaluated.

    This is a defense-in-depth guard for an unsafe tool, not a process sandbox.
    """
    tree = ast.parse(code, filename=filename, mode="exec")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr.startswith("__")
            and node.attr.endswith("__")
        ):
            raise ValueError(
                f"Access to dunder attribute '{node.attr}' is blocked"
            )


def _make_restricted_exec_globals() -> dict:

    def _safe_getattr(obj, name, *default):
        if isinstance(name, str) and name.startswith("__") and name.endswith("__"):
            raise AttributeError(f"Access to dunder attribute '{name}' is blocked")
        return getattr(obj, name, *default)

    def _safe_setattr(obj, name, value):
        if isinstance(name, str) and name.startswith("__") and name.endswith("__"):
            raise AttributeError(f"Setting dunder attribute '{name}' is blocked")
        return setattr(obj, name, value)

    _safe_builtins = {
        "True": True, "False": False, "None": None,
        "int": int, "float": float, "str": str, "bool": bool,
        "bytes": bytes, "bytearray": bytearray, "complex": complex,
        "list": list, "tuple": tuple, "dict": dict, "set": set, "frozenset": frozenset,
        "abs": abs, "all": all, "any": any, "bin": bin, "chr": chr, "ord": ord,
        "divmod": divmod, "enumerate": enumerate, "filter": filter,
        "format": format, "getattr": _safe_getattr, "hasattr": hasattr,
        "hash": hash, "hex": hex, "id": id, "isinstance": isinstance,
        "issubclass": issubclass, "iter": iter, "len": len, "map": map,
        "max": max, "min": min, "next": next, "oct": oct, "pow": pow,
        "print": print, "range": range, "repr": repr, "reversed": reversed,
        "round": round, "setattr": _safe_setattr, "slice": slice, "sorted": sorted,
        "sum": sum, "zip": zip,
        "callable": callable, "property": property,
        "staticmethod": staticmethod, "classmethod": classmethod,
        "Exception": Exception, "ValueError": ValueError, "TypeError": TypeError,
        "KeyError": KeyError, "IndexError": IndexError, "AttributeError": AttributeError,
        "RuntimeError": RuntimeError, "StopIteration": StopIteration,
        "NotImplementedError": NotImplementedError, "ZeroDivisionError": ZeroDivisionError,
        "__import__": _restricted_ida_import,
    }

    return {
        "__builtins__": _safe_builtins,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": _optional_ida_import("idautils"),
        "ida_allins": _optional_ida_import("ida_allins"),
        "ida_auto": _optional_ida_import("ida_auto"),
        "ida_bitrange": _optional_ida_import("ida_bitrange"),
        "ida_bytes": ida_bytes,
        "ida_dbg": ida_dbg,
        "ida_dirtree": _optional_ida_import("ida_dirtree"),
        "ida_diskio": _optional_ida_import("ida_diskio"),
        "ida_entry": ida_entry,
        "ida_expr": _optional_ida_import("ida_expr"),
        "ida_fixup": _optional_ida_import("ida_fixup"),
        "ida_fpro": _optional_ida_import("ida_fpro"),
        "ida_frame": ida_frame,
        "ida_funcs": ida_funcs,
        "ida_gdl": _optional_ida_import("ida_gdl"),
        "ida_graph": _optional_ida_import("ida_graph"),
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_idd": _optional_ida_import("ida_idd"),
        "ida_idp": _optional_ida_import("ida_idp"),
        "ida_ieee": _optional_ida_import("ida_ieee"),
        "ida_kernwin": ida_kernwin,
        "ida_libfuncs": _optional_ida_import("ida_libfuncs"),
        "ida_lines": ida_lines,
        "ida_loader": _optional_ida_import("ida_loader"),
        "ida_merge": _optional_ida_import("ida_merge"),
        "ida_mergemod": _optional_ida_import("ida_mergemod"),
        "ida_moves": _optional_ida_import("ida_moves"),
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_netnode": _optional_ida_import("ida_netnode"),
        "ida_offset": _optional_ida_import("ida_offset"),
        "ida_pro": _optional_ida_import("ida_pro"),
        "ida_problems": _optional_ida_import("ida_problems"),
        "ida_range": _optional_ida_import("ida_range"),
        "ida_regfinder": _optional_ida_import("ida_regfinder"),
        "ida_registry": _optional_ida_import("ida_registry"),
        "ida_search": _optional_ida_import("ida_search"),
        "ida_segment": ida_segment,
        "ida_segregs": _optional_ida_import("ida_segregs"),
        "ida_srclang": _optional_ida_import("ida_srclang"),
        "ida_strlist": _optional_ida_import("ida_strlist"),
        "ida_struct": _optional_ida_import("ida_struct"),
        "ida_tryblks": _optional_ida_import("ida_tryblks"),
        "ida_typeinf": ida_typeinf,
        "ida_ua": _optional_ida_import("ida_ua"),
        "ida_undo": _optional_ida_import("ida_undo"),
        "ida_xref": ida_xref,
        "ida_enum": _optional_ida_import("ida_enum"),
        "parse_address": parse_address,
        "get_function": get_function,
    }


# ============================================================================
# Python Evaluation
# ============================================================================


@tool
@idasync
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
) -> dict:
    """Execute Python code in IDA context.
    Returns dict with result/stdout/stderr.
    Has access to all IDA API modules.
    Supports Jupyter-style evaluation. This unsafe tool uses defense-in-depth
    restrictions but is not a process security sandbox."""
    # Capture stdout/stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        _validate_restricted_python(code)

        # Defense in depth: reduce accidental access to host-side primitives.
        # This in-process tool is still explicitly unsafe and is not a sandbox.

        # Wrap getattr/setattr to block direct dunder traversal.
        def _safe_getattr(obj, name, *default):
            if isinstance(name, str) and name.startswith("__") and name.endswith("__"):
                raise AttributeError(f"Access to dunder attribute '{name}' is blocked in py_eval")
            return getattr(obj, name, *default)

        def _safe_setattr(obj, name, value):
            if isinstance(name, str) and name.startswith("__") and name.endswith("__"):
                raise AttributeError(f"Setting dunder attribute '{name}' is blocked in py_eval")
            return setattr(obj, name, value)

        _safe_builtins = {
            # Core types and conversions
            "True": True, "False": False, "None": None,
            "int": int, "float": float, "str": str, "bool": bool,
            "bytes": bytes, "bytearray": bytearray, "complex": complex,
            "list": list, "tuple": tuple, "dict": dict, "set": set, "frozenset": frozenset,
            # Utility functions
            "abs": abs, "all": all, "any": any, "bin": bin, "chr": chr, "ord": ord,
            "divmod": divmod, "enumerate": enumerate, "filter": filter,
            "format": format, "getattr": _safe_getattr, "hasattr": hasattr,
            "hash": hash, "hex": hex, "id": id, "isinstance": isinstance,
            "issubclass": issubclass, "iter": iter, "len": len, "map": map,
            "max": max, "min": min, "next": next, "oct": oct, "pow": pow,
            "print": print, "range": range, "repr": repr, "reversed": reversed,
            "round": round, "setattr": _safe_setattr, "slice": slice, "sorted": sorted,
            "sum": sum, "zip": zip,
            "callable": callable, "property": property,
            "staticmethod": staticmethod, "classmethod": classmethod,
            # Exceptions (needed for try/except)
            "Exception": Exception, "ValueError": ValueError, "TypeError": TypeError,
            "KeyError": KeyError, "IndexError": IndexError, "AttributeError": AttributeError,
            "RuntimeError": RuntimeError, "StopIteration": StopIteration,
            "NotImplementedError": NotImplementedError, "ZeroDivisionError": ZeroDivisionError,
            # Restrict ordinary import statements to IDA modules.
            "__import__": _restricted_ida_import,
        }

        exec_globals = {
            "__builtins__": _safe_builtins,
            "idaapi": idaapi,
            "idc": idc,
            "idautils": _optional_ida_import("idautils"),
            "ida_allins": _optional_ida_import("ida_allins"),
            "ida_auto": _optional_ida_import("ida_auto"),
            "ida_bitrange": _optional_ida_import("ida_bitrange"),
            "ida_bytes": ida_bytes,
            "ida_dbg": ida_dbg,
            "ida_dirtree": _optional_ida_import("ida_dirtree"),
            "ida_diskio": _optional_ida_import("ida_diskio"),
            "ida_entry": ida_entry,
            "ida_expr": _optional_ida_import("ida_expr"),
            "ida_fixup": _optional_ida_import("ida_fixup"),
            "ida_fpro": _optional_ida_import("ida_fpro"),
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_gdl": _optional_ida_import("ida_gdl"),
            "ida_graph": _optional_ida_import("ida_graph"),
            "ida_hexrays": ida_hexrays,
            "ida_ida": ida_ida,
            "ida_idd": _optional_ida_import("ida_idd"),
            "ida_idp": _optional_ida_import("ida_idp"),
            "ida_ieee": _optional_ida_import("ida_ieee"),
            "ida_kernwin": ida_kernwin,
            "ida_libfuncs": _optional_ida_import("ida_libfuncs"),
            "ida_lines": ida_lines,
            "ida_loader": _optional_ida_import("ida_loader"),
            "ida_merge": _optional_ida_import("ida_merge"),
            "ida_mergemod": _optional_ida_import("ida_mergemod"),
            "ida_moves": _optional_ida_import("ida_moves"),
            "ida_nalt": ida_nalt,
            "ida_name": ida_name,
            "ida_netnode": _optional_ida_import("ida_netnode"),
            "ida_offset": _optional_ida_import("ida_offset"),
            "ida_pro": _optional_ida_import("ida_pro"),
            "ida_problems": _optional_ida_import("ida_problems"),
            "ida_range": _optional_ida_import("ida_range"),
            "ida_regfinder": _optional_ida_import("ida_regfinder"),
            "ida_registry": _optional_ida_import("ida_registry"),
            "ida_search": _optional_ida_import("ida_search"),
            "ida_segment": ida_segment,
            "ida_segregs": _optional_ida_import("ida_segregs"),
            "ida_srclang": _optional_ida_import("ida_srclang"),
            "ida_strlist": _optional_ida_import("ida_strlist"),
            "ida_struct": _optional_ida_import("ida_struct"),
            "ida_tryblks": _optional_ida_import("ida_tryblks"),
            "ida_typeinf": ida_typeinf,
            "ida_ua": _optional_ida_import("ida_ua"),
            "ida_undo": _optional_ida_import("ida_undo"),
            "ida_xref": ida_xref,
            "ida_enum": _optional_ida_import("ida_enum"),
            "parse_address": parse_address,
            "get_function": get_function,
        }

        result_value = None

        # Try evaluation first (for simple expressions)
        try:
            result_value = str(eval(code, exec_globals))
        except Exception:
            # Execute as statements
            exec_locals = {}
            exec(code, exec_globals, exec_locals)

            # Merge locals into globals for multi-statement blocks
            exec_globals.update(exec_locals)

            # Try to eval the last line as an expression (Jupyter-style)
            lines = code.strip().split("\n")
            if lines:
                last_line = lines[-1].strip()
                if last_line and not last_line.startswith(
                    (
                        "#",
                        "import ",
                        "from ",
                        "def ",
                        "class ",
                        "if ",
                        "for ",
                        "while ",
                        "with ",
                        "try:",
                    )
                ):
                    try:
                        result_value = str(eval(last_line, exec_globals))
                    except Exception:
                        pass

            # Return 'result' variable if explicitly set
            if result_value is None and "result" in exec_locals:
                result_value = str(exec_locals["result"])

            # Return last assigned variable
            if result_value is None and exec_locals:
                last_key = list(exec_locals.keys())[-1]
                result_value = str(exec_locals[last_key])

        # Collect output
        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": result_value or "",
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        import traceback

        return {
            "result": "",
            "stdout": "",
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


@tool
@idasync
@unsafe
def py_exec_file(
    file_path: Annotated[str, "Absolute path to a Python script to execute"],
) -> dict:
    """Execute a Python script file in IDA context.

    This unsafe tool uses defense-in-depth restrictions but is not a process
    security sandbox.
    """
    if not os.path.isfile(file_path):
        return {"result": "", "stdout": "", "stderr": f"File not found: {file_path}"}

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        exec_globals = _make_restricted_exec_globals()
        exec_globals["__file__"] = file_path
        exec_globals["__name__"] = "__main__"
        exec_globals["__package__"] = None

        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        _validate_restricted_python(code, filename=file_path)
        exec(compile(code, file_path, "exec"), exec_globals)

        result_value = ""
        if "result" in exec_globals and exec_globals["result"] is not None:
            result_value = str(exec_globals["result"])

        return {
            "result": result_value,
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
        }
    except Exception:
        import traceback

        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
