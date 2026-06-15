"""Core API Functions - IDB metadata and basic queries"""

import re
import time
from typing import Annotated, Any, Optional

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_loader
import idaapi
import idautils
import ida_nalt
import ida_typeinf
import ida_segment
import idc

from .rpc import tool
from .sync import idasync, tool_timeout, get_tool_deadline

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None

# Cached function list: [Function(...), ...]
_funcs_cache: list["Function"] | None = None

# Cached globals list: [Global(...), ...]
_globals_cache: list["Global"] | None = None


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def _get_funcs_cache() -> list["Function"]:
    """Get cached function list, building cache on first access."""
    global _funcs_cache
    if _funcs_cache is None:
        _funcs_cache = [get_function(addr) for addr in idautils.Functions()]
    return _funcs_cache


def invalidate_funcs_cache():
    """Clear the function cache (call after function changes)."""
    global _funcs_cache
    _funcs_cache = None


def _get_globals_cache() -> list["Global"]:
    """Get cached globals list, building cache on first access."""
    global _globals_cache
    if _globals_cache is None:
        _globals_cache = []
        for addr, name in idautils.Names():
            if not idaapi.get_func(addr) and name is not None:
                _globals_cache.append(Global(addr=hex(addr), name=name))
    return _globals_cache


def invalidate_globals_cache():
    """Clear the globals cache (call after data changes)."""
    global _globals_cache
    _globals_cache = None


def init_caches():
    """Build caches on plugin startup."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1-t0)*1000:.0f}ms")

    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    print(f"[MCP] Cached {len(funcs)} functions in {(t2-t1)*1000:.0f}ms")

    globals_ = _get_globals_cache()
    t3 = time.perf_counter()
    print(f"[MCP] Cached {len(globals_)} globals in {(t3-t2)*1000:.0f}ms")


@tool
@idasync
@tool_timeout(120.0)
def refresh_caches() -> dict:
    """Force-refresh all caches (strings, functions, globals)."""
    invalidate_strings_cache()
    invalidate_funcs_cache()
    invalidate_globals_cache()

    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    globals_ = _get_globals_cache()
    t3 = time.perf_counter()

    return {
        "strings": len(strings),
        "functions": len(funcs),
        "globals": len(globals_),
        "time_ms": round((t3 - t0) * 1000),
    }


from .utils import (
    Metadata,
    Function,
    ConvertedNumber,
    Global,
    Import,
    String,
    Segment,
    Page,
    EntityQuery,
    NumberConversion,
    ListQuery,
    get_image_size,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    paginate,
    pattern_filter,
)
from .sync import IDAError


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_functions = _get_funcs_cache()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals = _get_globals_cache()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings with case-insensitive regex patterns"""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    # Security: limit regex pattern length to prevent ReDoS
    if len(pattern) > 500:
        from .sync import IDAError
        raise IDAError("Regex pattern too long: maximum 500 characters")

    matches = []
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        from .sync import IDAError
        raise IDAError(f"Invalid regex pattern: {e}")
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


# ============================================================================
# Server Health & Warmup
# ============================================================================


_SERVER_START_TIME = time.time()


def _build_health_payload() -> dict:
    """Build health/readiness snapshot."""
    path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
    module = ida_nalt.get_root_filename() or ""
    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _SERVER_START_TIME, 1),
        "idb_path": path,
        "module": module,
        "auto_analysis_ready": not ida_auto.auto_is_ok(),
        "hexrays_ready": bool(ida_hexrays.init_hexrays_plugin()),
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache else 0,
    }


@tool
@idasync
def server_health() -> dict:
    """Health/ready probe for MCP server and current IDB state. Returns
    uptime, IDB path, auto-analysis status, Hex-Rays availability, and
    strings cache state."""
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> dict:
    """Warm up IDA subsystems to reduce first-call latency. Call after
    connecting to a new instance to ensure analysis is complete and caches
    are populated before running tools."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append({"step": "auto_wait", "ok": True,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append({"step": "init_caches", "ok": True,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step: dict = {"step": "init_hexrays", "ok": ok,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)}
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(s.get("ok")) for s in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


# ============================================================================
# Rich Queries
# ============================================================================


def _collect_imports() -> list[dict]:
    """Collect all imports into a flat list for filtering."""
    rv: list[dict] = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
        collected: list[tuple[int, str]] = []

        def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
            name = symbol_name if symbol_name else f"#{ordinal}"
            collected.append((ea, name))
            return True

        ida_nalt.enum_import_names(i, imp_cb)
        for ea, name in collected:
            rv.append({"addr": hex(ea), "imported_name": name, "module": module_name})
    return rv


def _coerce_sort_number(value, default: int = 0) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _segment_name_for_ea(ea: int) -> str | None:
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        return ida_segment.get_segm_name(seg)
    except Exception:
        try:
            return idaapi.get_segm_name(seg)
        except Exception:
            return None


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append({
                "kind": "function",
                "addr": hex(fn.start_ea),
                "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                "size": hex(size_int),
                "size_int": size_int,
                "segment": _segment_name_for_ea(fn.start_ea),
                "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
            })
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append({
                "kind": "global",
                "addr": hex(ea),
                "name": name,
                "size": idc.get_item_size(ea),
                "segment": _segment_name_for_ea(ea),
            })
        return rows

    if kind == "imports":
        return [
            {
                "kind": "import",
                "addr": imp["addr"],
                "name": imp["imported_name"],
                "module": imp["module"],
            }
            for imp in _collect_imports()
        ]

    if kind == "strings":
        return [
            {
                "kind": "string",
                "addr": hex(ea),
                "text": text,
                "length": len(text),
                "segment": _segment_name_for_ea(ea),
            }
            for ea, text in _get_strings_cache()
        ]

    if kind == "names":
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        rows = []
        for ea, name in idautils.Names():
            rows.append({
                "kind": "name",
                "addr": hex(ea),
                "name": name,
                "segment": _segment_name_for_ea(ea),
                "is_function": bool(idaapi.get_func(ea)),
                "is_import": ea in imports_by_ea,
            })
        return rows

    return []


def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add("kind")
    return [{k: v for k, v in item.items() if k in keep} for item in items]


@tool
@idasync
def func_query(
    queries: Annotated[list[dict] | dict,
        "Function query: filter, name_regex, min_size, max_size, has_type, sort_by, descending, offset, count"],
) -> list[dict]:
    """Query functions with richer filtering than list_funcs. Supports regex
    name filter, size range, type filter, sort by size/name/addr, and pagination.
    Example: {name_regex: 'crypt', min_size: 100, sort_by: 'size', descending: true}"""
    queries = normalize_dict_list(queries)

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea))
        all_functions.append({
            "addr": hex(fn.start_ea), "name": fn_name,
            "size": hex(size_int), "size_int": size_int, "has_type": has_type,
        })

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            try:
                compiled = re.compile(name_regex)
                filtered = [f for f in filtered if compiled.search(f["name"])]
            except re.error:
                pass

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]
        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            filtered = [f for f in filtered if f["has_type"] is bool(query["has_type"])]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[dict]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(queries)
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        if kind not in {"functions", "globals", "imports", "strings", "names"}:
            results.append({
                "kind": kind,
                "data": [],
                "next_offset": None,
                "total": 0,
                "error": f"Unsupported kind: {kind}",
            })
            continue

        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error:
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                rows = []

        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: row.get("size_int", _coerce_sort_number(row.get(sort_by, 0))),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)

        results.append({
            "kind": kind,
            "data": data,
            "next_offset": page["next_offset"],
            "total": len(rows),
            "error": None,
        })

    return results


@tool
@idasync
def imports_query(
    queries: Annotated[list[dict] | dict,
        "Import query: filter (import name pattern), module (module name pattern), offset, count"],
) -> list[dict]:
    """Query imports with module and name filters. Example:
    {module: 'kernel32', filter: '*File*'} to find all kernel32 file I/O imports."""
    queries = normalize_dict_list(queries)
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(paginate(filtered, query.get("offset", 0), query.get("count", 100)))

    return results


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> dict:
    """Save active IDB to disk. Call after renaming, retyping, or commenting
    to persist changes. Optionally specify a custom output path."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        ok = bool(ida_loader.save_database(save_path, 0))
        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}


_COMMENT_SCOLORS = (
    ida_lines.SCOLOR_REGCMT,
    ida_lines.SCOLOR_RPTCMT,
    ida_lines.SCOLOR_AUTOCMT,
    ida_lines.SCOLOR_COLLAPSED,
)


def _line_is_comment(tagged: str) -> bool:
    if not tagged:
        return False
    for sc in _COMMENT_SCOLORS:
        if ida_lines.COLOR_ON + sc in tagged:
            return True
    return False


def _classify_hit_lines(
    ea: int,
    matcher,
    want_disasm: bool,
    want_comments: bool,
    max_lines: int = 32,
) -> list[dict]:
    out: list[dict] = []
    try:
        result = ida_lines.generate_disassembly(ea, max_lines, False, False)
    except Exception:
        return out
    lines = None
    if isinstance(result, tuple):
        for item in result:
            if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                lines = list(item)
                break
    if lines is None:
        return out

    for tagged in lines:
        text = ida_lines.tag_remove(tagged) or ""
        if not text or not matcher(text):
            continue
        kind = "comment" if _line_is_comment(tagged) else "disasm"
        if kind == "disasm" and not want_disasm:
            continue
        if kind == "comment" and not want_comments:
            continue
        out.append({"kind": kind, "text": text})
    return out


def _exec_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to search for in the rendered listing"],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Lower bound or cursor address. Empty = first segment."] = "",
    end: Annotated[str, "Upper bound (exclusive). Empty = last segment."] = "",
    regex: Annotated[bool, "Treat pattern as a regex"] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all'"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments"] = True,
) -> dict:
    """Search rendered listing text over [start, end).

    This walks IDA heads in bounded chunks instead of calling
    ida_search.find_text(), which can block inside a large segment without
    yielding to timeout or cancel handling.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    include = (include or "all").lower()
    if include not in ("disasm", "comments", "all"):
        return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid include: {include!r}"}

    want_disasm = include in ("disasm", "all")
    want_comments = include in ("comments", "all")

    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid regex: {e}"}
        matcher = lambda s: bool(rx.search(s))
    else:
        if case_sensitive:
            needle = pattern
            matcher = lambda s: needle in s
        else:
            needle = pattern.lower()
            matcher = lambda s: needle in s.lower()

    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    if start:
        try:
            start_ea = parse_address(start)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid start: {e}"}
    else:
        start_ea = segments[0][0]

    if end:
        try:
            end_ea = parse_address(end)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid end: {e}"}
    else:
        end_ea = segments[-1][1]

    if end_ea <= start_ea:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    hits: list[dict] = []
    next_cursor: int | None = None
    cancelled = False
    chunk_bytes = 65536
    deadline = get_tool_deadline()

    for seg_start, seg_end in segments:
        if cancelled or len(hits) >= limit:
            break
        if seg_end <= start_ea:
            continue
        if seg_start >= end_ea:
            break
        walk_start = max(seg_start, start_ea)
        walk_end = min(seg_end, end_ea)
        chunk_ea = walk_start
        while chunk_ea < walk_end:
            if cancelled or len(hits) >= limit:
                break
            if (
                deadline is not None and time.monotonic() >= deadline
            ) or ida_kernwin.user_cancelled():
                cancelled = True
                next_cursor = chunk_ea
                break
            chunk_end = min(chunk_ea + chunk_bytes, walk_end)
            for head_ea in idautils.Heads(chunk_ea, chunk_end):
                lines = _classify_hit_lines(head_ea, matcher, want_disasm, want_comments)
                if not lines:
                    continue
                entry = {"addr": hex(head_ea), "matches": lines}
                func = idaapi.get_func(head_ea)
                if func is not None:
                    fname = ida_funcs.get_func_name(func.start_ea)
                    if fname:
                        entry["function"] = fname
                seg = idaapi.getseg(head_ea)
                if seg is not None:
                    sname = ida_segment.get_segm_name(seg)
                    if sname:
                        entry["segment"] = sname
                hits.append(entry)
                if len(hits) >= limit:
                    size = max(1, idaapi.get_item_size(head_ea))
                    next_cursor = head_ea + size
                    break
            chunk_ea = chunk_end

    cursor: dict[str, Any]
    if cancelled:
        cursor = {"next": hex(next_cursor) if next_cursor is not None else "", "cancelled": True}
    elif next_cursor is not None:
        cursor = {"next": hex(next_cursor)}
    else:
        cursor = {"done": True}

    return {"n": len(hits), "hits": hits, "cursor": cursor}
