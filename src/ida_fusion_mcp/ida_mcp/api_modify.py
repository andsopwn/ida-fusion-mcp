from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import idc
import ida_bytes
import ida_dirtree
import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import ida_ua

from .rpc import tool
from .sync import idasync, IDAError
from .api_core import invalidate_funcs_cache, invalidate_globals_cache
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    CommentOp,
    CommentAppendOp,
    AsmPatchOp,
    DefineOp,
    UndefineOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
)


class AppendCommentResult(TypedDict, total=False):
    addr: str
    scope: str
    appended: bool
    skipped: bool
    error: str


class DefineResult(TypedDict, total=False):
    addr: str
    ea: str
    start: str
    end: str
    size: int
    length: int
    error: str


class BookmarkResult(TypedDict, total=False):
    addr: str
    ea: str
    slot: int | None
    title: str
    prefix: str
    ok: bool
    error: str


# ============================================================================
# Modification Operations
# ============================================================================


_MAX_BATCH_SIZE = 500
_MAX_BOOKMARK_SLOTS = 1024
_BOOKMARK_PREFIX = "idaMCP: "


@tool
@idasync
def add_bookmark(
    addr: Annotated[str, "Address to bookmark"],
    name: Annotated[str, "Bookmark label text after the prefix"],
    prefix: Annotated[
        str,
        "Optional title prefix. Defaults to 'idaMCP: '; pass '' for no prefix.",
    ] = _BOOKMARK_PREFIX,
) -> BookmarkResult:
    """Add or replace the IDA bookmark at an address."""
    ea = parse_address(addr)
    title = f"{prefix}{name}"
    free_slot: int | None = None

    for slot in range(_MAX_BOOKMARK_SLOTS):
        slot_ea = idc.get_bookmark(slot)
        if slot_ea == idc.BADADDR:
            if free_slot is None:
                free_slot = slot
            continue
        if slot_ea == ea:
            free_slot = slot
            break

    if free_slot is None:
        return {
            "addr": addr,
            "ea": hex(ea),
            "slot": None,
            "title": title,
            "prefix": prefix,
            "ok": False,
            "error": "No free bookmark slot",
        }

    idc.put_bookmark(ea, 0, 0, 0, free_slot, title)
    return {
        "addr": addr,
        "ea": hex(ea),
        "slot": free_slot,
        "title": title,
        "prefix": prefix,
        "ok": True,
    }


@tool
@idasync
def set_comments(items: list[CommentOp] | CommentOp):
    """Set comments at addresses (both disassembly and decompiler views)"""
    if isinstance(items, dict):
        items = [items]

    # Security: limit batch size (each comment triggers decompilation)
    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")

        try:
            ea = parse_address(addr_str)

            if not idaapi.set_cmt(ea, comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue

            if not ida_hexrays.init_hexrays_plugin():
                results.append({"addr": addr_str, "ok": True})
                continue

            try:
                cfunc = decompile_checked(ea)
            except IDAError:
                results.append({"addr": addr_str, "ok": True})
                continue

            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
                results.append({"addr": addr_str, "ok": True})
                continue

            eamap = cfunc.get_eamap()
            if ea not in eamap:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea

            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    results.append({"addr": addr_str, "ok": True})
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
def patch_asm(items: list[AsmPatchOp] | AsmPatchOp) -> list[dict]:
    """Patch assembly instructions at addresses"""
    if isinstance(items, dict):
        items = [items]

    # Security: limit batch size
    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        instructions = item.get("asm", "")

        try:
            ea = parse_address(addr_str)
            assembles = instructions.split(";")
            for assemble in assembles:
                assemble = assemble.strip()
                try:
                    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
                    if not check_assemble:
                        results.append(
                            {
                                "addr": addr_str,
                                "error": f"Failed to assemble: {assemble}",
                            }
                        )
                        break
                    ida_bytes.patch_bytes(ea, bytes_to_patch)
                    ea += len(bytes_to_patch)
                except Exception as e:
                    results.append(
                        {"addr": addr_str, "error": f"Failed at {hex(ea)}: {e}"}
                    )
                    break
            else:
                results.append({"addr": addr_str, "ok": True})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
def rename(batch: RenameBatch) -> dict:
    """Unified rename operation for functions, globals, locals, and stack variables"""

    def _normalize_items(items):
        """Convert single item or None to list"""
        if items is None:
            return []
        return [items] if isinstance(items, dict) else items

    # Security: limit total rename operations across all categories
    total_items = sum(
        len(_normalize_items(batch.get(cat)))
        for cat in ("func", "data", "local", "stack")
    )
    if total_items > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: {total_items} total renames exceeds maximum of {_MAX_BATCH_SIZE}")

    def _has_user_name(ea: int) -> bool:
        flags = idaapi.get_flags(ea)
        checker = getattr(idaapi, "has_user_name", None)
        if checker is not None:
            return checker(flags)
        try:
            import ida_name

            checker = getattr(ida_name, "has_user_name", None)
            if checker is not None:
                return checker(flags)
        except Exception:
            pass
        return False

    def _place_func_in_vibe_dir(ea: int) -> tuple[bool, str | None]:
        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        if tree is None:
            return False, "Function dirtree not available"

        if not tree.load():
            return False, "Failed to load function dirtree"

        vibe_path = "/vibe/"
        if not tree.isdir(vibe_path):
            err = tree.mkdir(vibe_path)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"mkdir failed: {err}"

        old_cwd = tree.getcwd()
        try:
            if tree.chdir(vibe_path) != ida_dirtree.DTE_OK:
                return False, "Failed to chdir to vibe"
            err = tree.link(ea)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"link failed: {err}"
            if not tree.save():
                return False, "Failed to save function dirtree"
        finally:
            if old_cwd:
                tree.chdir(old_cwd)

        return True, None

    def _rename_funcs(items: list[FunctionRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = parse_address(item["addr"])
                had_user_name = _has_user_name(ea)
                success = idaapi.set_name(ea, item["name"], idaapi.SN_CHECK)
                if success:
                    func = idaapi.get_func(ea)
                    if func:
                        refresh_decompiler_ctext(func.start_ea)
                    if not had_user_name and func:
                        placed, place_error = _place_func_in_vibe_dir(func.start_ea)
                    else:
                        placed, place_error = None, None
                results.append(
                    {
                        "addr": item["addr"],
                        "name": item["name"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                        "dir": "vibe" if success and placed else None,
                        "dir_error": place_error if success else None,
                    }
                )
            except Exception as e:
                results.append({"addr": item.get("addr"), "error": str(e)})
        return results

    def _rename_globals(items: list[GlobalRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, item["old"])
                if ea == idaapi.BADADDR:
                    results.append(
                        {
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"Global '{item['old']}' not found",
                        }
                    )
                    continue
                success = idaapi.set_name(ea, item["new"], idaapi.SN_CHECK)
                results.append(
                    {
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"old": item.get("old"), "error": str(e)})
        return results

    def _rename_locals(items: list[LocalRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                func = idaapi.get_func(parse_address(item["func_addr"]))
                if not func:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "No function found",
                        }
                    )
                    continue
                success = ida_hexrays.rename_lvar(
                    func.start_ea, item["old"], item["new"]
                )
                if success:
                    refresh_decompiler_ctext(func.start_ea)
                results.append(
                    {
                        "func_addr": item["func_addr"],
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
        return results

    def _rename_stack(items: list[StackRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                func = idaapi.get_func(parse_address(item["func_addr"]))
                if not func:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "No function found",
                        }
                    )
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "No frame",
                        }
                    )
                    continue

                idx, udm = frame_tif.get_udm(item["old"])
                if not udm:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"'{item['old']}' not found",
                        }
                    )
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Special frame member",
                        }
                    )
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Argument member",
                        }
                    )
                    continue

                sval = ida_frame.soff_to_fpoff(func, offset)
                success = ida_frame.define_stkvar(func, item["new"], sval, udm.type)
                results.append(
                    {
                        "func_addr": item["func_addr"],
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
        return results

    # Process each category
    result = {}
    if "func" in batch:
        result["func"] = _rename_funcs(_normalize_items(batch["func"]))
        invalidate_funcs_cache()
    if "data" in batch:
        result["data"] = _rename_globals(_normalize_items(batch["data"]))
        invalidate_globals_cache()
    if "local" in batch:
        result["local"] = _rename_locals(_normalize_items(batch["local"]))
    if "stack" in batch:
        result["stack"] = _rename_stack(_normalize_items(batch["stack"]))

    return result


# ============================================================================
# Append-style Comment (non-destructive)
# ============================================================================


def _append_comment_text(current: str, new_text: str, *, dedupe: bool) -> tuple[str, bool]:
    """Merge new_text into current. Returns (merged_text, skipped_as_duplicate)."""
    normalized_new = new_text.strip()
    if dedupe and normalized_new:
        existing_entries = [line.strip() for line in current.splitlines()]
        if normalized_new in existing_entries:
            return current, True
    if not current:
        return new_text, False
    if not new_text:
        return current, False
    joiner = "" if current.endswith("\n") else "\n"
    return f"{current}{joiner}{new_text}", False


@tool
@idasync
def append_comments(
    items: list[CommentAppendOp] | CommentAppendOp,
) -> list[AppendCommentResult]:
    """Append comments at addresses, deduping exact text by default. Unlike
    set_comments (which overwrites), this preserves existing annotations — use
    it for incremental commentary. scope='auto' (default) writes a function
    comment when addr is a function start, otherwise a line comment; force
    with scope='func' or 'line'. dedupe=True skips writes when the exact
    stripped text already appears on its own line."""
    if isinstance(items, dict):
        items = [items]

    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results: list[AppendCommentResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")
        scope = str(item.get("scope", "auto") or "auto").lower()
        dedupe = bool(item.get("dedupe", True))

        try:
            ea = parse_address(addr_str)
            if scope not in {"auto", "func", "line"}:
                results.append({"addr": addr_str, "error": f"Unsupported scope: {scope}"})
                continue

            fn = idaapi.get_func(ea)
            use_func_comment = scope == "func" or (
                scope == "auto" and fn is not None and fn.start_ea == ea
            )

            if use_func_comment:
                if fn is None:
                    results.append({"addr": addr_str, "error": f"No function found at {hex(ea)}"})
                    continue
                target_ea = fn.start_ea
                current = idc.get_func_cmt(target_ea, False) or ""
                new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
                if skipped:
                    results.append({"addr": addr_str, "scope": "func", "skipped": True})
                    continue
                if not idc.set_func_cmt(target_ea, new_comment, False):
                    results.append({
                        "addr": addr_str,
                        "error": f"Failed to set function comment at {hex(target_ea)}",
                    })
                    continue
                results.append({"addr": addr_str, "scope": "func", "appended": True})
                continue

            current = idaapi.get_cmt(ea, False) or ""
            new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
            if skipped:
                results.append({"addr": addr_str, "scope": "line", "skipped": True})
                continue
            if not idaapi.set_cmt(ea, new_comment, False):
                results.append({
                    "addr": addr_str,
                    "error": f"Failed to set disassembly comment at {hex(ea)}",
                })
                continue
            results.append({"addr": addr_str, "scope": "line", "appended": True})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


# ============================================================================
# Code / Function Definition & Undefinition
# ============================================================================


# Cap on the number of bytes a single undefine call may affect. Prevents a
# stray `end` address or oversized `size` from wiping large regions of the
# IDB. Mirrors this project's 1 MB memory read/write caps in spirit.
_MAX_UNDEFINE_BYTES = 16 * 1024 * 1024


@tool
@idasync
def define_func(items: list[DefineOp] | DefineOp) -> list[DefineResult]:
    """Define a function at each given address. IDA infers bounds unless an
    explicit end address is provided. Returns {addr, start, end} on success or
    {addr, start, error} if the function already exists or add_func fails.
    Use this when IDA auto-analysis missed a function entry point."""
    if isinstance(items, dict):
        items = [items]

    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results: list[DefineResult] = []
    had_success = False
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")

        try:
            start_ea = parse_address(addr_str)
            if not idaapi.is_loaded(start_ea):
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": f"Address {hex(start_ea)} is not mapped in the IDB",
                })
                continue
            end_ea = parse_address(end_str) if end_str else idaapi.BADADDR

            if end_ea != idaapi.BADADDR and end_ea <= start_ea:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "end": hex(end_ea),
                    "error": f"Invalid range: end ({hex(end_ea)}) must be greater than start ({hex(start_ea)})",
                })
                continue

            existing = idaapi.get_func(start_ea)
            if existing and existing.start_ea == start_ea:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": "Function already exists at this address",
                })
                continue
            if existing and existing.start_ea != start_ea:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": (
                        f"Address {hex(start_ea)} is inside function at "
                        f"{hex(existing.start_ea)}; cannot start a new function here"
                    ),
                })
                continue

            if ida_funcs.add_func(start_ea, end_ea):
                func = idaapi.get_func(start_ea)
                had_success = True
                results.append({
                    "addr": addr_str,
                    "start": hex(func.start_ea),
                    "end": hex(func.end_ea),
                })
            else:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": "define_func failed",
                })
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    if had_success:
        invalidate_funcs_cache()
        invalidate_globals_cache()

    return results


@tool
@idasync
def define_code(items: list[DefineOp] | DefineOp) -> list[DefineResult]:
    """Convert raw bytes to a code instruction at each given address. Returns
    {addr, ea, length} on success (length is the instruction byte length) or
    {addr, ea, error} if create_insn failed. Use this when IDA classified an
    instruction as data or failed to decode."""
    if isinstance(items, dict):
        items = [items]

    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results: list[DefineResult] = []
    for item in items:
        addr_str = item.get("addr", "")

        try:
            ea = parse_address(addr_str)
            if not idaapi.is_loaded(ea):
                results.append({
                    "addr": addr_str,
                    "ea": hex(ea),
                    "error": f"Address {hex(ea)} is not mapped in the IDB",
                })
                continue
            length = ida_ua.create_insn(ea)
            if length > 0:
                results.append({"addr": addr_str, "ea": hex(ea), "length": length})
            else:
                results.append({
                    "addr": addr_str,
                    "ea": hex(ea),
                    "error": "Failed to create instruction",
                })
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
def undefine(items: list[UndefineOp] | UndefineOp) -> list[DefineResult]:
    """Undefine item(s) at each address, converting them back to raw bytes.
    Size is determined from `end` (exclusive) or `size`; defaults to 1 byte.
    Uses ida_bytes.DELIT_EXPAND so adjacent items spanning into the range are
    fully removed. Returns {addr, start, size} on success."""
    if isinstance(items, dict):
        items = [items]

    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results: list[DefineResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")
        size = item.get("size", 0)

        try:
            start_ea = parse_address(addr_str)
            if not idaapi.is_loaded(start_ea):
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": f"Address {hex(start_ea)} is not mapped in the IDB",
                })
                continue

            if end_str:
                end_ea = parse_address(end_str)
                nbytes = end_ea - start_ea
            elif size:
                nbytes = size
            else:
                nbytes = 1

            if nbytes <= 0:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": f"Invalid range: {nbytes} bytes",
                })
                continue

            if nbytes > _MAX_UNDEFINE_BYTES:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": (
                        f"Range too large: {nbytes} bytes exceeds "
                        f"_MAX_UNDEFINE_BYTES ({_MAX_UNDEFINE_BYTES}). "
                        "Split into smaller undefine calls."
                    ),
                })
                continue

            if ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, nbytes):
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "size": nbytes,
                })
            else:
                results.append({
                    "addr": addr_str,
                    "start": hex(start_ea),
                    "error": "undefine failed",
                })
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


# ============================================================================
# Hex-Rays + operand-typing operations
# ============================================================================


class ForceRecompileOp(TypedDict, total=False):
    addr: str


class ForceRecompileResult(TypedDict, total=False):
    addr: str
    name: str
    ok: bool
    error: str


@tool
@idasync
def force_recompile(
    items: Annotated[
        list[ForceRecompileOp] | ForceRecompileOp | None,
        "List of {addr: function-entry-EA} ops, a single op, or omit/pass empty list to recompile every function.",
    ] = None,
) -> dict:
    """Invalidate the Hex-Rays decompile cache for one or more functions."""
    targets: list[int] = []
    invalidate_all = False

    if items is None:
        invalidate_all = True
    elif isinstance(items, dict):
        items = [items]
    elif isinstance(items, list) and len(items) == 0:
        invalidate_all = True

    if invalidate_all:
        targets = list(idautils.Functions())
    else:
        for item in items or []:
            addr_str = item.get("addr") if isinstance(item, dict) else None
            if not addr_str:
                continue
            try:
                ea = parse_address(addr_str)
                func = ida_funcs.get_func(ea)
                if func is not None:
                    targets.append(func.start_ea)
            except Exception:
                pass

    results: list[ForceRecompileResult] = []
    for ea in targets:
        try:
            ida_hexrays.mark_cfunc_dirty(ea)
            results.append({
                "addr": hex(ea),
                "name": ida_funcs.get_func_name(ea) or "",
                "ok": True,
            })
        except Exception as e:
            results.append({"addr": hex(ea), "ok": False, "error": str(e)})

    return {
        "summary": {
            "total": len(results),
            "ok": sum(1 for r in results if r.get("ok")),
            "failed": sum(1 for r in results if not r.get("ok")),
            "all": invalidate_all,
        },
        "results": results,
    }


class SetOpTypeOp(TypedDict, total=False):
    addr: str
    op_n: int
    kind: str
    struct: NotRequired[str]
    delta: NotRequired[int]
    target_addr: NotRequired[str]


class SetOpTypeResult(TypedDict, total=False):
    addr: str
    op_n: int
    kind: str
    ok: bool
    error: str


_OP_FORMAT_FLAGS = {
    "hex": ida_bytes.FF_0NUMH,
    "dec": ida_bytes.FF_0NUMD,
    "char": ida_bytes.FF_0CHAR,
    "binary": ida_bytes.FF_0NUMB,
    "octal": ida_bytes.FF_0NUMO,
}


@tool
@idasync
def set_op_type(
    items: Annotated[
        list[SetOpTypeOp] | SetOpTypeOp,
        "Operand-typing ops for struct offsets, plain offsets, stack vars, or numeric formats.",
    ],
) -> list[SetOpTypeResult]:
    """Set the interpretation of an instruction operand."""
    if isinstance(items, dict):
        items = [items]

    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results: list[SetOpTypeResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        op_n = int(item.get("op_n", 0))
        kind = str(item.get("kind", "")).strip().lower()

        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append({"addr": addr_str, "op_n": op_n, "kind": kind, "ok": False, "error": str(e)})
            continue

        ok = False
        err = None
        try:
            if kind == "stroff":
                struct_name = str(item.get("struct", "")).strip()
                if not struct_name:
                    err = "struct name required for kind='stroff'"
                else:
                    delta = int(item.get("delta", 0))
                    til = ida_typeinf.get_idati()
                    sti = ida_typeinf.tinfo_t()
                    if not sti.get_named_type(til, struct_name):
                        err = f"struct not found: {struct_name}"
                    else:
                        tid = sti.get_tid()
                        if tid == idaapi.BADADDR:
                            err = f"struct {struct_name} has no tid"
                        else:
                            path = idaapi.tid_array(1)
                            path[0] = tid
                            ok = bool(ida_bytes.op_stroff(ea, op_n, path.cast(), 1, delta))
            elif kind == "offset":
                target_str = str(item.get("target_addr", "")).strip()
                if target_str:
                    target_ea = parse_address(target_str)
                    ok = bool(idc.op_plain_offset(ea, op_n, target_ea))
                else:
                    ok = bool(idc.op_plain_offset(ea, op_n, 0))
            elif kind == "stkvar":
                ok = bool(idc.op_stkvar(ea, op_n))
            elif kind in _OP_FORMAT_FLAGS:
                ok = bool(ida_bytes.set_op_type(ea, _OP_FORMAT_FLAGS[kind], op_n))
            else:
                err = f"unknown kind: {kind!r} (expected stroff/offset/stkvar/hex/dec/char/binary/octal)"

            if ok:
                func = idaapi.get_func(ea)
                if func is not None:
                    ida_hexrays.mark_cfunc_dirty(func.start_ea)
        except Exception as e:
            err = str(e)

        result: SetOpTypeResult = {"addr": addr_str, "op_n": op_n, "kind": kind, "ok": ok}
        if err is not None and not ok:
            result["error"] = err
        results.append(result)

    return results


class MakeDataOp(TypedDict, total=False):
    addr: str
    type: str
    name: NotRequired[str]
    delete_existing: NotRequired[bool]


class MakeDataResult(TypedDict, total=False):
    addr: str
    name: str
    type: str
    size: int
    ok: bool
    error: str


@tool
@idasync
def make_data(
    items: Annotated[
        list[MakeDataOp] | MakeDataOp,
        "Data-creation ops. Each {addr, type, name?} applies a fresh typed data item.",
    ],
) -> list[MakeDataResult]:
    """Create a typed data symbol at an address, replacing prior items by default."""
    if isinstance(items, dict):
        items = [items]

    if len(items) > _MAX_BATCH_SIZE:
        raise IDAError(f"Batch too large: maximum {_MAX_BATCH_SIZE} items per request")

    results: list[MakeDataResult] = []
    had_success = False
    for item in items:
        addr_str = item.get("addr", "")
        type_decl = str(item.get("type", "")).strip()
        name = str(item.get("name", "")).strip()
        delete_existing = bool(item.get("delete_existing", True))

        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})
            continue

        if not type_decl:
            results.append({"addr": addr_str, "ok": False, "error": "type declaration is required"})
            continue

        decl = type_decl if type_decl.endswith(";") else type_decl + ";"

        try:
            apply_ok = idc.SetType(ea, decl)
            if not apply_ok:
                results.append({"addr": addr_str, "ok": False, "error": f"SetType rejected declaration: {decl!r}"})
                continue

            tif = ida_typeinf.tinfo_t()
            try:
                ok_t = ida_typeinf.guess_tinfo(tif, ea)
            except Exception:
                ok_t = False
            size = tif.get_size() if ok_t else 0

            if delete_existing and size > 0:
                ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size)
                idc.SetType(ea, decl)

            if name:
                ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)

            ida_hexrays.clear_cached_cfuncs()
            had_success = True
            results.append({
                "addr": addr_str,
                "name": name or (ida_name.get_name(ea) or ""),
                "type": idc.get_type(ea) or "",
                "size": size,
                "ok": True,
            })
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    if had_success:
        invalidate_globals_cache()

    return results
