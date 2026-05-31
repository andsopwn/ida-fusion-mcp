"""IDA SDK version compatibility shims.

Provides unified wrappers for APIs that moved between IDA 8.3 and 9.3.
Import from this module instead of from version-specific ``ida_*`` modules.

Known migrations:
- Entry point functions (get_entry_qty, get_entry_ordinal, get_entry,
  get_entry_name): ida_nalt (8.x) → ida_entry (9.0+, exclusive in 9.3+).
- inf_is_64bit: idaapi (8.x) → ida_ida (9.0+).
"""

from __future__ import annotations

import idaapi
import ida_typeinf

# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

_kernel_version = idaapi.get_kernel_version()  # e.g. "9.3"
_major, _minor = (int(x) for x in _kernel_version.split(".")[:2])


# ---------------------------------------------------------------------------
# Entry point API (ida_nalt in 8.x, ida_entry in 9.x)
# ---------------------------------------------------------------------------

try:
    import ida_entry as _entry_mod
    if not hasattr(_entry_mod, "get_entry_qty"):
        raise ImportError
except ImportError:
    import ida_nalt as _entry_mod  # type: ignore[no-redef]


def get_entry_qty() -> int:
    return _entry_mod.get_entry_qty()


def get_entry_ordinal(index: int) -> int:
    return _entry_mod.get_entry_ordinal(index)


def get_entry(ordinal: int) -> int:
    return _entry_mod.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str:
    return _entry_mod.get_entry_name(ordinal)


# ---------------------------------------------------------------------------
# inf_is_64bit (idaapi in 8.x, ida_ida in 9.x)
# ---------------------------------------------------------------------------

try:
    import ida_ida
    if hasattr(ida_ida, "inf_is_64bit"):
        def inf_is_64bit() -> bool:
            return ida_ida.inf_is_64bit()
    else:
        raise AttributeError
except (ImportError, AttributeError):
    def inf_is_64bit() -> bool:  # type: ignore[misc]
        return idaapi.inf_is_64bit()


# ---------------------------------------------------------------------------
# tinfo_t.get_udm (missing in some older/early IDA builds)
# ---------------------------------------------------------------------------

def tinfo_get_udm(
    tif: ida_typeinf.tinfo_t, name: str
) -> tuple[int, ida_typeinf.udm_t | None]:
    if hasattr(tif, "get_udm"):
        return tif.get_udm(name)

    idx = tif.find_udm(name)
    if idx == -1:
        return -1, None

    udm = ida_typeinf.udm_t()
    tid = tif.get_udm_tid(idx)
    tif.get_udm_by_tid(udm, tid)
    if udm.name:
        return idx, udm
    return -1, None
