"""idalib management tools — exposed through the router MCP server.

These four tools let MCP clients open/close/list/inspect headless idalib
sessions.  Each session is a subprocess managed by :class:`IdalibManager`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..idalib_manager import IdalibManager

_manager: IdalibManager | None = None


def set_manager(manager: IdalibManager) -> None:
    """Inject the :class:`IdalibManager` instance (called by server.py on startup)."""
    global _manager
    _manager = manager


def _get_manager() -> IdalibManager:
    if _manager is None:
        raise RuntimeError("IdalibManager not initialized")
    return _manager


def _bool_arg(arguments: dict, name: str, default: bool) -> bool:
    value = arguments.get(name, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return bool(value)


def _optional_int_arg(arguments: dict, name: str) -> int | None:
    value = arguments.get(name)
    if value is None or value == "":
        return None
    return int(value)


# ------------------------------------------------------------------
# Tool functions (called from custom_tools_call in server.py)
# ------------------------------------------------------------------


def idalib_open(arguments: dict) -> dict:
    """Open a binary in a new headless idalib session.

    Required args:
        input_path (str): Path to the binary or IDB file.
    Optional args:
        timeout (int): Seconds to wait for analysis (default 120).
        unsafe (bool): Enable unsafe tools (default false).
        mode (str): prefer_headless|force_headless|prefer_gui|force_gui.
        preferred_instance_id (str): Reuse this registry instance if reachable.
        idle_ttl_sec (int): Stop owned headless worker after idle seconds.
        run_auto_analysis (bool): Run/wait for auto-analysis in headless worker.
        build_caches (bool): Build startup caches in headless worker.
        init_hexrays (bool): Initialize Hex-Rays in headless worker.
    """
    mgr = _get_manager()
    input_path = arguments.get("input_path", "")
    if not input_path:
        return {"error": "Missing required argument 'input_path'"}
    timeout = int(arguments.get("timeout", 120))
    unsafe = _bool_arg(arguments, "unsafe", False)
    mode = str(arguments.get("mode", "prefer_headless") or "prefer_headless")
    preferred_instance_id = arguments.get("preferred_instance_id") or None
    idle_ttl_sec = _optional_int_arg(arguments, "idle_ttl_sec")
    run_auto_analysis = _bool_arg(arguments, "run_auto_analysis", True)
    build_caches = _bool_arg(arguments, "build_caches", True)
    init_hexrays = _bool_arg(arguments, "init_hexrays", True)
    return mgr.spawn_session(
        input_path,
        timeout=timeout,
        unsafe=unsafe,
        mode=mode,
        preferred_instance_id=preferred_instance_id,
        idle_ttl_sec=idle_ttl_sec,
        run_auto_analysis=run_auto_analysis,
        build_caches=build_caches,
        init_hexrays=init_hexrays,
    )


def idalib_close(arguments: dict) -> dict:
    """Close a headless idalib session and terminate its worker process.

    Required args:
        instance_id (str): Instance ID of the idalib session.
    """
    mgr = _get_manager()
    instance_id = arguments.get("instance_id", "")
    if not instance_id:
        return {"error": "Missing required argument 'instance_id'"}
    return mgr.close_session(instance_id)


def idalib_list(arguments: dict) -> dict:
    """List all managed idalib sessions."""
    mgr = _get_manager()
    sessions = mgr.list_sessions()
    return {"count": len(sessions), "sessions": sessions}


def idalib_status(arguments: dict) -> dict:
    """Health / readiness check for a specific idalib session.

    Required args:
        instance_id (str): Instance ID to check.
    """
    mgr = _get_manager()
    instance_id = arguments.get("instance_id", "")
    if not instance_id:
        return {"error": "Missing required argument 'instance_id'"}
    return mgr.get_status(instance_id)


# ------------------------------------------------------------------
# Tool schemas (registered in server._refresh_tools)
# ------------------------------------------------------------------

IDALIB_TOOL_SCHEMAS: list[dict] = [
    {
        "name": "idalib_open",
        "description": (
            "Open a binary through the router-native IDA registry. "
            "By default this starts or reuses a headless idalib worker, but "
            "mode='prefer_gui'/'force_gui' can reuse an already registered GUI "
            "IDA instance for the same binary. Use list_instances() to see the "
            "resulting instance_id. Requires idapro Python package for headless mode."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": "Path to the binary or IDB file to open",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Seconds to wait for analysis to complete (default 120)",
                },
                "unsafe": {
                    "type": "boolean",
                    "description": "Enable unsafe/destructive tools (default false)",
                },
                "mode": {
                    "type": "string",
                    "enum": ["prefer_headless", "force_headless", "prefer_gui", "force_gui"],
                    "description": "Routing mode. force_gui never launches headless; prefer_gui falls back to headless.",
                },
                "preferred_instance_id": {
                    "type": "string",
                    "description": "Reuse this registry instance if it is reachable and compatible with mode.",
                },
                "idle_ttl_sec": {
                    "type": "integer",
                    "description": "Owned headless worker exits after this many idle seconds (0/omitted disables).",
                },
                "run_auto_analysis": {
                    "type": "boolean",
                    "description": "Run and wait for auto-analysis in the headless worker (default true)",
                },
                "build_caches": {
                    "type": "boolean",
                    "description": "Build strings/functions/globals caches during headless startup (default true)",
                },
                "init_hexrays": {
                    "type": "boolean",
                    "description": "Initialize Hex-Rays in the headless worker during startup (default true)",
                },
            },
            "required": ["input_path"],
        },
    },
    {
        "name": "idalib_close",
        "description": (
            "Close a headless idalib session and terminate its worker process. "
            "The instance is removed from the registry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID of the idalib session to close",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "idalib_list",
        "description": "List all managed headless idalib sessions with pid, port, and binary info.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "idalib_status",
        "description": (
            "Health and readiness check for a specific idalib session. "
            "Reports whether the worker process is alive and reachable via HTTP."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID of the idalib session to check",
                },
            },
            "required": ["instance_id"],
        },
    },
]
