"""idalib subprocess lifecycle manager.

Spawns, monitors, and terminates headless idalib worker processes.
Each worker opens one binary and listens on a unique localhost port.
Does NOT depend on ``idapro`` — purely manages subprocesses.
"""

from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Any

from .health import is_process_alive, ping_instance, query_binary_metadata

if TYPE_CHECKING:
    from .registry import InstanceRegistry

# Default timeout (seconds) waiting for worker to become ready.
_READY_TIMEOUT = 120
# Poll interval while waiting for worker readiness.
_READY_POLL_INTERVAL = 0.5

# idalib library file name per platform.
_IDALIB_NAMES = {
    "win32": "idalib.dll",
    "darwin": "libidalib.dylib",
    "linux": "libidalib.so",
}
_DEFAULT_MAX_OWNED_WORKERS = 4
_OPEN_MODES = frozenset({"prefer_headless", "force_headless", "prefer_gui", "force_gui"})


def is_idalib_available() -> bool:
    """Check whether the detected IDA installation includes idalib (Pro only).

    Returns True if idalib.dll / libidalib.* exists in the IDA directory
    resolved from IDADIR or ida-config.json.
    """
    ida_dir = _resolve_ida_dir()
    if not ida_dir:
        return False
    lib_name = _IDALIB_NAMES.get(sys.platform, "libidalib.so")
    return os.path.isfile(os.path.join(ida_dir, lib_name))


def _resolve_ida_dir() -> str | None:
    """Resolve IDA dir from IDADIR env or ida-config.json (no filesystem scan)."""
    env_dir = os.environ.get("IDADIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        return env_dir
    # ida-config.json
    if sys.platform == "win32":
        cfg_path = os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "ida-config.json")
    else:
        cfg_path = os.path.join(os.path.expanduser("~"), ".idapro", "ida-config.json")
    try:
        import json
        with open(cfg_path, "r") as f:
            cfg = json.load(f)
        d = cfg.get("Paths", {}).get("ida-install-dir", "").strip()
        if d and os.path.isdir(d):
            return d
    except Exception:
        pass
    return None


def _find_free_port(host: str = "127.0.0.1") -> int:
    """Bind an ephemeral port, release it, return the number.

    There is a small TOCTOU race, but acceptable for localhost-only use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _max_owned_workers() -> int:
    value = os.environ.get("IDA_MCP_MAX_IDALIB_WORKERS", "").strip()
    if not value:
        return _DEFAULT_MAX_OWNED_WORKERS
    try:
        return max(1, int(value))
    except ValueError:
        return _DEFAULT_MAX_OWNED_WORKERS


def _normalized_path(value: str | None) -> str | None:
    if not value or value == "unknown":
        return None
    value = os.path.expanduser(str(value))
    return os.path.normcase(os.path.realpath(value))


def _path_basename(value: str | None) -> str | None:
    if not value or value == "unknown":
        return None
    return os.path.basename(str(value).replace("\\", "/")).casefold() or None


def _entry_backend(info: dict[str, Any]) -> str:
    entry_type = str(info.get("type", "gui") or "gui")
    if entry_type == "idalib":
        return "headless"
    return "gui"


class IdalibManager:
    """Manages headless idalib worker subprocesses.

    Each call to :meth:`spawn_session` starts a new Python subprocess
    that opens one binary via ``idapro``, starts an HTTP MCP server on
    a unique port, and registers itself in the shared
    :class:`InstanceRegistry` so the router can forward tool calls.
    """

    def __init__(
        self,
        registry: InstanceRegistry,
        python_executable: str | None = None,
    ):
        self.registry = registry
        self.python_executable = python_executable or sys.executable
        # instance_id -> subprocess.Popen
        self._processes: dict[str, subprocess.Popen] = {}
        # Register cleanup on interpreter shutdown
        atexit.register(self.close_all_sessions)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def spawn_session(
        self,
        input_path: str,
        *,
        host: str = "127.0.0.1",
        timeout: int = _READY_TIMEOUT,
        unsafe: bool = False,
        mode: str = "prefer_headless",
        preferred_instance_id: str | None = None,
        idle_ttl_sec: int | None = None,
        run_auto_analysis: bool = True,
        build_caches: bool = True,
        init_hexrays: bool = True,
    ) -> dict:
        """Spawn a headless idalib worker for *input_path*.

        Returns a dict with ``instance_id``, ``host``, ``port``, ``pid``,
        ``binary`` on success, or ``error`` on failure.
        """
        mode = (mode or "prefer_headless").strip().lower()
        if mode not in _OPEN_MODES:
            return {"error": f"invalid mode: {mode!r}", "valid_modes": sorted(_OPEN_MODES)}

        resolved_path = os.path.realpath(os.path.expanduser(input_path))
        if not os.path.isfile(resolved_path):
            return {"error": f"File not found: {input_path}"}

        if preferred_instance_id:
            preferred = self._select_preferred_instance(preferred_instance_id, mode, resolved_path)
            if "error" in preferred:
                return preferred
            if preferred:
                return preferred

        if mode in ("prefer_gui", "force_gui"):
            existing_gui = self._find_matching_instance(resolved_path, backend="gui")
            if existing_gui is not None:
                return existing_gui
            if mode == "force_gui":
                return {
                    "error": "No matching GUI IDA instance is registered.",
                    "hint": "Open the binary in IDA, start the MCP plugin, then call idalib_open again.",
                }

        existing_headless = self._find_matching_instance(resolved_path, backend="headless")
        if existing_headless is not None:
            return existing_headless

        max_workers = _max_owned_workers()
        owned_workers = self._owned_worker_count()
        if owned_workers >= max_workers:
            return {
                "error": f"Maximum owned idalib workers reached ({owned_workers}/{max_workers}).",
                "hint": "Close an idalib session or raise IDA_MCP_MAX_IDALIB_WORKERS.",
            }

        if not is_idalib_available():
            return {
                "error": (
                    "idalib is not available. Headless mode requires IDA Pro "
                    "(IDA Home/Free do not include idalib). "
                    "Ensure IDADIR points to an IDA Pro installation."
                )
            }

        port = _find_free_port(host)

        cmd = [
            self.python_executable,
            "-m", "ida_fusion_mcp.idalib_worker",
            "--host", host,
            "--port", str(port),
        ]
        if unsafe:
            cmd.append("--unsafe")
        if not run_auto_analysis:
            cmd.append("--no-auto-analysis")
        if not build_caches:
            cmd.append("--no-build-caches")
        if not init_hexrays:
            cmd.append("--no-init-hexrays")
        if idle_ttl_sec is not None:
            cmd.extend(["--idle-ttl-sec", str(int(idle_ttl_sec))])
        cmd.append(resolved_path)

        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
            )
        except FileNotFoundError:
            return {
                "error": (
                    f"Python executable not found: {self.python_executable}. "
                    "Set --idalib-python to the correct Python with idapro installed."
                )
            }
        except Exception as exc:
            return {"error": f"Failed to spawn idalib worker: {exc}"}

        # Wait for the worker to become ready.
        if not self._wait_for_ready(host, port, proc, timeout):
            # Worker didn't come up — collect stderr for diagnostics.
            stderr_text = ""
            try:
                proc.terminate()
                _, stderr_bytes = proc.communicate(timeout=5)
                stderr_text = stderr_bytes.decode(errors="replace")[-500:]
            except Exception:
                proc.kill()
            return {
                "error": (
                    f"idalib worker did not become ready within {timeout}s. "
                    f"Last stderr: {stderr_text}"
                )
            }

        # Ask the worker for its canonical module name so the registry matches
        # what the metadata resource reports. Falls back to basename when the
        # input was an IDB (e.g. foo.exe.i64 → module is "foo.exe") or query fails.
        metadata = query_binary_metadata(host, port, timeout=5.0)
        module_name = (metadata or {}).get("module") if metadata else None
        binary_name = module_name or os.path.basename(resolved_path)
        instance_id = self.registry.register(
            pid=proc.pid,
            port=port,
            idb_path=resolved_path,
            host=host,
            binary_name=binary_name,
            binary_path=resolved_path,
            type="idalib",
            backend="headless",
            owned=True,
            adopted=False,
            worker_pid=proc.pid,
            input_path=resolved_path,
            idle_ttl_sec=idle_ttl_sec,
            run_auto_analysis=run_auto_analysis,
            build_caches=build_caches,
            init_hexrays=init_hexrays,
        )

        self._processes[instance_id] = proc
        return {
            "instance_id": instance_id,
            "host": host,
            "port": port,
            "pid": proc.pid,
            "binary": binary_name,
            "backend": "headless",
            "owned": True,
            "adopted": False,
        }

    def close_session(self, instance_id: str) -> dict:
        """Terminate the worker for *instance_id* and unregister it.

        Returns ``{"ok": True}`` on success or ``{"error": ...}`` on failure.
        """
        proc = self._processes.get(instance_id)
        if proc is None:
            # Not managed by us (might be GUI or already closed).
            info = self.registry.get_instance(instance_id)
            if info is not None and info.get("type") == "idalib":
                # Orphaned idalib entry — clean it up from registry.
                self.registry.unregister(instance_id)
                return {"ok": True, "note": "orphaned entry removed"}
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        # Terminate the subprocess.
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        del self._processes[instance_id]
        self.registry.unregister(instance_id)
        return {"ok": True}

    def close_all_sessions(self) -> int:
        """Terminate all managed idalib workers. Returns count closed."""
        ids = list(self._processes.keys())
        for iid in ids:
            self.close_session(iid)
        return len(ids)

    def list_sessions(self) -> list[dict]:
        """Return info about all managed idalib sessions."""
        result = []
        for iid, proc in list(self._processes.items()):
            info = self.registry.get_instance(iid)
            alive = is_process_alive(proc.pid)
            if not alive:
                # Clean up dead workers.
                del self._processes[iid]
                self.registry.unregister(iid)
                continue
            result.append({
                "instance_id": iid,
                "pid": proc.pid,
                "host": info.get("host", "127.0.0.1") if info else "127.0.0.1",
                "port": info.get("port", 0) if info else 0,
                "binary_name": info.get("binary_name", "unknown") if info else "unknown",
                "binary_path": info.get("binary_path", "") if info else "",
                "type": "idalib",
            })
        return result

    def get_status(self, instance_id: str) -> dict:
        """Health / readiness check for a specific idalib session."""
        proc = self._processes.get(instance_id)
        if proc is None:
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        info = self.registry.get_instance(instance_id)
        alive = is_process_alive(proc.pid)
        if not alive:
            del self._processes[instance_id]
            self.registry.unregister(instance_id)
            return {
                "instance_id": instance_id,
                "alive": False,
                "reachable": False,
                "error": "Worker process is dead",
            }

        host = info.get("host", "127.0.0.1") if info else "127.0.0.1"
        port = info.get("port", 0) if info else 0
        reachable = ping_instance(host, port, timeout=5.0)

        return {
            "instance_id": instance_id,
            "pid": proc.pid,
            "alive": True,
            "reachable": reachable,
            "binary_name": info.get("binary_name", "unknown") if info else "unknown",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _owned_worker_count(self) -> int:
        pids: set[int] = set()
        for iid, proc in list(self._processes.items()):
            if is_process_alive(proc.pid):
                pids.add(proc.pid)
                continue
            del self._processes[iid]
            self.registry.unregister(iid)
        for info in self.registry.list_instances().values():
            if info.get("type") != "idalib" or not info.get("owned", False):
                continue
            pid = info.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                continue
            if is_process_alive(pid):
                pids.add(pid)
        return len(pids)

    def _select_preferred_instance(self, instance_id: str, mode: str, input_path: str) -> dict:
        info = self.registry.get_instance(instance_id)
        if info is None:
            return {"error": f"Preferred instance '{instance_id}' not found"}
        backend = _entry_backend(info)
        if mode == "force_headless" and backend != "headless":
            return {"error": f"Preferred instance '{instance_id}' is not headless"}
        if mode == "force_gui" and backend != "gui":
            return {"error": f"Preferred instance '{instance_id}' is not a GUI instance"}
        if not self._matches_input_path(info, input_path):
            return {"error": f"Preferred instance '{instance_id}' does not match input_path"}
        if not self._is_reachable(info):
            return {"error": f"Preferred instance '{instance_id}' is not reachable"}
        return self._existing_result(instance_id, info, note="preferred_instance")

    def _find_matching_instance(self, input_path: str, *, backend: str) -> dict | None:
        for iid, info in self.registry.list_instances().items():
            if _entry_backend(info) != backend:
                continue
            if not self._matches_input_path(info, input_path):
                continue
            if not self._is_reachable(info):
                continue
            note = "matched_gui_instance" if backend == "gui" else "adopted_existing_headless"
            return self._existing_result(iid, info, note=note)
        return None

    def _matches_input_path(self, info: dict[str, Any], input_path: str) -> bool:
        wanted = _normalized_path(input_path)
        wanted_name = _path_basename(input_path)
        path_candidates: list[str] = []
        for key in ("input_path", "binary_path", "idb_path"):
            value = info.get(key)
            candidate = _normalized_path(value)
            if candidate:
                path_candidates.append(candidate)
            if wanted and candidate and wanted == candidate:
                return True
        if path_candidates:
            return False
        for key in ("binary_name", "binary_path", "idb_path", "input_path"):
            if wanted_name and wanted_name == _path_basename(info.get(key)):
                return True
        return False

    def _is_reachable(self, info: dict[str, Any]) -> bool:
        pid = info.get("pid")
        if isinstance(pid, int) and pid > 0 and not is_process_alive(pid):
            return False
        host = info.get("host", "127.0.0.1")
        port = info.get("port", 0)
        return isinstance(port, int) and ping_instance(host, port, timeout=5.0)

    def _existing_result(self, instance_id: str, info: dict[str, Any], *, note: str) -> dict:
        backend = _entry_backend(info)
        return {
            "instance_id": instance_id,
            "host": info.get("host", "127.0.0.1"),
            "port": info.get("port", 0),
            "pid": info.get("pid", 0),
            "binary": info.get("binary_name", "unknown"),
            "backend": backend,
            "owned": bool(info.get("owned", False)),
            "adopted": True,
            "note": note,
        }

    def _wait_for_ready(
        self,
        host: str,
        port: int,
        proc: subprocess.Popen,
        timeout: int,
    ) -> bool:
        """Poll until the worker responds to ping or until timeout/death."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Check if process died.
            if proc.poll() is not None:
                return False
            if ping_instance(host, port, timeout=2.0):
                return True
            time.sleep(_READY_POLL_INTERVAL)
        return False
