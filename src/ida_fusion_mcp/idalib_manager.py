"""idalib subprocess lifecycle manager.

Spawns, monitors, and terminates headless idalib worker processes.
Each worker opens one binary and listens on a unique localhost port.
Does NOT depend on ``idapro`` — purely manages subprocesses.
"""

from __future__ import annotations

import atexit
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING, Any

from .health import is_process_alive, ping_instance, query_binary_metadata

if TYPE_CHECKING:
    from .registry import InstanceRegistry

# Default timeout (seconds) waiting for worker to become ready.
_READY_TIMEOUT = 120
# Poll interval while waiting for worker readiness.
_READY_POLL_INTERVAL = 0.5
_STDERR_TAIL_BYTES = 8192
_KILL_WAIT_TIMEOUT = 5

# idalib library file name per platform.
_IDALIB_NAMES = {
    "win32": "idalib.dll",
    "darwin": "libidalib.dylib",
    "linux": "libidalib.so",
}
_DEFAULT_MAX_OWNED_WORKERS = 4
_OPEN_MODES = frozenset({"prefer_headless", "force_headless", "prefer_gui", "force_gui"})


class _StderrDrainer:
    """Continuously drain a worker's stderr into a bounded in-memory tail."""

    def __init__(self, stream: Any, limit: int = _STDERR_TAIL_BYTES):
        self._stream = stream
        self._limit = limit
        self._tail = bytearray()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        if stream is not None:
            self._thread = threading.Thread(
                target=self._drain,
                name="idalib-stderr-drainer",
                daemon=True,
            )
            self._thread.start()

    def _drain(self) -> None:
        while True:
            try:
                chunk = self._stream.read(4096)
            except Exception:
                return
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode(errors="replace")
            elif not isinstance(chunk, (bytes, bytearray)):
                return
            with self._lock:
                self._tail.extend(chunk)
                if len(self._tail) > self._limit:
                    del self._tail[:-self._limit]

    def tail(self) -> str:
        with self._lock:
            data = bytes(self._tail)
        return data.decode(errors="replace")

    def finish(self, timeout: float = 1.0) -> None:
        thread = self._thread
        if thread is None:
            return
        thread.join(timeout)
        try:
            self._stream.close()
        except Exception:
            pass
        if thread.is_alive():
            thread.join(timeout)


class _OwnedWorkerGeneration:
    """One locally owned process generation and its cleanup identity."""

    def __init__(
        self,
        process: subprocess.Popen,
        ownership_nonce: str | None,
        drainer: _StderrDrainer | None,
    ):
        self.process = process
        self.ownership_nonce = ownership_nonce
        self.drainer = drainer
        self._finish_lock = threading.Lock()
        self._finished = False

    def finish_drainer(self) -> None:
        with self._finish_lock:
            if self._finished:
                return
            self._finished = True
        if self.drainer is not None:
            self.drainer.finish()
            return
        IdalibManager._close_stderr_stream(self.process)


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
        self._state_lock = threading.RLock()
        self._owned_generations: dict[str, _OwnedWorkerGeneration] = {}
        # instance_id -> subprocess.Popen
        self._processes: dict[str, subprocess.Popen] = {}
        # instance_id -> per-registration ownership generation
        self._ownership_nonces: dict[str, str] = {}
        # instance_id -> bounded stderr drainer
        self._stderr_drainers: dict[str, _StderrDrainer] = {}
        # Local cleanup IDs for workers that could not be registered or stopped.
        self._unregistered_sessions: set[str] = set()
        # Registry reconciliation metadata retained for cleanup IDs whose
        # registration state was unknown or ambiguous.
        self._pending_registry_contexts: dict[str, dict[str, Any]] = {}
        self._cleanup_sequence = 0
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

        try:
            ownership_nonce = secrets.token_hex(16)
        except Exception as exc:
            return {"error": f"Failed to initialize worker ownership nonce: {exc}"}

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
                stdout=subprocess.DEVNULL,
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

        try:
            stderr_drainer = _StderrDrainer(getattr(proc, "stderr", None))
        except Exception as exc:
            self._close_stderr_stream(proc)
            return_code = self._stop_process(proc, terminate_timeout=5)
            return self._failed_start_result(
                proc=proc,
                drainer=None,
                return_code=return_code,
                error=f"Failed to initialize idalib worker diagnostics: {exc}",
            )

        # From this point onward every exceptional path must either confirm
        # process death or retain the process and drainer for a close retry.
        try:
            ready = self._wait_for_ready(host, port, proc, timeout)
        except Exception as exc:
            return_code = self._stop_process(proc, terminate_timeout=5)
            return self._failed_start_result(
                proc=proc,
                drainer=stderr_drainer,
                return_code=return_code,
                error=f"Failed while waiting for idalib worker readiness: {exc}",
            )

        if not ready:
            try:
                initial_return_code = proc.poll()
            except Exception:
                initial_return_code = None
            final_return_code = self._stop_process(proc, terminate_timeout=5)
            return_code = (
                initial_return_code
                if initial_return_code is not None
                else final_return_code
            )
            stop_confirmed = self._process_stop_confirmed(proc, return_code)
            if stop_confirmed:
                stderr_drainer.finish()
            stderr_text = stderr_drainer.tail().strip() or "<no stderr output>"
            if initial_return_code is not None:
                reason = "exited before becoming ready"
            else:
                reason = f"did not become ready within {timeout}s"
            error = (
                f"idalib worker {reason} (return code {return_code}). "
                f"Last stderr: {stderr_text}"
            )
            if stop_confirmed:
                return {
                    "error": error,
                    "pid": proc.pid,
                    "managed": False,
                    "registered": False,
                }
            return self._failed_start_result(
                proc=proc,
                drainer=stderr_drainer,
                return_code=return_code,
                error=error,
            )

        # Ask the worker for its canonical module name so the registry matches
        # what the metadata resource reports. Falls back to basename when the
        # input was an IDB (e.g. foo.exe.i64 → module is "foo.exe") or query fails.
        warnings: list[str] = []
        try:
            metadata = query_binary_metadata(host, port, timeout=5.0)
        except Exception as exc:
            # Metadata is advisory. Keep the ready worker under normal manager
            # ownership and use the documented basename fallback.
            metadata = None
            warnings.append(
                f"Worker metadata query failed; using input basename: {exc}"
            )
        module_value = metadata.get("module") if isinstance(metadata, dict) else None
        module_name = (
            module_value
            if isinstance(module_value, str) and module_value.strip()
            else None
        )
        binary_name = module_name or os.path.basename(resolved_path)
        try:
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
                _manager_nonce=ownership_nonce,
            )
        except Exception as exc:
            registration_error = str(exc).replace(ownership_nonce, "<redacted>")
            (
                reconciled_id,
                reconciled_info,
                registry_state,
                reconciliation_detail,
            ) = self._reconcile_registration(
                pid=proc.pid,
                host=host,
                port=port,
                input_path=resolved_path,
                ownership_nonce=ownership_nonce,
            )
            if reconciled_id is not None and reconciled_info is not None:
                self._remember_owned_generation(
                    reconciled_id,
                    proc,
                    ownership_nonce,
                    stderr_drainer,
                )
                warnings.append(
                    "Registry entry committed despite register() raising; "
                    f"ownership reconciled under '{reconciled_id}': {registration_error}"
                )
                reconciled_binary = reconciled_info.get("binary_name")
                if not isinstance(reconciled_binary, str) or not reconciled_binary.strip():
                    reconciled_binary = binary_name
                return self._owned_worker_result(
                    instance_id=reconciled_id,
                    host=host,
                    port=port,
                    pid=proc.pid,
                    binary_name=reconciled_binary,
                    registry_reconciled=True,
                    warnings=warnings,
                )

            return_code = self._stop_process(proc, terminate_timeout=5)
            return self._failed_start_result(
                proc=proc,
                drainer=stderr_drainer,
                return_code=return_code,
                error=(
                    f"Failed to register idalib worker: {registration_error}. "
                    f"Registry reconciliation state: {registry_state}"
                    + (
                        f" ({reconciliation_detail})"
                        if reconciliation_detail
                        else ""
                    )
                ),
                registered=False if registry_state == "absent" else None,
                registry_state=registry_state,
                registry_context=(
                    {
                        "pid": proc.pid,
                        "host": host,
                        "port": port,
                        "input_path": resolved_path,
                        "ownership_nonce": ownership_nonce,
                    }
                    if registry_state in {"unknown", "ambiguous"}
                    else None
                ),
            )

        self._remember_owned_generation(
            instance_id,
            proc,
            ownership_nonce,
            stderr_drainer,
        )
        return self._owned_worker_result(
            instance_id=instance_id,
            host=host,
            port=port,
            pid=proc.pid,
            binary_name=binary_name,
            registry_reconciled=False,
            warnings=warnings,
        )

    def close_session(self, instance_id: str) -> dict:
        """Terminate the worker for *instance_id* and unregister it.

        Returns ``{"ok": True}`` on success or ``{"error": ...}`` on failure.
        """
        generation = self._capture_generation(instance_id)
        proc = generation.process if generation is not None else None
        if proc is None and instance_id in self._pending_registry_contexts:
            return self._cleanup_pending_registry(
                instance_id,
                process_stopped=True,
            )
        local_only = instance_id in self._unregistered_sessions
        if proc is None:
            info = self.registry.get_instance(instance_id)
            if info is not None and info.get("type") == "idalib":
                pid = info.get("worker_pid") or info.get("pid")
                if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
                    try:
                        alive = is_process_alive(pid)
                    except Exception:
                        alive = None
                    if alive is False:
                        snapshot_nonce = info.get("_manager_nonce")
                        if not isinstance(snapshot_nonce, str):
                            snapshot_nonce = None
                        cleanup_error = self._unregister_error(
                            instance_id,
                            ownership_nonce=snapshot_nonce,
                        )
                        if cleanup_error is not None:
                            return {
                                "ok": False,
                                "error": (
                                    "Worker was already dead, but registry cleanup failed: "
                                    f"{cleanup_error}"
                                ),
                                "instance_id": instance_id,
                                "pid": pid,
                                "managed": False,
                                "process_stopped": True,
                                "registry_cleaned": False,
                            }
                        return {
                            "ok": True,
                            "note": (
                                "stale registry generation cleared or replaced; "
                                "worker was already dead"
                            ),
                            "instance_id": instance_id,
                            "pid": pid,
                            "managed": False,
                        }
                return {
                    "error": (
                        f"Instance '{instance_id}' is registered as idalib but is not "
                        "owned by this router process; it was not terminated or unregistered."
                    ),
                    "instance_id": instance_id,
                    "pid": pid,
                    "managed": False,
                    "hint": (
                        "Close it from the router process that opened it, or terminate "
                        "the verified worker process manually."
                    ),
                }
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        return_code = self._stop_process(proc, terminate_timeout=10)
        if return_code is None:
            try:
                alive = is_process_alive(proc.pid)
            except Exception:
                alive = None
            if alive is not False:
                if local_only:
                    error = (
                        f"Termination of local cleanup worker '{instance_id}' could not "
                        "be confirmed; it remains managed for a later retry."
                    )
                else:
                    error = (
                        f"Termination of managed worker '{instance_id}' could not be "
                        "confirmed; the session remains registered."
                    )
                return {
                    "error": error,
                    "instance_id": instance_id,
                    "pid": proc.pid,
                    "managed": True,
                    "registered": (
                        None
                        if instance_id in self._pending_registry_contexts
                        else not local_only
                    ),
                    **(
                        {
                            "registry_state": self._pending_registry_contexts[
                                instance_id
                            ].get("state", "unknown")
                        }
                        if instance_id in self._pending_registry_contexts
                        else {}
                    ),
                    "hint": "Resolve the process termination failure, then retry idalib_close.",
                }
        assert generation is not None
        self._release_generation(instance_id, generation)
        generation.finish_drainer()
        if local_only:
            if instance_id in self._pending_registry_contexts:
                return self._cleanup_pending_registry(
                    instance_id,
                    process_stopped=True,
                )
            self._unregistered_sessions.discard(instance_id)
            return {
                "ok": True,
                "instance_id": instance_id,
                "managed": False,
                "registered": False,
                "process_stopped": True,
                "registry_cleaned": True,
                "note": "unregistered worker stopped and local cleanup state removed",
            }
        cleanup_error = self._unregister_error(
            instance_id,
            generation.ownership_nonce,
        )
        if cleanup_error is not None:
            return {
                "ok": False,
                "error": f"Worker stopped, but registry cleanup failed: {cleanup_error}",
                "instance_id": instance_id,
                "pid": proc.pid,
                "managed": False,
                "process_stopped": True,
                "registry_cleaned": False,
            }
        return {
            "ok": True,
            "process_stopped": True,
            "registry_cleaned": True,
        }

    def close_all_sessions(self) -> int:
        """Terminate all managed idalib workers. Returns count closed."""
        with self._state_lock:
            process_ids = list(self._processes)
        ids = list(
            dict.fromkeys(
                [*process_ids, *self._pending_registry_contexts.keys()]
            )
        )
        closed = 0
        for iid in ids:
            had_process = iid in self._processes
            try:
                result = self.close_session(iid)
            except Exception:
                continue
            if had_process and (
                result.get("ok") is True
                or result.get("process_stopped") is True
            ):
                closed += 1
        return closed

    def list_sessions(self) -> list[dict]:
        """Return info about all managed idalib sessions."""
        result = []
        for iid, generation in self._generation_snapshots():
            proc = generation.process
            info = self.registry.get_instance(iid)
            alive = is_process_alive(proc.pid)
            if not alive:
                # Clean up dead workers.
                self._release_generation(iid, generation)
                generation.finish_drainer()
                local_only = iid in self._unregistered_sessions
                if local_only and iid in self._pending_registry_contexts:
                    self._cleanup_pending_registry(iid, process_stopped=True)
                elif local_only:
                    self._unregistered_sessions.discard(iid)
                else:
                    self._unregister_error(iid, generation.ownership_nonce)
                continue
            pending = self._pending_registry_contexts.get(iid)
            result.append({
                "instance_id": iid,
                "pid": proc.pid,
                "host": (
                    pending.get("host", "127.0.0.1")
                    if pending
                    else info.get("host", "127.0.0.1") if info else "127.0.0.1"
                ),
                "port": (
                    pending.get("port", 0)
                    if pending
                    else info.get("port", 0) if info else 0
                ),
                "binary_name": info.get("binary_name", "unknown") if info else "unknown",
                "binary_path": info.get("binary_path", "") if info else "",
                "type": "idalib",
                **(
                    {
                        "registered": None,
                        "registry_state": pending.get("state", "unknown"),
                    }
                    if pending
                    else {}
                ),
            })
        return result

    def get_status(self, instance_id: str) -> dict:
        """Health / readiness check for a specific idalib session."""
        generation = self._capture_generation(instance_id)
        proc = generation.process if generation is not None else None
        if proc is None:
            pending = self._pending_registry_contexts.get(instance_id)
            if pending is not None:
                return {
                    "instance_id": instance_id,
                    "pid": pending["pid"],
                    "alive": False,
                    "reachable": False,
                    "managed": False,
                    "registered": None,
                    "registry_state": pending.get("state", "unknown"),
                    "hint": f"Retry idalib_close with instance_id '{instance_id}'.",
                }
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        info = self.registry.get_instance(instance_id)
        alive = is_process_alive(proc.pid)
        if not alive:
            assert generation is not None
            self._release_generation(instance_id, generation)
            generation.finish_drainer()
            local_only = instance_id in self._unregistered_sessions
            registry_cleanup_error = None
            pending_cleanup = None
            if local_only and instance_id in self._pending_registry_contexts:
                pending_cleanup = self._cleanup_pending_registry(
                    instance_id,
                    process_stopped=True,
                )
            elif local_only:
                self._unregistered_sessions.discard(instance_id)
            else:
                registry_cleanup_error = self._unregister_error(
                    instance_id,
                    generation.ownership_nonce,
                )
            result = {
                "instance_id": instance_id,
                "alive": False,
                "reachable": False,
                "error": "Worker process is dead",
            }
            if registry_cleanup_error is not None:
                result["registry_cleanup_error"] = registry_cleanup_error
            if pending_cleanup is not None:
                for key in (
                    "registered",
                    "registry_state",
                    "registry_cleaned",
                    "registry_instance_id",
                ):
                    if key in pending_cleanup:
                        result[key] = pending_cleanup[key]
            return result

        pending = self._pending_registry_contexts.get(instance_id)
        host = (
            pending.get("host", "127.0.0.1")
            if pending
            else info.get("host", "127.0.0.1") if info else "127.0.0.1"
        )
        port = (
            pending.get("port", 0)
            if pending
            else info.get("port", 0) if info else 0
        )
        reachable = ping_instance(host, port, timeout=5.0)

        return {
            "instance_id": instance_id,
            "pid": proc.pid,
            "alive": True,
            "reachable": reachable,
            "binary_name": info.get("binary_name", "unknown") if info else "unknown",
            **(
                {
                    "registered": None,
                    "registry_state": pending.get("state", "unknown"),
                }
                if pending
                else {}
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _remember_owned_generation(
        self,
        instance_id: str,
        process: subprocess.Popen,
        ownership_nonce: str,
        drainer: _StderrDrainer,
    ) -> _OwnedWorkerGeneration:
        generation = _OwnedWorkerGeneration(process, ownership_nonce, drainer)
        with self._state_lock:
            self._owned_generations[instance_id] = generation
            self._processes[instance_id] = process
            self._ownership_nonces[instance_id] = ownership_nonce
            self._stderr_drainers[instance_id] = drainer
        return generation

    def _capture_generation(
        self,
        instance_id: str,
    ) -> _OwnedWorkerGeneration | None:
        with self._state_lock:
            process = self._processes.get(instance_id)
            if process is None:
                return None
            generation = self._owned_generations.get(instance_id)
            if generation is not None and generation.process is process:
                return generation
            return _OwnedWorkerGeneration(
                process,
                self._ownership_nonces.get(instance_id),
                self._stderr_drainers.get(instance_id),
            )

    def _generation_snapshots(
        self,
    ) -> list[tuple[str, _OwnedWorkerGeneration]]:
        with self._state_lock:
            snapshots = []
            for instance_id, process in self._processes.items():
                generation = self._owned_generations.get(instance_id)
                if generation is None or generation.process is not process:
                    generation = _OwnedWorkerGeneration(
                        process,
                        self._ownership_nonces.get(instance_id),
                        self._stderr_drainers.get(instance_id),
                    )
                snapshots.append((instance_id, generation))
            return snapshots

    def _release_generation(
        self,
        instance_id: str,
        generation: _OwnedWorkerGeneration,
    ) -> bool:
        """Drop local state only if *generation* still occupies the ID."""
        with self._state_lock:
            current_generation = self._owned_generations.get(instance_id)
            if current_generation is not None and current_generation is not generation:
                return False

            current_process = self._processes.get(instance_id)
            if current_process is not generation.process:
                if current_generation is generation:
                    self._owned_generations.pop(instance_id, None)
                return False

            if current_generation is generation:
                self._owned_generations.pop(instance_id, None)
            self._processes.pop(instance_id, None)
            if self._ownership_nonces.get(instance_id) == generation.ownership_nonce:
                self._ownership_nonces.pop(instance_id, None)
            if self._stderr_drainers.get(instance_id) is generation.drainer:
                self._stderr_drainers.pop(instance_id, None)
            return True

    def _owned_worker_count(self) -> int:
        pids: set[int] = set()
        for iid, generation in self._generation_snapshots():
            proc = generation.process
            if is_process_alive(proc.pid):
                pids.add(proc.pid)
                continue
            self._release_generation(iid, generation)
            generation.finish_drainer()
            local_only = iid in self._unregistered_sessions
            if local_only and iid in self._pending_registry_contexts:
                self._cleanup_pending_registry(iid, process_stopped=True)
            elif local_only:
                self._unregistered_sessions.discard(iid)
            else:
                self._unregister_error(iid, generation.ownership_nonce)
        for info in self.registry.list_instances().values():
            if info.get("type") != "idalib" or not info.get("owned", False):
                continue
            pid = info.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                continue
            if is_process_alive(pid):
                pids.add(pid)
        return len(pids)

    @staticmethod
    def _process_stop_confirmed(proc: subprocess.Popen, return_code: int | None) -> bool:
        if return_code is not None:
            return True
        try:
            return not is_process_alive(proc.pid)
        except Exception:
            return False

    def _conditional_unregister(
        self,
        instance_id: str,
        ownership_nonce: str | None,
    ) -> dict[str, Any]:
        """Atomically unregister one owned registry generation.

        Real ``InstanceRegistry`` implementations expose the guarded method.
        The fallback preserves compatibility with older duck-typed registry
        doubles while production cleanup always uses compare-and-delete.
        """
        guarded_method = getattr(
            type(self.registry),
            "unregister_if_owner",
            None,
        )
        if not callable(guarded_method):
            removed = self.registry.unregister(instance_id)
            if removed is False:
                return {"status": "missing", "removed": False}
            return {"status": "removed", "removed": True}

        result = self.registry.unregister_if_owner(
            instance_id,
            ownership_nonce,
        )
        if not isinstance(result, dict) or result.get("status") not in {
            "removed",
            "missing",
            "owner_mismatch",
        }:
            raise RuntimeError("invalid conditional unregister result")
        return result

    @staticmethod
    def _conditional_unregister_error(result: dict[str, Any]) -> str | None:
        status = result.get("status")
        if status in {"removed", "missing"}:
            return None
        reason = result.get("reason")
        if status == "owner_mismatch" and reason == "nonce_mismatch":
            # The old generation has already been replaced. Preserve its owner.
            return None
        if reason == "missing_expected_nonce":
            return "registry ownership nonce is unavailable; current entry preserved"
        if reason == "missing_entry_nonce":
            return "registry entry has no ownership nonce; current entry preserved"
        return "registry ownership could not be verified; current entry preserved"

    def _unregister_error(
        self,
        instance_id: str,
        ownership_nonce: str | None = None,
    ) -> str | None:
        if ownership_nonce is None:
            ownership_nonce = self._ownership_nonces.get(instance_id)
        try:
            result = self._conditional_unregister(instance_id, ownership_nonce)
            return self._conditional_unregister_error(result)
        except Exception as exc:
            error = str(exc)
            if isinstance(ownership_nonce, str) and ownership_nonce:
                error = error.replace(ownership_nonce, "<redacted>")
            return error

    @staticmethod
    def _close_stderr_stream(proc: subprocess.Popen) -> None:
        stream = getattr(proc, "stderr", None)
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass

    def _track_unregistered_worker(
        self,
        proc: subprocess.Popen,
        drainer: _StderrDrainer | None,
    ) -> str:
        with self._state_lock:
            instance_id = self._next_cleanup_id(proc.pid)
            self._processes[instance_id] = proc
            if drainer is not None:
                self._stderr_drainers[instance_id] = drainer
            self._unregistered_sessions.add(instance_id)
        return instance_id

    def _next_cleanup_id(self, pid: int) -> str:
        self._cleanup_sequence += 1
        instance_id = f"pending-{pid}-{self._cleanup_sequence}"
        while (
            instance_id in self._processes
            or instance_id in self._pending_registry_contexts
        ):
            self._cleanup_sequence += 1
            instance_id = f"pending-{pid}-{self._cleanup_sequence}"
        return instance_id

    def _failed_start_result(
        self,
        *,
        proc: subprocess.Popen,
        drainer: _StderrDrainer | None,
        return_code: int | None,
        error: str,
        registered: bool | None = False,
        registry_state: str | None = None,
        registry_context: dict[str, Any] | None = None,
    ) -> dict:
        if self._process_stop_confirmed(proc, return_code):
            if drainer is not None:
                drainer.finish()
            else:
                self._close_stderr_stream(proc)
            result: dict[str, Any] = {
                "error": error,
                "pid": proc.pid,
                "managed": False,
                "registered": registered,
                "process_stopped": True,
            }
            if registry_context is not None:
                instance_id = self._next_cleanup_id(proc.pid)
                self._pending_registry_contexts[instance_id] = {
                    **registry_context,
                    "state": registry_state or "unknown",
                }
                self._unregistered_sessions.add(instance_id)
                result.update({
                    "instance_id": instance_id,
                    "registry_cleaned": None,
                    "hint": (
                        "Worker stopped; retry idalib_close with instance_id "
                        f"'{instance_id}' to reconcile registry cleanup."
                    ),
                })
            if registry_state is not None:
                result["registry_state"] = registry_state
            return result

        instance_id = self._track_unregistered_worker(proc, drainer)
        if registry_context is not None:
            self._pending_registry_contexts[instance_id] = {
                **registry_context,
                "state": registry_state or "unknown",
            }
        result = {
            "error": (
                f"{error} Cleanup could not be confirmed; the worker remains managed "
                "locally for a later close retry."
            ),
            "instance_id": instance_id,
            "pid": proc.pid,
            "managed": True,
            "registered": registered,
            "hint": f"Retry idalib_close with instance_id '{instance_id}'.",
        }
        if registry_state is not None:
            result["registry_state"] = registry_state
        return result

    @staticmethod
    def _owned_worker_result(
        *,
        instance_id: str,
        host: str,
        port: int,
        pid: int,
        binary_name: str,
        registry_reconciled: bool,
        warnings: list[str],
    ) -> dict:
        result = {
            "instance_id": instance_id,
            "host": host,
            "port": port,
            "pid": pid,
            "binary": binary_name,
            "backend": "headless",
            "owned": True,
            "adopted": False,
            "managed": True,
            "registered": True,
            "registry_reconciled": registry_reconciled,
        }
        if warnings:
            result["warning"] = " ".join(warnings)
        return result

    def _reconcile_registration(
        self,
        *,
        pid: int,
        host: str,
        port: int,
        input_path: str,
        ownership_nonce: str,
    ) -> tuple[str | None, dict[str, Any] | None, str, str | None]:
        """Find the one exact entry that register() may have committed."""
        try:
            entries = self.registry.list_instances()
        except Exception as exc:
            detail = str(exc).replace(ownership_nonce, "<redacted>")
            return None, None, "unknown", detail
        if not isinstance(entries, dict):
            return None, None, "unknown", "registry listing was not a mapping"

        wanted_path = _normalized_path(input_path)
        matches: list[tuple[str, dict[str, Any]]] = []
        try:
            for instance_id, info in entries.items():
                if not isinstance(instance_id, str) or not isinstance(info, dict):
                    continue
                if info.get("type") != "idalib":
                    continue
                if info.get("backend") != "headless" or info.get("owned") is not True:
                    continue
                if type(info.get("pid")) is not int or info.get("pid") != pid:
                    continue
                if type(info.get("worker_pid")) is not int or info.get("worker_pid") != pid:
                    continue
                if info.get("host") != host:
                    continue
                if type(info.get("port")) is not int or info.get("port") != port:
                    continue
                if _normalized_path(info.get("input_path")) != wanted_path:
                    continue
                if _normalized_path(info.get("idb_path")) != wanted_path:
                    continue
                candidate_nonce = info.get("_manager_nonce")
                if not isinstance(candidate_nonce, str):
                    continue
                if not secrets.compare_digest(candidate_nonce, ownership_nonce):
                    continue
                matches.append((instance_id, info))
        except Exception as exc:
            detail = str(exc).replace(ownership_nonce, "<redacted>")
            return None, None, "unknown", detail

        if len(matches) == 1:
            instance_id, info = matches[0]
            return instance_id, info, "committed", None
        if not matches:
            return None, None, "absent", None
        return None, None, "ambiguous", f"{len(matches)} exact entries matched"

    def _cleanup_pending_registry(
        self,
        instance_id: str,
        *,
        process_stopped: bool,
    ) -> dict:
        """Retry registry reconciliation for a local cleanup identifier."""
        context = self._pending_registry_contexts[instance_id]
        reconciled_id, _info, state, detail = self._reconcile_registration(
            pid=context["pid"],
            host=context["host"],
            port=context["port"],
            input_path=context["input_path"],
            ownership_nonce=context["ownership_nonce"],
        )
        context["state"] = state

        if reconciled_id is not None:
            try:
                cleanup_result = self._conditional_unregister(
                    reconciled_id,
                    context["ownership_nonce"],
                )
            except Exception as exc:
                cleanup_error = str(exc).replace(
                    context["ownership_nonce"],
                    "<redacted>",
                )
                return {
                    "ok": False,
                    "error": (
                        "Worker stopped, but reconciled registry cleanup failed: "
                        f"{cleanup_error}"
                    ),
                    "instance_id": instance_id,
                    "registry_instance_id": reconciled_id,
                    "pid": context["pid"],
                    "managed": False,
                    "registered": True,
                    "registry_state": "committed",
                    "process_stopped": process_stopped,
                    "registry_cleaned": False,
                }

            cleanup_error = self._conditional_unregister_error(cleanup_result)
            if cleanup_error is not None:
                return {
                    "ok": False,
                    "error": (
                        "Worker stopped, but reconciled registry cleanup failed: "
                        f"{cleanup_error}"
                    ),
                    "instance_id": instance_id,
                    "registry_instance_id": reconciled_id,
                    "pid": context["pid"],
                    "managed": False,
                    "registered": True,
                    "registry_state": "committed",
                    "process_stopped": process_stopped,
                    "registry_cleaned": False,
                }

            self._pending_registry_contexts.pop(instance_id, None)
            self._unregistered_sessions.discard(instance_id)
            if cleanup_result["status"] != "removed":
                return {
                    "ok": True,
                    "instance_id": instance_id,
                    "registry_instance_id": reconciled_id,
                    "pid": context["pid"],
                    "managed": False,
                    "registered": False,
                    "registry_state": "absent",
                    "process_stopped": process_stopped,
                    "registry_cleaned": True,
                    "note": (
                        "matching registry generation was already absent or replaced; "
                        "current owner preserved"
                    ),
                }
            return {
                "ok": True,
                "instance_id": instance_id,
                "registry_instance_id": reconciled_id,
                "pid": context["pid"],
                "managed": False,
                "registered": False,
                "registry_state": "committed",
                "process_stopped": process_stopped,
                "registry_cleaned": True,
                "note": "reconciled registry entry removed after worker stop",
            }

        if state == "absent":
            self._pending_registry_contexts.pop(instance_id, None)
            self._unregistered_sessions.discard(instance_id)
            return {
                "ok": True,
                "instance_id": instance_id,
                "pid": context["pid"],
                "managed": False,
                "registered": False,
                "registry_state": "absent",
                "process_stopped": process_stopped,
                "registry_cleaned": True,
                "note": "registry confirmed absent after worker stop",
            }

        return {
            "ok": False,
            "error": (
                "Worker stopped, but registry cleanup state remains "
                f"{state}"
                + (f": {detail}" if detail else ".")
            ),
            "instance_id": instance_id,
            "pid": context["pid"],
            "managed": False,
            "registered": None,
            "registry_state": state,
            "process_stopped": process_stopped,
            "registry_cleaned": None,
            "hint": f"Retry idalib_close with instance_id '{instance_id}'.",
        }

    @staticmethod
    def _stop_process(proc: subprocess.Popen, *, terminate_timeout: float) -> int | None:
        """Stop and reap *proc*, escalating from terminate to kill."""
        try:
            return_code = proc.poll()
        except Exception:
            return_code = None

        if return_code is not None:
            return return_code

        try:
            proc.terminate()
        except Exception:
            pass

        try:
            return proc.wait(timeout=terminate_timeout)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        try:
            proc.kill()
        except Exception:
            pass
        try:
            return proc.wait(timeout=_KILL_WAIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return getattr(proc, "returncode", None)

    def _finish_drainer(
        self,
        instance_id: str,
        proc: subprocess.Popen | None = None,
    ) -> None:
        drainer = self._stderr_drainers.pop(instance_id, None)
        if drainer is not None:
            drainer.finish()
        elif proc is not None:
            self._close_stderr_stream(proc)

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
