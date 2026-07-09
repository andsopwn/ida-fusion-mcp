"""MCP server for ida-fusion-mcp.

Aggregates tools from multiple IDA instances and routes requests.
"""

import os
import re
import secrets
import stat
import sys
import json
import tempfile
from pathlib import Path
from typing import Any

from .vendor.zeromcp import McpServer
from .registry import InstanceRegistry
from .router import InstanceRouter
from .health import cleanup_stale_instances, rediscover_instances
from .idalib_manager import IdalibManager
from .tools import management, idalib as idalib_tools
from .cache import get_cache, DEFAULT_MAX_OUTPUT_CHARS

# Static IDA tool schemas (loaded once at import time)
_STATIC_IDA_TOOLS_PATH = Path(__file__).parent / "ida_tool_schemas.json"
_STATIC_IDA_TOOLS: list[dict] | None = None

_DIR_FD_SUPPORTED = (
    os.name != "nt"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)


class _OutputDirectory:
    """Hold and revalidate the directory selected for decompiler output."""

    def __init__(self, path: str):
        self.path = path
        self.fd: int | None = None
        initial = os.stat(path)
        self._identity = (initial.st_dev, initial.st_ino)

        if _DIR_FD_SUPPORTED:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != self._identity:
                os.close(fd)
                raise OSError("output_dir changed while it was being secured")
            self.fd = fd

        try:
            self.revalidate()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> "_OutputDirectory":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def close(self) -> None:
        fd = self.fd
        self.fd = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def revalidate(self) -> None:
        try:
            current_path = os.path.realpath(self.path)
            current = os.stat(self.path)
        except (OSError, TypeError, ValueError) as exc:
            raise OSError(f"output_dir changed after validation: {exc}") from exc

        identity = (current.st_dev, current.st_ino)
        if os.path.normcase(current_path) != os.path.normcase(self.path):
            raise OSError("output_dir changed after validation")
        if identity != self._identity:
            raise OSError("output_dir changed after validation")
        if self.fd is not None:
            opened = os.fstat(self.fd)
            if (opened.st_dev, opened.st_ino) != self._identity:
                raise OSError("secured output_dir identity changed")


def _leaf_lstat(output: _OutputDirectory, leaf_name: str):
    if output.fd is None:
        try:
            return os.lstat(os.path.join(output.path, leaf_name))
        except FileNotFoundError:
            return None
    try:
        return os.stat(leaf_name, dir_fd=output.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _leaf_is_symlink(output: _OutputDirectory, leaf_name: str) -> bool:
    info = _leaf_lstat(output, leaf_name)
    return info is not None and stat.S_ISLNK(info.st_mode)


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _leaf_has_identity(
    output: _OutputDirectory,
    leaf_name: str,
    identity: tuple[int, int],
) -> bool:
    info = _leaf_lstat(output, leaf_name)
    return info is not None and _file_identity(info) == identity


def _open_temporary_leaf(output: _OutputDirectory) -> tuple[int, str]:
    if output.fd is None:
        fd, path = tempfile.mkstemp(
            prefix=".ida-fusion-",
            suffix=".tmp",
            dir=output.path,
        )
        return fd, os.path.basename(path)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _ in range(100):
        name = f".ida-fusion-{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(name, flags, 0o600, dir_fd=output.fd)
            return fd, name
        except FileExistsError:
            continue
    raise OSError("could not allocate a unique temporary output file")


def _replace_leaf(output: _OutputDirectory, source: str, destination: str) -> None:
    if output.fd is not None:
        os.replace(
            source,
            destination,
            src_dir_fd=output.fd,
            dst_dir_fd=output.fd,
        )
    else:
        os.replace(
            os.path.join(output.path, source),
            os.path.join(output.path, destination),
        )


def _link_leaf(output: _OutputDirectory, source: str, destination: str) -> None:
    if output.fd is not None:
        os.link(
            source,
            destination,
            src_dir_fd=output.fd,
            dst_dir_fd=output.fd,
            follow_symlinks=False,
        )
    else:
        os.link(
            os.path.join(output.path, source),
            os.path.join(output.path, destination),
            follow_symlinks=False,
        )


def _unlink_leaf(output: _OutputDirectory, leaf_name: str) -> None:
    try:
        if output.fd is not None:
            os.unlink(leaf_name, dir_fd=output.fd)
        else:
            os.unlink(os.path.join(output.path, leaf_name))
    except FileNotFoundError:
        pass


def _unlink_leaf_if_identity(
    output: _OutputDirectory,
    leaf_name: str,
    identity: tuple[int, int],
) -> bool:
    """Unlink a leaf only when it is still the file this operation owns."""
    if not _leaf_has_identity(output, leaf_name, identity):
        return False
    _unlink_leaf(output, leaf_name)
    return True


def _create_rollback_link(
    output: _OutputDirectory,
    leaf_name: str,
    original_identity: tuple[int, int],
) -> str:
    """Retain the old inode without making the destination disappear."""
    for _ in range(100):
        backup_name = f".ida-fusion-{secrets.token_hex(8)}.bak"
        try:
            _link_leaf(output, leaf_name, backup_name)
        except FileExistsError:
            continue
        except Exception:
            # A wrapper may raise after link() has already committed.
            backup_info = _leaf_lstat(output, backup_name)
            if (
                backup_info is not None
                and _file_identity(backup_info) == original_identity
            ):
                try:
                    _unlink_leaf_if_identity(
                        output,
                        backup_name,
                        original_identity,
                    )
                except OSError:
                    pass
            raise

        backup_info = _leaf_lstat(output, backup_name)
        if backup_info is None:
            raise OSError("rollback backup disappeared during creation")
        backup_identity = _file_identity(backup_info)
        if backup_identity != original_identity:
            raise OSError("output leaf changed while creating rollback backup")
        return backup_name
    raise OSError("could not allocate a unique output rollback backup")


def _atomic_write_text(
    output: _OutputDirectory,
    leaf_name: str,
    writer: Any,
) -> None:
    """Atomically replace one leaf without resolving a changed parent path."""
    if os.path.basename(leaf_name) != leaf_name or leaf_name in {"", ".", ".."}:
        raise OSError(f"invalid output filename: {leaf_name!r}")

    output.revalidate()
    if _leaf_is_symlink(output, leaf_name):
        raise OSError(f"refusing to overwrite symbolic link: {leaf_name}")

    fd, temp_name = _open_temporary_leaf(output)
    temp_identity = _file_identity(os.fstat(fd))
    backup_name = ""
    original_identity: tuple[int, int] | None = None
    backup_active = False

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            writer(stream)
            stream.flush()
        output.revalidate()
        destination_info = _leaf_lstat(output, leaf_name)
        if destination_info is not None and stat.S_ISLNK(destination_info.st_mode):
            raise OSError(f"refusing to overwrite symbolic link: {leaf_name}")
        if destination_info is not None:
            if not stat.S_ISREG(destination_info.st_mode):
                raise OSError(f"refusing to replace non-regular output leaf: {leaf_name}")
            original_identity = _file_identity(destination_info)

        try:
            if original_identity is not None:
                backup_name = _create_rollback_link(
                    output,
                    leaf_name,
                    original_identity,
                )
                backup_active = True
                output.revalidate()

            _replace_leaf(output, temp_name, leaf_name)
            output.revalidate()
            if not _leaf_has_identity(output, leaf_name, temp_identity):
                raise OSError("output leaf changed during commit")
        except Exception as exc:
            if (
                original_identity is not None
                and backup_name
                and _leaf_has_identity(output, backup_name, original_identity)
            ):
                # os.replace() may have committed before a wrapper raised.
                backup_active = True

            rollback_errors: list[str] = []
            current_leaf = _leaf_lstat(output, leaf_name)
            if (
                current_leaf is not None
                and _file_identity(current_leaf) == temp_identity
            ):
                try:
                    if not _unlink_leaf_if_identity(output, leaf_name, temp_identity):
                        rollback_errors.append("generated output leaf changed before removal")
                except OSError as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            elif (
                current_leaf is not None
                and backup_active
                and _file_identity(current_leaf) != original_identity
            ):
                rollback_errors.append(
                    "output leaf changed; refusing to overwrite it during rollback"
                )

            if backup_active:
                try:
                    current_leaf = _leaf_lstat(output, leaf_name)
                    if (
                        current_leaf is not None
                        and _file_identity(current_leaf) == original_identity
                    ):
                        backup_info = _leaf_lstat(output, backup_name)
                        if backup_info is None:
                            backup_active = False
                            backup_name = ""
                        elif _file_identity(backup_info) != original_identity:
                            rollback_errors.append("original rollback backup changed")
                        elif _unlink_leaf_if_identity(
                            output,
                            backup_name,
                            original_identity,
                        ):
                            backup_active = False
                            backup_name = ""
                        else:
                            rollback_errors.append(
                                "original rollback backup changed before cleanup"
                            )
                    elif current_leaf is not None:
                        rollback_errors.append(
                            "output leaf occupied; original preserved in rollback backup"
                        )
                    elif not _leaf_has_identity(
                        output,
                        backup_name,
                        original_identity,
                    ):
                        rollback_errors.append("original rollback backup changed")
                    else:
                        _replace_leaf(output, backup_name, leaf_name)
                        if not _leaf_has_identity(
                            output,
                            leaf_name,
                            original_identity,
                        ):
                            rollback_errors.append("original output restoration was not durable")
                        else:
                            backup_active = False
                            backup_name = ""
                except OSError as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            if rollback_errors:
                raise OSError(
                    f"{exc}; output rollback failed: {'; '.join(rollback_errors)}"
                ) from exc
            raise

        # The generated leaf is now committed and validated. Backup cleanup is
        # intentionally outside the rollback region: once the old hard link is
        # gone, removing the generated leaf could only cause data loss.
        temp_name = ""
        if backup_active:
            try:
                backup_removed = _unlink_leaf_if_identity(
                    output,
                    backup_name,
                    original_identity,
                )
            except OSError:
                # unlink() may commit before an instrumentation wrapper raises.
                if (
                    _leaf_lstat(output, backup_name) is None
                    and _leaf_has_identity(output, leaf_name, temp_identity)
                ):
                    backup_removed = True
                else:
                    raise
            if (
                not backup_removed
                and _leaf_lstat(output, backup_name) is None
                and _leaf_has_identity(output, leaf_name, temp_identity)
            ):
                backup_removed = True
            if not backup_removed:
                raise OSError(
                    "output committed, but rollback backup changed before cleanup"
                )
            backup_active = False
            backup_name = ""
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_name:
            try:
                _unlink_leaf_if_identity(output, temp_name, temp_identity)
            except OSError:
                pass


def _load_static_ida_tools() -> list[dict]:
    """Load static IDA tool schemas from bundled JSON file."""
    global _STATIC_IDA_TOOLS
    if _STATIC_IDA_TOOLS is None:
        try:
            with open(_STATIC_IDA_TOOLS_PATH, "r") as f:
                _STATIC_IDA_TOOLS = json.load(f)
        except Exception as e:
            print(f"[ida-fusion-mcp] Warning: failed to load static tool schemas: {e}",
                  file=sys.stderr)
            _STATIC_IDA_TOOLS = []
    return _STATIC_IDA_TOOLS


class IdaFusionMcpServer:
    """MCP server that aggregates multiple IDA Pro instances.

    Discovers tools dynamically from registered IDA instances and routes
    tool calls to the appropriate instance.
    """

    def __init__(
        self,
        registry_path: str | None = None,
        idalib_python: str | None = None,
    ):
        """Initialize the multi-instance MCP server.

        Args:
            registry_path: Path to registry JSON file (default: ~/.ida-mcp/instances.json)
            idalib_python: Python executable with idapro installed (for headless sessions)
        """
        self.registry = InstanceRegistry(registry_path)
        self.router = InstanceRouter(self.registry)
        self.server = McpServer("ida-fusion-mcp", version="1.0.0")

        # idalib lifecycle manager
        self.idalib_manager = IdalibManager(self.registry, python_executable=idalib_python)

        # Tool cache
        self._tool_cache: dict[str, dict] = {}
        self._cache_valid = False

        # Set up management tools
        management.set_registry(self.registry)
        management.set_refresh_callback(self._refresh_tools)
        management.set_router(self.router)
        idalib_tools.set_manager(self.idalib_manager)

        # Register handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP protocol handlers."""

        def _is_result_wrapper_schema(schema: Any) -> bool:
            if not isinstance(schema, dict):
                return False
            if schema.get("type") != "object":
                return False
            props = schema.get("properties")
            if not isinstance(props, dict) or "result" not in props:
                return False
            # Treat {result: <T>} as wrapper only when it is the ONLY property
            return set(props.keys()) == {"result"}

        def _coerce_structured_for_schema(tool_name: str, structured: Any) -> Any:
            """Ensure structuredContent matches the tool's advertised outputSchema.

            Some servers advertise an object wrapper {result: ...} for non-object returns.
            Others advertise raw arrays/scalars. We adapt based on cached tool schema.
            """
            schema = self._tool_cache.get(tool_name, {}).get("outputSchema")

            # If schema expects wrapper, always wrap non-wrapper values.
            if _is_result_wrapper_schema(schema):
                if isinstance(structured, dict) and set(structured.keys()) == {"result"}:
                    return structured
                return {"result": structured}

            # If schema does NOT expect wrapper, unwrap legacy {result: ...}.
            if isinstance(structured, dict) and set(structured.keys()) == {"result"}:
                return structured.get("result")

            return structured

        def _json_text(value: Any) -> str:
            return json.dumps(value, separators=(",", ":"))

        def _schema_preserving_preview(value: Any, max_chars: int) -> Any:
            """Return a smaller value of the same JSON type (str/list/dict) when huge."""
            if max_chars <= 0:
                return value
            try:
                if len(_json_text(value)) <= max_chars:
                    return value
            except Exception:
                return value

            if isinstance(value, str):
                return value[:max_chars]

            if isinstance(value, list):
                out: list[Any] = []
                for item in value:
                    out.append(item)
                    try:
                        if len(_json_text(out)) > max_chars:
                            out.pop()
                            break
                    except Exception:
                        break
                return out

            if isinstance(value, dict):
                def _truncate(v: Any, depth: int = 0) -> Any:
                    if depth > 6:
                        return v
                    if isinstance(v, str) and len(v) > 1000:
                        return v[:1000] + f"... [{len(v)} chars total]"
                    if isinstance(v, list):
                        return [_truncate(x, depth + 1) for x in v[:50]]
                    if isinstance(v, dict):
                        return {k: _truncate(x, depth + 1) for k, x in v.items()}
                    return v

                return _truncate(value)

            return value

        # Override tools/list to return cached tools

        def custom_tools_list(cursor: str | None = None, _meta: dict | None = None) -> dict:
            """List all available tools (management + IDA tools)."""
            # Ensure tool cache is fresh
            if not self._cache_valid:
                self._refresh_tools()

            # Return all cached tools (cursor ignored - no pagination needed)
            return {"tools": list(self._tool_cache.values())}

        self.server.registry.methods["tools/list"] = custom_tools_list

        # Override tools/call to route requests
        def custom_tools_call(name: str, arguments: dict[str, Any] | None = None, _meta: dict | None = None) -> dict:
            """Route tool call to appropriate handler."""
            if arguments is None:
                arguments = {}

            # Management tools (local)
            if name == "list_instances":
                result = management.list_instances()
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": False
                }

            elif name == "refresh_tools":
                result = management.refresh_tools()
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": False
                }

            elif name == "get_cached_output":
                cache = get_cache()
                cache_id = arguments.get("cache_id", "")
                offset = arguments.get("offset", 0)
                size = arguments.get("size", DEFAULT_MAX_OUTPUT_CHARS)

                try:
                    result = cache.get(cache_id, offset, size)
                    return {
                        "content": [{"type": "text", "text": result["chunk"]}],
                        "structuredContent": result,
                        "isError": False
                    }
                except KeyError as e:
                    return {
                        "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                        "isError": True
                    }

            elif name == "compare_binaries":
                result = management.compare_binaries(arguments)
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": "error" in result,
                }

            elif name == "list_cached_outputs":
                cache = get_cache()
                result = {"entries": cache.list_entries(), **cache.stats()}
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": False,
                }

            elif name == "decompile_to_file":
                result = self._handle_decompile_to_file(arguments)
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": "error" in result
                }

            # idalib management tools (local)
            elif name in ("idalib_open", "idalib_close", "idalib_list", "idalib_status"):
                handler = getattr(idalib_tools, name)
                result = handler(arguments)
                is_error = "error" in result
                # After idalib_open succeeds, refresh tools so the new instance's
                # tools become available immediately.
                if name == "idalib_open" and not is_error:
                    self._refresh_tools()
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": is_error,
                }

            # IDA tools (proxied)
            else:
                # Check if any IDA instance is available before proxying
                active = self.registry.get_active()
                if not active:
                    # Try auto-discovery before giving up
                    discovered = rediscover_instances(self.registry)
                    if discovered:
                        active = self.registry.get_active()
                if not active:
                    return {
                        "content": [{"type": "text", "text": (
                            f"Error: No IDA Pro instance is connected. "
                            f"Cannot execute tool '{name}'.\n\n"
                            f"To fix this:\n"
                            f"1. Open IDA Pro and load a binary\n"
                            f"2. Press Ctrl+M (or start the MCP plugin manually)\n"
                            f"3. The plugin will auto-register with this server\n"
                            f"4. Use 'list_instances' to verify the connection"
                        )}],
                        "isError": True,
                    }

                # Extract max_output_chars if provided (0 = unlimited)
                max_output = arguments.pop("max_output_chars", DEFAULT_MAX_OUTPUT_CHARS)

                ida_response = self.router.route_request("tools/call", {
                    "name": name,
                    "arguments": arguments
                })

                # Format response
                if "error" in ida_response:
                    return {
                        "content": [{"type": "text", "text": f"Error: {_json_text(ida_response)}"}],
                        "isError": True
                    }

                # IDA instance should return an MCP tool result envelope already.
                content = ida_response.get("content") if isinstance(ida_response, dict) else None
                is_error = bool(ida_response.get("isError")) if isinstance(ida_response, dict) else False
                structured = ida_response.get("structuredContent") if isinstance(ida_response, dict) else None

                if structured is None and isinstance(content, list) and content:
                    # Best-effort: parse JSON text content as structured output
                    try:
                        structured = json.loads(content[0].get("text", ""))
                    except Exception:
                        structured = None

                structured = _coerce_structured_for_schema(name, structured)

                # If IDA didn't provide content, generate a readable one.
                if not content:
                    content = [{"type": "text", "text": _json_text(structured)}]

                # If the tool has an output schema, Factory requires structuredContent.
                # Even on errors, keep the structured payload if present.
                if is_error:
                    return {
                        "content": content,
                        **({"structuredContent": structured} if structured is not None else {}),
                        "isError": True,
                    }

                # Serialize structured for size checks
                structured_text = _json_text(structured)
                total_chars = len(structured_text)

                # Check if truncation needed (max_output=0 means unlimited)
                if max_output > 0 and total_chars > max_output:
                    # Cache full response text for humans (get_cached_output)
                    cache = get_cache()
                    instance_id = arguments.get("instance_id") or "unknown"
                    cache_id = cache.store(structured_text, tool_name=name, instance_id=instance_id)

                    preview_structured = _schema_preserving_preview(structured, max_output)
                    preview_text = _json_text(preview_structured)

                    truncation_notice = (
                        f"\n\n--- TRUNCATED ---\n"
                        f"Showing ~{max_output:,} of {total_chars:,} chars ({total_chars - max_output:,} remaining)\n"
                        f"cache_id: {cache_id}\n"
                        f"To get more: get_cached_output(cache_id='{cache_id}', offset={max_output})"
                    )

                    return {
                        "content": [{"type": "text", "text": preview_text[:max_output] + truncation_notice}],
                        "structuredContent": preview_structured,
                        "isError": False,
                    }

                return {
                    "content": content,
                    "structuredContent": structured,
                    "isError": False,
                }

        self.server.registry.methods["tools/call"] = custom_tools_call

    def _handle_decompile_to_file(self, arguments: dict) -> dict:
        """Decompile functions and save results to local files.

        Orchestrates list_funcs + decompile calls via IDA, writes to disk locally.
        """
        decompile_all = arguments.get("all", False)
        addrs = arguments.get("addrs", [])
        output_dir = arguments.get("output_dir")
        allow_outside_cwd = arguments.get("allow_outside_cwd", False)
        mode = arguments.get("mode", "single")
        instance_id = arguments.get("instance_id")
        if not instance_id:
            return {
                "error": "Missing required parameter 'instance_id'.",
                "hint": "Call list_instances() and pass instance_id explicitly.",
            }

        if not isinstance(output_dir, str) or not output_dir.strip():
            return {"error": "output_dir must be a non-empty string"}
        if not isinstance(allow_outside_cwd, bool):
            return {"error": "allow_outside_cwd must be a boolean"}
        if not allow_outside_cwd and not _DIR_FD_SUPPORTED:
            return {
                "error": (
                    "Default output confinement requires secure directory descriptors "
                    "on this platform. Pass allow_outside_cwd=true to use the "
                    "path-based fallback."
                )
            }

        # Inspect raw components before normalization, which would erase '..'.
        component_path = output_dir
        if os.altsep:
            component_path = component_path.replace(os.altsep, os.sep)
        if ".." in component_path.split(os.sep):
            return {"error": "output_dir must not contain '..' path components"}

        try:
            if os.path.lexists(output_dir) and not os.path.isdir(output_dir):
                return {"error": f"output_dir exists but is not a directory: {output_dir}"}

            resolved_dir = os.path.realpath(output_dir)
            if not allow_outside_cwd:
                cwd = os.path.realpath(os.getcwd())
                within_cwd = os.path.commonpath([cwd, resolved_dir]) == cwd
                if not within_cwd:
                    return {
                        "error": (
                            "output_dir must be within the current working directory. "
                            "Pass allow_outside_cwd=true to write elsewhere."
                        ),
                        "cwd": cwd,
                    }
        except (OSError, TypeError, ValueError) as exc:
            return {"error": f"invalid output_dir: {exc}"}
        output_dir = resolved_dir

        if not decompile_all and not addrs:
            return {"error": "No addresses provided. Pass 'addrs' array or set 'all' to true."}

        try:
            os.makedirs(output_dir, exist_ok=True)
            is_directory = os.path.isdir(output_dir)
        except (OSError, TypeError, ValueError) as exc:
            return {"error": f"Failed to create output_dir: {exc}"}
        if not is_directory:
            return {"error": f"output_dir exists but is not a directory: {output_dir}"}

        try:
            with _OutputDirectory(output_dir) as secured_output:
                return self._decompile_to_output_dir(
                    decompile_all=decompile_all,
                    addrs=addrs,
                    output_dir=output_dir,
                    output=secured_output,
                    mode=mode,
                    instance_id=instance_id,
                )
        except (OSError, TypeError, ValueError) as exc:
            return {"error": f"Failed to secure output_dir: {exc}"}

    def _decompile_to_output_dir(
        self,
        *,
        decompile_all: bool,
        addrs: list,
        output_dir: str,
        output: _OutputDirectory,
        mode: str,
        instance_id: str,
    ) -> dict:
        """Run router calls and write through a held output-directory identity."""
        addr_names: dict[str, str] = {}

        if decompile_all:
            addrs = []
            offset = 0
            page_size = 500
            while True:
                list_result = self.router.route_request("tools/call", {
                    "name": "list_funcs",
                    "arguments": {
                        "queries": json.dumps({"count": page_size, "offset": offset}),
                        "instance_id": instance_id,
                    }
                })
                if "error" in list_result:
                    return {"error": f"Failed to list functions: {list_result['error']}"}

                try:
                    content = list_result.get("content", [])
                    if not content:
                        break
                    raw = json.loads(content[0]["text"])
                    if not isinstance(raw, list) or not raw:
                        break
                    page_data = raw[0].get("data", [])
                    if not page_data:
                        break
                    for f in page_data:
                        if "addr" in f:
                            addrs.append(f["addr"])
                            if "name" in f:
                                addr_names[f["addr"]] = f["name"]
                    next_offset = raw[0].get("next_offset")
                    if next_offset is None or len(page_data) < page_size:
                        break
                    offset = next_offset
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    return {"error": "Failed to parse list_funcs response"}

            if not addrs:
                return {"error": "No functions found in binary"}

        success = 0
        failed = 0
        failed_addrs = []
        files_written = []

        def _call_decompile(addr: str) -> dict:
            """Call decompile and parse MCP content wrapper."""
            raw = self.router.route_request("tools/call", {
                "name": "decompile",
                "arguments": {
                    "addr": addr,
                    "instance_id": instance_id,
                }
            })
            # Router returns {"content": [{"text": "{\"addr\":...,\"code\":...}"}]}
            try:
                content = raw.get("content", [])
                if content:
                    return json.loads(content[0]["text"])
            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                pass
            return raw

        if mode == "merged":
            merged_path = os.path.join(output_dir, "decompiled.c")

            def _write_merged(f):
                nonlocal success, failed
                for addr in addrs:
                    decomp = _call_decompile(addr)
                    code = decomp.get("code")
                    if code:
                        name = addr_names.get(addr) or decomp.get("name") or addr
                        f.write(f"// {name} @ {addr}\n")
                        f.write(code)
                        f.write("\n\n")
                        success += 1
                    else:
                        failed += 1
                        failed_addrs.append(addr)
            try:
                _atomic_write_text(output, "decompiled.c", _write_merged)
            except Exception as exc:
                return {"error": f"Failed to write '{merged_path}': {exc}"}
            files_written.append("decompiled.c")
        else:
            # single mode: one file per function
            for addr in addrs:
                decomp = _call_decompile(addr)
                code = decomp.get("code")
                if code:
                    name = addr_names.get(addr) or decomp.get("name") or addr
                    safe_name = re.sub(r'[<>:"/\\|?*]', "_", name)
                    # Security: strip '..' path traversal sequences from function names
                    safe_name = safe_name.replace("..", "_")
                    # Include address to avoid collisions across duplicate function names.
                    addr_suffix = re.sub(r"[^0-9A-Fa-fx]", "_", str(addr))
                    filename = f"{safe_name}_{addr_suffix}.c"
                    filepath = os.path.join(output_dir, filename)

                    def _write_single(f):
                        f.write(f"// {name} @ {addr}\n")
                        f.write(code)
                        f.write("\n")
                    try:
                        _atomic_write_text(output, filename, _write_single)
                    except Exception as exc:
                        return {"error": f"Failed to write '{filepath}': {exc}"}
                    files_written.append(filename)
                    success += 1
                else:
                    failed += 1
                    failed_addrs.append(addr)

        return {
            "output_dir": output_dir,
            "mode": mode,
            "total": len(addrs),
            "success": success,
            "failed": failed,
            "failed_addrs": failed_addrs[:50],
            "files": files_written[:50],
            "files_total": len(files_written),
        }

    def _refresh_tools(self) -> int:
        """Refresh tool cache from IDA instances.

        Returns:
            Number of tools discovered
        """
        self._tool_cache = {}

        # Add management tools
        self._tool_cache["list_instances"] = {
            "name": "list_instances",
            "description": "List all registered IDA Pro instances with their metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "instances": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "type": {"type": "string", "description": "gui or idalib"},
                                "binary_name": {"type": "string"},
                                "binary_path": {"type": "string"},
                                "arch": {"type": "string"},
                                "host": {"type": "string"},
                                "port": {"type": "integer"},
                                "pid": {"type": "integer"},
                                "backend": {"type": "string"},
                                "owned": {"type": "boolean"},
                                "adopted": {"type": "boolean"},
                                "worker_pid": {"type": ["integer", "null"]},
                                "idle_ttl_sec": {"type": ["integer", "null"]},
                                "registered_at": {"type": "string"}
                            },
                            "required": ["id", "type", "binary_name", "binary_path", "arch", "host", "port", "pid", "registered_at"]
                        }
                    }
                },
                "required": ["count", "instances"]
            }
        }

        self._tool_cache["refresh_tools"] = {
            "name": "refresh_tools",
            "description": "Re-discover tools from IDA Pro instances.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

        self._tool_cache["compare_binaries"] = {
            "name": "compare_binaries",
            "description": "Compare two IDA instances by diffing their binary metadata, entrypoints, and segments. Takes two instance_id values and returns what is common vs unique to each.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "instance_id_a": {"type": "string", "description": "First instance ID"},
                    "instance_id_b": {"type": "string", "description": "Second instance ID"},
                },
                "required": ["instance_id_a", "instance_id_b"]
            }
        }

        self._tool_cache["list_cached_outputs"] = {
            "name": "list_cached_outputs",
            "description": "List all cached truncated outputs with cache_id, age, size, and tool name. Use this to find cache IDs for get_cached_output.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

        self._tool_cache["get_cached_output"] = {
            "name": "get_cached_output",
            "description": "Retrieve cached output from a previous tool call that was truncated. Use this to get additional chunks of large responses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cache_id": {
                        "type": "string",
                        "description": "Cache ID from the _truncated metadata of a previous response"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Starting character position (default: 0)"
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of characters to return (default: 20000, 0 = all remaining)"
                    }
                },
                "required": ["cache_id"]
            }
        }

        self._tool_cache["decompile_to_file"] = {
            "name": "decompile_to_file",
            "description": "Decompile functions and save results directly to files on disk. "
                "IMPORTANT: Each function requires a separate IDA decompile call. "
                "For large binaries, check function count with list_funcs first before using 'all'. "
                "Hundreds of functions can take minutes; thousands can take much longer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "addrs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Function addresses to decompile (e.g. ['0x1800011A0', '0x180004B20']). Required unless 'all' is true."
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Decompile all functions in the binary (default: false). Uses paginated queries to avoid blocking IDA. When true, 'addrs' is ignored."
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to save decompiled files"
                    },
                    "allow_outside_cwd": {
                        "type": "boolean",
                        "description": "Permit output_dir outside the current working directory (default: false)."
                    },
                    "mode": {
                        "type": "string",
                        "description": "Output mode: 'single' = one .c file per function (default), 'merged' = all in one file"
                    },
                    "instance_id": {
                        "type": "string",
                        "description": "Target IDA instance ID (required)"
                    }
                },
                "required": ["output_dir", "instance_id"]
            }
        }

        # Register idalib management schemas unconditionally. GUI reuse modes do
        # not need idalib, and headless mode reports a runtime error if idalib
        # is unavailable.
        for schema in idalib_tools.IDALIB_TOOL_SCHEMAS:
            self._tool_cache[schema["name"]] = schema.copy()

        _SINGLE_THREAD_WARNING = (
            " WARNING: IDA executes on a single main thread. "
            "Long-running operations will block ALL subsequent requests and make IDA unresponsive."
        )

        # Always load static IDA tool schemas so tools are visible even
        # when no IDA instance is connected.
        for tool_schema in _load_static_ida_tools():
            schema = tool_schema.copy()

            # Require explicit instance_id for all IDA tools (avoid global active instance contention).
            input_schema = schema.get("inputSchema", {}) or {}
            properties = input_schema.get("properties", {}) or {}
            required = input_schema.get("required", []) or []
            properties["instance_id"] = {
                "type": "string",
                "description": "Target IDA instance ID (required)"
            }
            if "instance_id" not in required:
                required.append("instance_id")
            input_schema["properties"] = properties
            input_schema["required"] = required
            schema["inputSchema"] = input_schema

            # Append warnings to specific tool descriptions
            if schema.get("name") == "py_eval":
                schema["description"] = (
                    schema.get("description", "") +
                    _SINGLE_THREAD_WARNING +
                    " Do NOT iterate all functions, bulk decompile, or run heavy loops. "
                    "Use decompile_to_file for batch decompilation instead."
                )
            elif schema.get("name") == "list_funcs":
                schema["description"] = (
                    schema.get("description", "") +
                    _SINGLE_THREAD_WARNING +
                    " For large binaries (100K+ functions), use count/offset pagination. "
                    "Avoid count=0 (all) with glob filters on large binaries."
                )

            self._tool_cache[schema["name"]] = schema

        # Discover IDA tools from any available instance (rediscover if needed).
        instances = self.registry.list_instances()
        if not instances:
            discovered = rediscover_instances(self.registry)
            if discovered:
                print(
                    f"[ida-fusion-mcp] Auto-discovered {len(discovered)} IDA instance(s) during refresh",
                    file=sys.stderr,
                )
            instances = self.registry.list_instances()

        if instances:
            # Copy tool schemas from the first responsive instance. Routing always requires instance_id.
            ida_tools: list[dict] = []
            for candidate_id in sorted(instances.keys()):
                instance_info = self.registry.get_instance(candidate_id)
                if not instance_info:
                    continue
                ida_tools = self._discover_ida_tools(instance_info)
                if ida_tools:
                    break

            for tool in ida_tools:
                tool_schema = tool.copy()
                input_schema = tool_schema.get("inputSchema", {}) or {}
                properties = input_schema.get("properties", {}) or {}
                required = input_schema.get("required", []) or []

                # Add instance_id parameter (required)
                properties["instance_id"] = {
                    "type": "string",
                    "description": "Target IDA instance ID (required)"
                }
                if "instance_id" not in required:
                    required.append("instance_id")

                input_schema["properties"] = properties
                input_schema["required"] = required
                tool_schema["inputSchema"] = input_schema

                # Append warnings to specific tool descriptions
                if tool.get("name") == "py_eval":
                    tool_schema["description"] = (
                        tool_schema.get("description", "") +
                        _SINGLE_THREAD_WARNING +
                        " Do NOT iterate all functions, bulk decompile, or run heavy loops. "
                        "Use decompile_to_file for batch decompilation instead."
                    )
                elif tool.get("name") == "list_funcs":
                    tool_schema["description"] = (
                        tool_schema.get("description", "") +
                        _SINGLE_THREAD_WARNING +
                        " For large binaries (100K+ functions), use count/offset pagination. "
                        "Avoid count=0 (all) with glob filters on large binaries."
                    )

                self._tool_cache[tool_schema["name"]] = tool_schema

        # MCP spec expects outputSchema to be an object schema.
        # Some clients validate all advertised tools; keep schemas conservative.
        for tool_schema in self._tool_cache.values():
            os = tool_schema.get("outputSchema")
            if not os:
                tool_schema["outputSchema"] = {"type": "object"}
                continue
            if os.get("type") != "object":
                tool_schema["outputSchema"] = {
                    "type": "object",
                    "properties": {"result": os},
                    "required": ["result"],
                }

        self._cache_valid = True
        return len(self._tool_cache)

    def _discover_ida_tools(self, instance_info: dict) -> list[dict]:
        """Discover tools from an IDA instance.

        Args:
            instance_info: Instance metadata

        Returns:
            List of tool schemas
        """
        import http.client

        from .registry import ALLOWED_HOSTS

        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")

        # Security: only connect to localhost instances
        if host not in ALLOWED_HOSTS:
            return []

        try:
            conn = http.client.HTTPConnection(host, port, timeout=10.0)
            request_body = json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            })
            conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            response_data = json.loads(response.read().decode())
            conn.close()

            if "result" in response_data:
                tools = response_data["result"].get("tools", [])
                return tools
            else:
                return []

        except Exception as e:
            print(f"[ida-fusion-mcp] Failed to discover tools from instance: {e}", file=sys.stderr)
            return []

    def run(self):
        """Run the MCP server with stdio transport."""
        # Clean up dead instances on startup
        removed = cleanup_stale_instances(self.registry)
        if removed:
            print(f"[ida-fusion-mcp] Cleaned up {len(removed)} dead instances on startup",
                  file=sys.stderr)

        # Auto-discover IDA instances if registry is empty
        if not self.registry.list_instances():
            discovered = rediscover_instances(self.registry)
            if discovered:
                print(f"[ida-fusion-mcp] Auto-discovered {len(discovered)} IDA instance(s)",
                      file=sys.stderr)
            else:
                print("[ida-fusion-mcp] No IDA instances found (start IDA with MCP plugin first)",
                      file=sys.stderr)

        # Refresh tools
        self._refresh_tools()
        print(f"[ida-fusion-mcp] Server starting with {len(self._tool_cache)} tools",
              file=sys.stderr)

        # Run server with stdio transport (idalib cleanup via atexit in IdalibManager)
        self.server.stdio()


def serve(registry_path: str | None = None, idalib_python: str | None = None):
    """Start the ida-fusion-mcp server.

    Args:
        registry_path: Optional custom registry path
        idalib_python: Python executable with idapro installed (for headless)
    """
    server = IdaFusionMcpServer(registry_path, idalib_python=idalib_python)
    server.run()
