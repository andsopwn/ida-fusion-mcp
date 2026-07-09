"""CLI entry point for ida-fusion-mcp.

Provides flags for running the server, listing instances, and managing installation.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .server import serve
from .registry import InstanceRegistry

SERVER_NAME = "ida-fusion-mcp"
LEGACY_SERVER_NAMES = (
    "ida-multi-mcp",
    "github.com/MeroZemory/ida-multi-mcp",
)

_CLIENT_COMMANDS: dict[str, tuple[str, ...]] = {
    "Claude Code": ("claude",),
    "Cursor": ("cursor",),
    "Codex": ("codex",),
    "Gemini CLI": ("gemini",),
    "Qwen Coder": ("qwen",),
    "Copilot CLI": ("copilot",),
    "Crush": ("crush",),
    "Amazon Q": ("q",),
    "Opencode": ("opencode",),
    "Factory Droid": ("droid", "factory"),
    "VS Code": ("code",),
}

_MACOS_CLIENT_APPS: dict[str, tuple[str, ...]] = {
    "Claude": ("Claude.app",),
    "Cursor": ("Cursor.app",),
    "Windsurf": ("Windsurf.app",),
    "LM Studio": ("LM Studio.app",),
    "Antigravity IDE": ("Antigravity.app",),
    "Zed": ("Zed.app",),
    "BoltAI": ("BoltAI.app",),
    "Perplexity": ("Perplexity.app",),
    "Warp": ("Warp.app",),
    "Kiro": ("Kiro.app",),
    "Trae": ("Trae.app",),
    "VS Code": ("Visual Studio Code.app",),
}

_VSCODE_EXTENSION_IDS: dict[str, tuple[str, ...]] = {
    "Augment Code": ("augment.vscode-augment",),
    "Qodo Gen": ("Codium.qodogen",),
}


def _client_is_detected(name: str, config_path: Path) -> bool:
    """Return true only for an existing config or a real client install."""
    extension_ids = _VSCODE_EXTENSION_IDS.get(name)
    if extension_ids is not None:
        return any(
            _vscode_extension_is_installed(extension_id)
            for extension_id in extension_ids
        )

    if config_path.is_file():
        return True

    for command in _CLIENT_COMMANDS.get(name, ()):
        if shutil.which(command):
            return True

    if sys.platform == "darwin":
        roots = (Path("/Applications"), Path.home() / "Applications")
        return any(
            _macos_app_is_installed(root / app_name)
            for root in roots
            for app_name in _MACOS_CLIENT_APPS.get(name, ())
        )

    return False


def _vscode_extension_is_installed(extension_id: str) -> bool:
    extension_root = Path.home() / ".vscode" / "extensions"
    expected = extension_id.casefold()
    try:
        return any(
            entry.is_dir()
            and (
                entry.name.casefold() == expected
                or entry.name.casefold().startswith(expected + "-")
            )
            for entry in extension_root.iterdir()
        )
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return False


def _macos_app_is_installed(app_path: Path) -> bool:
    executable_dir = app_path / "Contents" / "MacOS"
    try:
        return any(
            child.is_file() and os.access(child, os.X_OK)
            for child in executable_dir.iterdir()
        )
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return False

# ---------------------------------------------------------------------------
# IDA installation auto-detection (used by --install)
# ---------------------------------------------------------------------------

_IDA_VERSION_RE = re.compile(r"(\d+\.\d+)")
_TOML_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")

_IDA_DIR_MARKERS = (
    "ida64.exe", "ida.exe", "ida64", "ida",
    "idalib.dll", "ida.dll", "libidalib.dylib", "libida.dylib",
    "libidalib.so", "libida.so",
)


def _normalize_ida_dir(value: str | os.PathLike[str] | None) -> str | None:
    """Return the IDA runtime directory, including inside a macOS app bundle."""
    if value is None:
        return None
    try:
        path_value = os.fspath(value)
    except TypeError:
        return None
    if not isinstance(path_value, str) or not path_value.strip():
        return None
    raw = Path(path_value).expanduser()
    candidates = (raw / "Contents" / "MacOS", raw)
    for candidate in candidates:
        if candidate.is_dir() and any(
            (candidate / marker).exists() for marker in _IDA_DIR_MARKERS
        ):
            return str(candidate.resolve())
    return None


def _normalize_idadir_environment() -> str | None:
    """Normalize IDADIR in this process so future idalib workers inherit it."""
    raw = os.environ.get("IDADIR", "").strip()
    if not raw:
        return None
    normalized = _normalize_ida_dir(raw)
    if normalized is not None:
        os.environ["IDADIR"] = normalized
    return normalized


def _ida_scan_roots() -> tuple[Path, ...]:
    if sys.platform == "win32":
        roots = [
            Path(drive)
            for drive in ("C:\\", "D:\\")
            if Path(drive).is_dir()
        ]
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        if program_files.is_dir():
            roots.append(program_files)
        program_files_x86 = os.environ.get("ProgramFiles(x86)")
        if program_files_x86 and Path(program_files_x86).is_dir():
            roots.append(Path(program_files_x86))
        return tuple(roots)
    if sys.platform == "darwin":
        return (Path("/Applications"), Path.home() / "Applications")
    return (Path("/opt"), Path.home())


def _detect_ida_dir() -> str | None:
    """Resolve IDADIR, idapro config, or the newest scanned IDA runtime."""
    env_dir = _normalize_ida_dir(os.environ.get("IDADIR", "").strip())
    if env_dir:
        return env_dir

    if sys.platform == "win32":
        config_path = Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    else:
        config_path = Path.home() / ".idapro" / "ida-config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        cfg_dir = _normalize_ida_dir(
            config.get("Paths", {}).get("ida-install-dir", "")
        )
        if cfg_dir:
            return cfg_dir
    except (OSError, AttributeError, json.JSONDecodeError):
        pass

    candidates: list[tuple[tuple[int, ...], str]] = []
    seen: set[str] = set()
    for root in _ida_scan_roots():
        if not root.is_dir():
            continue
        try:
            entries = tuple(root.iterdir())
        except (FileNotFoundError, PermissionError):
            continue
        for entry in entries:
            if not entry.is_dir() or "ida" not in entry.name.lower():
                continue
            normalized = _normalize_ida_dir(entry)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            match = _IDA_VERSION_RE.search(entry.name)
            version = (
                tuple(int(part) for part in match.group(1).split("."))
                if match else (0, 0)
            )
            candidates.append((version, normalized))

    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _replace_or_overwrite_file(src: str, dst: str, *, attempts: int = 6) -> bool:
    """Atomically replace a regular destination, or fail without changing it.

    On Windows, os.replace() can fail with WinError 5 if the destination is open
    without FILE_SHARE_DELETE (common for editor-held settings files). Retry those
    transient locks, but never fall back to an in-place write because a failed copy
    could corrupt the existing configuration.
    """

    def remove_source() -> None:
        try:
            os.unlink(src)
        except OSError:
            pass

    if os.path.islink(dst):
        print(f"  Warning: skipping symlink target: {dst}", file=sys.stderr)
        remove_source()
        return False

    # Retry only atomic replacement; the destination stays intact on failure.
    for i in range(max(1, attempts)):
        try:
            os.replace(src, dst)
            return True
        except PermissionError:
            if sys.platform == "win32" and i < attempts - 1:
                time.sleep(0.05 * (i + 1))
                continue
            break

    remove_source()
    return False


def get_python_executable():
    """Get the path to the Python executable (venv-aware)."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env):
    """Copy Python environment variables needed by MCP clients.

    MCP servers are run without inheriting the environment, so we need to forward
    the environment variables that affect Python's dependency resolution by hand.
    Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    """
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, include_type: bool = False):
    """Generate MCP server configuration for ida-fusion-mcp."""
    mcp_config = {
        "command": get_python_executable(),
        "args": ["-m", "ida_fusion_mcp"],
    }

    # Factory Droid's ~/.factory/mcp.json schema requires an explicit transport type.
    if include_type:
        mcp_config["type"] = "stdio"

    env = {}
    if copy_python_env(env):
        mcp_config["env"] = env
    return mcp_config


def print_mcp_config():
    """Print MCP client configuration JSON."""
    print(
        json.dumps(
            {"mcpServers": {SERVER_NAME: generate_mcp_config()}}, indent=2
        )
    )


def _mapping_child(
    parent: dict, key: str, *, create: bool, label: str
) -> dict | None:
    if key not in parent:
        if not create:
            return None
        parent[key] = {}
    value = parent[key]
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object/table")
    return value


def _get_server_mapping(
    config: dict, *, name: str, is_toml: bool, create: bool
) -> dict | None:
    """Locate one client's MCP-server mapping without replacing bad data."""
    if not isinstance(config, dict):
        raise ValueError("client config root must be an object/table")
    if is_toml:
        return _mapping_child(
            config, "mcp_servers", create=create, label="mcp_servers"
        )
    if name == "VS Code":
        mcp = _mapping_child(config, "mcp", create=create, label="mcp")
        if mcp is None:
            return None
        return _mapping_child(
            mcp, "servers", create=create, label="mcp.servers"
        )
    if name == "Visual Studio 2022":
        return _mapping_child(config, "servers", create=create, label="servers")
    return _mapping_child(config, "mcpServers", create=create, label="mcpServers")


def _mutate_client_config(
    config: dict, *, name: str, is_toml: bool, uninstall: bool
) -> bool:
    """Apply only ida-fusion-owned changes and report whether data changed."""
    mcp_servers = _get_server_mapping(
        config, name=name, is_toml=is_toml, create=not uninstall
    )
    if mcp_servers is None:
        return False
    if uninstall:
        if SERVER_NAME not in mcp_servers:
            return False
        del mcp_servers[SERVER_NAME]
        return True

    changed = False
    for old_name in LEGACY_SERVER_NAMES:
        if old_name in mcp_servers:
            del mcp_servers[old_name]
            changed = True
    desired = generate_mcp_config(include_type=(name == "Factory Droid"))
    if mcp_servers.get(SERVER_NAME) != desired:
        mcp_servers[SERVER_NAME] = desired
        changed = True
    return changed


def install_mcp_servers(
    uninstall: bool = False,
    quiet: bool = False,
    *,
    failures: list[str] | None = None,
) -> tuple[int, int]:
    """Auto-configure all known MCP clients for ida-fusion-mcp."""
    def record_failure(name: str, config_path: Path | None, reason: object) -> None:
        if failures is None:
            return
        location = f" ({config_path})" if config_path is not None else ""
        failures.append(f"{name}{location}: {reason}")

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "Factory Droid": (
                os.path.join(os.path.expanduser("~"), ".factory"),
                "mcp.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "Factory Droid": (
                os.path.join(os.path.expanduser("~"), ".factory"),
                "mcp.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "Factory Droid": (
                os.path.join(os.path.expanduser("~"), ".factory"),
                "mcp.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        record_failure("MCP client configuration", None, "unsupported platform")
        return 0, 0

    # Optional TOML support (Python 3.11+ has tomllib built-in)
    try:
        import tomllib
    except ImportError:
        tomllib = None

    try:
        import tomli_w
    except ImportError:
        tomli_w = None

    installed = 0
    skipped = 0
    detected_any = False
    for name, (config_dir, config_file) in configs.items():
        config_path = Path(config_dir) / config_file
        is_toml = config_path.suffix == ".toml"
        try:
            if uninstall:
                detected = config_path.is_file()
            else:
                detected = _client_is_detected(name, config_path)
            if not detected:
                skipped += 1
                if not quiet:
                    action = "uninstall" if uninstall else "installation"
                    print(
                        f"Skipping {name} {action}\n"
                        f"  Config: {config_path} (client not detected)"
                    )
                continue
            detected_any = True

            if is_toml and tomllib is None:
                skipped += 1
                record_failure(name, config_path, "TOML support is not available")
                if not quiet:
                    print(
                        f"Skipping {name} "
                        "(TOML support not available, need Python 3.11+)"
                    )
                continue

            if config_path.is_file():
                with open(
                    config_path,
                    "rb" if is_toml else "r",
                    encoding=None if is_toml else "utf-8",
                ) as f:
                    data = f.read()
                if not data or (not is_toml and not data.strip()):
                    config = {}
                elif is_toml:
                    config = tomllib.loads(data.decode("utf-8"))
                else:
                    config = json.loads(data)
            else:
                config = {}

            changed = _mutate_client_config(
                config, name=name, is_toml=is_toml, uninstall=uninstall
            )
            if not changed:
                skipped += 1
                if not quiet:
                    action = "uninstall" if uninstall else "installation"
                    print(
                        f"Skipping {name} {action}\n"
                        f"  Config: {config_path} (no change)"
                    )
                continue

            config_path.parent.mkdir(parents=True, exist_ok=True)
            suffix = ".toml" if is_toml else ".json"
            fd, temp_path = tempfile.mkstemp(
                dir=str(config_path.parent),
                prefix=".tmp_",
                suffix=suffix,
                text=True,
            )
            try:
                with os.fdopen(
                    fd,
                    "wb" if is_toml else "w",
                    encoding=None if is_toml else "utf-8",
                ) as f:
                    if is_toml:
                        if tomli_w is not None:
                            f.write(tomli_w.dumps(config).encode("utf-8"))
                        else:
                            import io

                            buf = io.StringIO()
                            _write_toml_fallback(buf, config)
                            f.write(buf.getvalue().encode("utf-8"))
                    else:
                        json.dump(config, f, indent=2)
                if not _replace_or_overwrite_file(
                    str(temp_path), str(config_path)
                ):
                    skipped += 1
                    record_failure(
                        name, config_path, "atomic configuration update failed"
                    )
                    if not quiet:
                        action = "uninstall" if uninstall else "installation"
                        print(
                            f"Skipping {name} {action}\n"
                            f"  Config: {config_path} "
                            "(permission denied or unsafe destination; "
                            "close the client and retry)"
                        )
                    continue
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

            installed += 1
            if not quiet:
                action = "Uninstalled" if uninstall else "Installed"
                print(
                    f"{action} {name} MCP server (restart required)\n"
                    f"  Config: {config_path}"
                )
        except Exception as exc:
            skipped += 1
            record_failure(name, config_path, exc)
            if not quiet:
                print(f"Skipping {name}\n  Config: {config_path} ({exc})")

    if not uninstall and installed == 0 and not quiet:
        if detected_any:
            print(
                "No client configurations were updated. "
                "Review the messages above for details."
            )
        else:
            print(
                "No MCP clients found. For unsupported MCP clients, "
                "use the following config:\n"
            )
            print_mcp_config()
    return installed, skipped


def _toml_quote_string(value: str) -> str:
    """Quote a TOML basic string, including the forbidden DEL control."""
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def _toml_quote_key(key: str) -> str:
    """Quote TOML keys when they are not valid bare keys."""
    if _TOML_BARE_KEY_RE.fullmatch(key):
        return key
    return _toml_quote_string(key)


def _toml_format_value(value):
    """Serialize values produced by Python 3.11 tomllib without data loss."""
    if isinstance(value, str):
        return _toml_quote_string(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, list):
        return "[" + ", ".join(_toml_format_value(item) for item in value) + "]"
    if isinstance(value, dict):
        body = ", ".join(
            f"{_toml_quote_key(key)} = {_toml_format_value(item)}"
            for key, item in value.items()
        )
        return "{ " + body + " }"
    if isinstance(value, (int, float)):
        return str(value)
    raise TypeError(f"Unsupported TOML value type: {type(value).__name__}")


def _write_toml_fallback(f, config, prefix=()):
    """Minimal TOML writer fallback when tomli_w is not available."""
    scalar_items = []
    table_items = []
    for key, value in config.items():
        if isinstance(value, dict):
            table_items.append((key, value))
        else:
            scalar_items.append((key, value))

    if prefix:
        table_name = ".".join(_toml_quote_key(part) for part in prefix)
        f.write(f"[{table_name}]\n")

    for key, value in scalar_items:
        f.write(f"{_toml_quote_key(key)} = {_toml_format_value(value)}\n")

    if prefix and scalar_items and table_items:
        f.write("\n")

    for index, (key, value) in enumerate(table_items):
        if prefix or index > 0 or scalar_items:
            f.write("\n")
        _write_toml_fallback(f, value, (*prefix, key))


def cmd_list(args):
    """List all registered IDA instances."""
    registry = InstanceRegistry(args.registry)
    instances = registry.list_instances()

    if not instances:
        print("No IDA instances registered.")
        print("Open IDA Pro with the ida-fusion-mcp plugin to register an instance.")
        return

    print(f"Registered IDA instances ({len(instances)}):\n")
    for instance_id, info in instances.items():
        print(f"  {instance_id}")
        print(f"    Binary: {info.get('binary_name', 'unknown')}")
        print(f"    Path: {info.get('binary_path', 'unknown')}")
        print(f"    Arch: {info.get('arch', 'unknown')}")
        print(f"    Port: {info.get('port', 0)}")
        print(f"    PID: {info.get('pid', 0)}")
        print()


def _get_ida_plugins_dir(custom_dir=None):
    """Detect the IDA Pro plugins directory.

    Args:
        custom_dir: Custom IDA directory override

    Returns:
        Path to IDA plugins directory
    """
    if custom_dir:
        return Path(custom_dir) / "plugins"

    # Platform-specific defaults
    if sys.platform == "win32":
        # Windows: %APPDATA%/Hex-Rays/IDA Pro/plugins/
        appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return appdata / "Hex-Rays" / "IDA Pro" / "plugins"
    elif sys.platform == "darwin":
        # macOS: ~/.idapro/plugins/
        return Path.home() / ".idapro" / "plugins"
    else:
        # Linux: ~/.idapro/plugins/
        return Path.home() / ".idapro" / "plugins"


def _configure_idalib_path(ida_dir: str | None = None) -> bool:
    """Write the normalized IDA runtime directory used by the idapro package."""
    explicit = ida_dir is not None
    if explicit:
        detected = _normalize_ida_dir(ida_dir)
        if detected is None:
            print(f"\n  [!!] Invalid IDA directory: {ida_dir}")
            return False
    else:
        env_dir = _normalize_idadir_environment()
        if env_dir:
            print(f"\n  [ok] IDADIR already set: {env_dir}")
            detected = env_dir
        else:
            detected = _detect_ida_dir()
            if detected is None:
                print("\n  [--] Could not auto-detect IDA installation directory.")
                print(
                    "       Pass --ida-dir or set IDADIR for headless "
                    "idalib support."
                )
                return False

    if sys.platform == "win32":
        config_path = Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    else:
        config_path = Path.home() / ".idapro" / "ida-config.json"
    try:
        config = (
            json.loads(config_path.read_text(encoding="utf-8"))
            if config_path.is_file()
            else {}
        )
        if not isinstance(config, dict):
            raise ValueError("ida-config.json root must be an object")
        paths = config.setdefault("Paths", {})
        if not isinstance(paths, dict):
            raise ValueError("ida-config.json Paths must be an object")
        paths["ida-install-dir"] = detected
        config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(
            dir=str(config_path.parent),
            prefix=".ida-config-",
            suffix=".json",
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=4)
            if not _replace_or_overwrite_file(temp_path, str(config_path)):
                return False
            temp_path = ""
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
        print(f"\n  [ok] IDA runtime directory: {detected}")
        print(f"       Written to: {config_path}")
        return True
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"\n  [!!] Failed to write ida-config.json: {exc}")
        print(f"       Set IDADIR={detected} manually.")
        return False


def cmd_install(args):
    """Install the IDA plugin and configure MCP clients."""
    normalized_ida_dir = None
    if args.ida_dir is not None:
        normalized_ida_dir = _normalize_ida_dir(args.ida_dir)
        if normalized_ida_dir is None:
            print(f"  [!!] Invalid IDA directory: {args.ida_dir}")
            return 1

    print("Installing ida-fusion-mcp...\n")

    # 1. Check prerequisites
    try:
        import ida_fusion_mcp
        print(f"  [ok] ida-fusion-mcp package found (v{ida_fusion_mcp.__version__})")
    except ImportError:
        print("  [!!] ida-fusion-mcp package not found in Python path")
        print(
            "       Install from Git: python -m pip install "
            "git+https://github.com/andsopwn/ida-fusion-mcp.git"
        )
        return 1

    # 2. Install IDA plugin loader
    ida_plugins_dir = _get_ida_plugins_dir(normalized_ida_dir)

    if not ida_plugins_dir.exists():
        print(f"\n  Creating IDA plugins directory: {ida_plugins_dir}")
        ida_plugins_dir.mkdir(parents=True, exist_ok=True)

    # Copy the loader file as ida_fusion_mcp.py into IDA's plugins directory.
    # Also clean the legacy ida_multi_mcp.py loader to avoid duplicate plugin entries.
    loader_source = Path(__file__).parent / "plugin" / "ida_fusion_mcp_loader.py"
    loader_dest = ida_plugins_dir / "ida_fusion_mcp.py"
    legacy_loader_dest = ida_plugins_dir / "ida_multi_mcp.py"
    if legacy_loader_dest.exists() or legacy_loader_dest.is_symlink():
        legacy_loader_dest.unlink()

    # Try symlink first (development-friendly), fall back to copy
    # Use a temporary name + rename to avoid TOCTOU race between unlink/symlink
    import tempfile
    loader_tmp = None
    try:
        # Create symlink/copy at a temp path in the same directory, then atomically rename
        tmp_fd, loader_tmp = tempfile.mkstemp(
            prefix=".ida_fusion_mcp_", suffix=".tmp",
            dir=str(ida_plugins_dir),
        )
        os.close(tmp_fd)
        os.unlink(loader_tmp)  # Remove the temp file so we can create symlink at this path

        try:
            Path(loader_tmp).symlink_to(loader_source)
            os.replace(loader_tmp, str(loader_dest))
            loader_tmp = None  # Successfully replaced, no cleanup needed
            print(f"\n  Symlinked plugin: {loader_dest} -> {loader_source}")
        except (OSError, NotImplementedError):
            # Symlink failed, fall back to copy + rename
            shutil.copy2(loader_source, loader_tmp)
            os.replace(loader_tmp, str(loader_dest))
            loader_tmp = None
            print(f"\n  Copied plugin to: {loader_dest}")
    finally:
        if loader_tmp is not None:
            try:
                os.unlink(loader_tmp)
            except OSError:
                pass

    print("\n  [ok] IDA plugin installed!")

    # 3. Auto-detect IDA installation and write to ida-config.json for idalib
    idalib_configured = _configure_idalib_path(normalized_ida_dir)
    if normalized_ida_dir is not None and not idalib_configured:
        print("\n  [!!] Explicit --ida-dir could not be configured for idalib.")
        return 1

    # 4. Auto-configure MCP clients
    print()
    install_mcp_servers()

    print("\n" + "=" * 60)
    print("Next steps:")
    print("  1. Restart your MCP client(s) for the config to take effect")
    print("  2. Open IDA Pro - the plugin auto-loads (PLUGIN_FIX)")
    print("  3. Run 'ida-fusion-mcp --list' to verify instances")
    print("=" * 60)
    return 0


def cmd_uninstall(args):
    """Uninstall the IDA plugin and remove MCP client configuration."""
    normalized_ida_dir = None
    if args.ida_dir is not None:
        normalized_ida_dir = _normalize_ida_dir(args.ida_dir)
        if normalized_ida_dir is None:
            print(f"  [!!] Invalid IDA directory: {args.ida_dir}")
            return 1

    print("Uninstalling ida-fusion-mcp...\n")

    # 1. Remove IDA plugin
    ida_plugins_dir = _get_ida_plugins_dir(normalized_ida_dir)
    removed_any_plugin = False
    for loader_dest in (ida_plugins_dir / "ida_fusion_mcp.py", ida_plugins_dir / "ida_multi_mcp.py"):
        if loader_dest.exists() or loader_dest.is_symlink():
            loader_dest.unlink()
            removed_any_plugin = True
            print(f"  Removed plugin: {loader_dest}")
    if not removed_any_plugin:
        print(f"  Plugin not found at {ida_plugins_dir}")

    # 2. Clean up registry
    registry_dir = Path.home() / ".ida-mcp"
    if registry_dir.exists():
        # Security: don't follow symlinks during uninstall (prevent arbitrary deletion)
        if registry_dir.is_symlink():
            registry_dir.unlink()
            print(f"  Removed registry symlink: {registry_dir}")
        else:
            # Only remove known files, not arbitrary directory trees
            for known_file in ["instances.json", "instances.json.lock"]:
                fpath = registry_dir / known_file
                if fpath.exists() and not fpath.is_symlink():
                    fpath.unlink()
            # Remove directory only if empty (safe)
            try:
                registry_dir.rmdir()
            except OSError:
                # Directory not empty (has unexpected files), leave it
                pass
            print(f"  Removed registry: {registry_dir}")

    # 3. Remove MCP client configuration
    print()
    config_failures: list[str] = []
    install_mcp_servers(uninstall=True, failures=config_failures)

    if config_failures:
        print("\n  [!!] ida-fusion-mcp uninstall incomplete.")
        print("       Failed to update these client configurations:")
        for failure in config_failures:
            print(f"       - {failure}")
        return 1

    print("\n  [ok] ida-fusion-mcp uninstalled!")
    return 0


def cmd_config(args):
    """Print MCP client configuration JSON."""
    print_mcp_config()
    return 0


def _validate_idalib_python(value: str) -> tuple[str | None, str | None]:
    """Validate an explicitly selected worker Python without importing idapro here."""
    resolved = shutil.which(value)
    if resolved is None:
        candidate = Path(value).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = str(candidate.resolve())
    if resolved is None:
        return None, f"idalib Python executable not found: {value}"

    probes = (
        (
            "idapro",
            "install ida-fusion-mcp[idalib] with that interpreter",
        ),
        (
            "ida_fusion_mcp.idalib_worker",
            "install ida-fusion-mcp with that interpreter",
        ),
    )
    for module, recovery in probes:
        try:
            probe = subprocess.run(
                [resolved, "-c", f"import {module}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (
                None,
                f"failed to probe {module} with idalib Python {resolved}: {exc}",
            )
        if probe.returncode != 0:
            return None, f"{resolved} cannot import {module}; {recovery}"
    return resolved, None


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ida-fusion-mcp: Multi-instance MCP server for IDA Pro"
    )
    parser.add_argument(
        "--install", action="store_true",
        help="Install the IDA plugin and configure MCP clients"
    )
    parser.add_argument(
        "--uninstall", action="store_true",
        help="Uninstall the IDA plugin, clean up registry, and remove MCP client config"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all registered IDA instances"
    )
    parser.add_argument(
        "--config", action="store_true",
        help="Print MCP client configuration JSON"
    )
    parser.add_argument(
        "--ida-dir", type=str, default=None,
        help="Custom IDA Pro directory (for --install/--uninstall)"
    )
    parser.add_argument(
        "--registry", type=str, default=None,
        help="Path to registry JSON file (default: ~/.ida-mcp/instances.json)"
    )
    parser.add_argument(
        "--idalib-python", type=str, default=None,
        help="Python executable with idapro installed (for headless idalib sessions). "
             "Defaults to the same Python running this server."
    )

    args = parser.parse_args()
    _normalize_idadir_environment()

    if args.install:
        sys.exit(cmd_install(args))
    elif args.uninstall:
        sys.exit(cmd_uninstall(args))
    elif args.list:
        cmd_list(args)
        return
    elif args.config:
        sys.exit(cmd_config(args))
    else:
        idalib_python = args.idalib_python
        if idalib_python is not None:
            idalib_python, error = _validate_idalib_python(idalib_python)
            if error is not None:
                parser.error(error)
        serve(registry_path=args.registry, idalib_python=idalib_python)


if __name__ == "__main__":
    main()
