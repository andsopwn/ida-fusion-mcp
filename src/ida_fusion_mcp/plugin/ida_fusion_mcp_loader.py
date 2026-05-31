"""IDA plugin loader for ida-fusion-mcp.

This file is placed in the IDA plugins directory (e.g., ~/.idapro/plugins/).
It bootstraps the actual plugin from the installed ida-fusion-mcp package.

The loader auto-discovers the package from multiple installation methods:
  - pip install (system/user site-packages)
  - pipx install (isolated venv)
  - homebrew Python site-packages (macOS)

Installation:
  pip install ida-fusion-mcp   (or pipx install ida-fusion-mcp)
  ida-fusion-mcp --install
"""

import sys
import importlib


def _collect_candidate_paths():
    """Collect all possible site-packages paths where ida-fusion-mcp may be installed.

    Covers: pip install, pip install --user, pipx install, homebrew Python,
    and platform-specific locations for Windows, macOS, and Linux.
    """
    import os
    from pathlib import Path

    ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    ver_nodot = f"{sys.version_info.major}{sys.version_info.minor}"
    home = Path.home()
    candidates = []

    # --- pip install --user locations ---
    # Linux
    candidates.append(home / ".local" / "lib" / f"python{ver}" / "site-packages")
    # macOS (Python.org / homebrew --user)
    candidates.append(home / "Library" / "Python" / ver / "lib" / "python" / "site-packages")
    # Windows
    candidates.append(home / "AppData" / "Roaming" / "Python" / f"Python{ver_nodot}" / "site-packages")

    # --- pipx venv location ---
    # pipx installs into ~/.local/pipx/venvs/<pkg>/lib/pythonX.Y/site-packages
    pipx_venvs = [
        home / ".local" / "pipx" / "venvs" / "ida-fusion-mcp" / "lib",
        home / ".local" / "pipx" / "venvs" / "ida-multi-mcp" / "lib",
    ]
    for pipx_venv in pipx_venvs:
        if not pipx_venv.is_dir():
            continue
        # Find the python directory inside (may differ from IDA's Python version)
        for child in pipx_venv.iterdir():
            sp = child / "site-packages"
            if sp.is_dir():
                candidates.append(sp)

    # --- homebrew Python site-packages (macOS) ---
    # Common homebrew prefixes
    for brew_prefix in ["/opt/homebrew", "/usr/local"]:
        brew_python = Path(brew_prefix) / "Cellar" / f"python@{ver}"
        if brew_python.is_dir():
            for version_dir in brew_python.iterdir():
                sp = (version_dir / "Frameworks" / "Python.framework" / "Versions"
                      / ver / "lib" / f"python{ver}" / "site-packages")
                if sp.is_dir():
                    candidates.append(sp)

    # --- System site-packages (fallback) ---
    # /usr/lib/pythonX.Y (Linux), /Library/Python/X.Y (macOS)
    candidates.append(Path("/usr") / "lib" / f"python{ver}" / "site-packages")
    candidates.append(Path("/Library") / "Python" / ver / "lib" / "python" / "site-packages")

    # Deduplicate, resolve, and filter to existing directories
    seen = set()
    result = []
    for p in candidates:
        try:
            resolved = str(p.resolve())
        except OSError:
            resolved = str(p)
        if resolved not in seen and os.path.isdir(resolved):
            seen.add(resolved)
            result.append(resolved)

    return result


def PLUGIN_ENTRY():
    """IDA plugin entry point — delegates to ida_fusion_mcp.plugin."""
    try:
        # Try importing from the installed package first
        mod = importlib.import_module("ida_fusion_mcp.plugin.ida_fusion_mcp")
        return mod.PLUGIN_ENTRY()
    except ImportError:
        pass

    # Fallback: add candidate paths and retry
    for path in _collect_candidate_paths():
        if path not in sys.path:
            sys.path.append(path)

    try:
        mod = importlib.import_module("ida_fusion_mcp.plugin.ida_fusion_mcp")
        return mod.PLUGIN_ENTRY()
    except ImportError as e:
        print(f"[ida-fusion-mcp] ERROR: Could not load plugin: {e}")
        print(f"[ida-fusion-mcp] IDA Python {sys.version_info.major}.{sys.version_info.minor}")
        print(f"[ida-fusion-mcp] Searched paths:")
        for p in _collect_candidate_paths():
            print(f"[ida-fusion-mcp]   {p}")
        print("[ida-fusion-mcp] Install with: pip install ida-fusion-mcp")
        print("[ida-fusion-mcp]   or: pipx install ida-fusion-mcp")
        # Return a dummy plugin that does nothing
        import idaapi

        class _DummyPlugin(idaapi.plugin_t):
            flags = idaapi.PLUGIN_SKIP
            comment = "ida-fusion-mcp (not installed)"
            help = ""
            wanted_name = "ida-fusion-mcp"
            wanted_hotkey = ""

            def init(self):
                return idaapi.PLUGIN_SKIP

            def run(self, arg):
                pass

            def term(self):
                pass

        return _DummyPlugin()
