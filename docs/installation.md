# ida-fusion-mcp Installation Guide

This guide is for AI agents. Follow each step exactly.

Last updated: 2026-07-10
Governance reference: `docs/README.md`
Authority note: this document is operational guidance and must not redefine contracts.

## Prerequisites

| Mode | IDA edition/version | Python | Extra package |
|---|---|---|---|
| GUI plugin | IDA Pro/Home 8.3+ | IDA's matching Python, server on 3.11+ | none |
| Managed headless | IDA Pro 9.x with `libidalib` | server/worker on 3.11+ | `ida-fusion-mcp[idalib]` |

Post-change v0.1.1 GUI routing and managed idalib are verified with IDA Pro 9.3
on macOS arm64, including a real GUI restart and managed-session lifecycle.

## Important: IDA Python Version Mismatch

IDA Pro bundles or links its own Python interpreter, which **may differ from your system default Python**. For example:
- macOS system Python may be 3.14, but IDA uses homebrew's Python 3.11
- Windows system Python may be 3.13, but IDA uses its bundled Python 3.12

The ida-fusion-mcp package must be importable from **IDA's Python**, not just your terminal's Python.

The plugin loader automatically searches common installation paths (pip --user, pipx venvs, homebrew site-packages), but matching the Python version is the most reliable approach.

## Installation

## Agent Execution Contract (for AI tools)

When an AI agent follows this guide, it should execute the workflow in this exact order:
1. Run **Pre-flight Auto-Diagnostics** and fix blocking issues.
2. Run platform-specific **Installation** steps.
3. Run **Post-flight Auto-Diagnostics**.
4. If any check fails, run **Auto-Remediation Playbook**, then re-run post-flight checks.
5. Do not report success until all required checks pass.

## Pre-flight Auto-Diagnostics

Run these checks before installing.

### 1) Python / pip baseline

```bash
python --version
python -m pip --version
```

Pass criteria:
- Python is `3.11+`
- `pip` command works for the same interpreter

### 2) CLI availability check (non-blocking)

```bash
ida-fusion-mcp --list
```

Interpretation:
- If this fails with command not found, installation is still allowed.
- If this succeeds, record current state for comparison after install.

### 3) IDA plugin directory write check

macOS/Linux:
```bash
test -d ~/.idapro/plugins || mkdir -p ~/.idapro/plugins
test -w ~/.idapro/plugins && echo "plugins dir writable"
```

Windows (PowerShell):
```powershell
if (!(Test-Path "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins")) { New-Item -ItemType Directory -Path "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins" | Out-Null }
if (Test-Path "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins") { "plugins dir exists" }
```

### 4) Optional cleanup of stale installs (recommended)

```bash
ida-fusion-mcp --uninstall
```

If command is unavailable, continue with install.

### macOS

**Option A: pipx (recommended for CLI) + pip --user for IDA**

```bash
# 1. Install CLI tool via pipx (runs ida-fusion-mcp serve, list, install, etc.)
pipx install git+https://github.com/andsopwn/ida-fusion-mcp.git

# 2. Find which Python version IDA uses (check IDA console or run):
#    Python> import sys; print(sys.version)
#    e.g., "3.11.14" means IDA uses Python 3.11

# 3. Install package for IDA's Python version
#    Replace "python3.11" with IDA's actual Python version
python3.11 -m pip install --user git+https://github.com/andsopwn/ida-fusion-mcp.git

# 4. Install IDA plugin + configure all MCP clients
ida-fusion-mcp --install
```

**Option B: pip install --user with IDA's Python only**

```bash
# 1. Install using IDA's Python version directly
python3.11 -m pip install --user --break-system-packages git+https://github.com/andsopwn/ida-fusion-mcp.git

# 2. Install IDA plugin + configure all MCP clients
python3.11 -m ida_fusion_mcp --install
```

For a system-wide IDA application bundle, both the bundle root and normalized
runtime payload are accepted:

```bash
ida-fusion-mcp --install --ida-dir "/Applications/IDA Professional 9.3.app"
# Equivalent normalized payload path:
ida-fusion-mcp --install --ida-dir "/Applications/IDA Professional 9.3.app/Contents/MacOS"
```

For managed headless sessions, install and verify the optional dependency with
the exact worker interpreter:

```bash
python3.11 -m pip install --upgrade \
  "ida-fusion-mcp[idalib] @ git+https://github.com/andsopwn/ida-fusion-mcp.git"
python3.11 -c "import idapro; print(idapro.__file__)"
```

When the licensed IDA bundle supplies the `idapro` wheel directly, install both
ida-fusion-mcp and that wheel into a separate worker interpreter, then pass the
interpreter explicitly:

```bash
/path/to/idalib-python -m pip install \
  git+https://github.com/andsopwn/ida-fusion-mcp.git
/path/to/idalib-python -m pip install \
  "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/idapro-0.0.7-py3-none-any.whl"
ida-fusion-mcp --idalib-python /path/to/idalib-python
```

**How to find IDA's Python version on macOS:**
1. Open IDA Pro with any binary
2. In the IDA console (Output window), run:
   ```
   Python> import sys; print(sys.version)
   ```
3. The first two numbers (e.g., `3.11`) are what you need

### Windows

```bash
# 0. (Recommended) Clean previous install to avoid stale scripts/config
ida-fusion-mcp --uninstall
python -m pip uninstall -y ida-fusion-mcp

# 1. Install ida-fusion-mcp
python -m pip install git+https://github.com/andsopwn/ida-fusion-mcp.git

# 2. Install IDA plugin + configure all MCP clients
ida-fusion-mcp --install
```

On Windows, IDA typically uses the system Python or its bundled Python. If using IDA's bundled Python, install to the matching version:

```bash
# If IDA uses Python 3.12 but your system default is different:
py -3.12 -m pip install git+https://github.com/andsopwn/ida-fusion-mcp.git
```

If IDA is installed in a custom location:
```bash
ida-fusion-mcp --install --ida-dir "C:/Program Files/IDA Pro 9.0"
```

If Codex fails to start with a TOML parse error from `%USERPROFILE%\.codex\config.toml`, fix Windows paths as literal TOML strings/keys.

Use this form (safe):
```toml
[projects.'\\?\C:\Git\andsopwn\ida-fusion-mcp']
trust_level = "trusted"

[mcp_servers.ida-fusion-mcp]
command = 'C:\Users\andsopwn\AppData\Local\Programs\Python\Python311\python.exe'
args = ["-m", "ida_fusion_mcp"]
```

Avoid this form (invalid in TOML):
```toml
[projects.\\?\C:\Git\andsopwn\ida-fusion-mcp]  # invalid unquoted key
command = "C:\Users\...\python.exe"       # backslashes parsed as escapes
```

### Linux

```bash
# 1. Install ida-fusion-mcp
pip install --user git+https://github.com/andsopwn/ida-fusion-mcp.git

# 2. Install IDA plugin + configure all MCP clients
ida-fusion-mcp --install
```

## MCP Client Configuration

`ida-fusion-mcp --install` automatically configures all detected MCP clients:
- Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more

For clients not auto-detected or to view the configuration JSON, run:
```bash
ida-fusion-mcp --config
```

## Verify

1. Open IDA Pro with any binary — the plugin auto-loads.
2. Check the IDA console for: `[ida-fusion-mcp] Registered as instance 'xxxx'`
3. Run: `ida-fusion-mcp --list` to confirm the instance is visible
4. In your MCP client, try calling `list_instances()` tool

## Post-flight Auto-Diagnostics

Run these checks immediately after installation.

### 1) CLI and module import health

```bash
ida-fusion-mcp --config
python -c "import ida_fusion_mcp; print(ida_fusion_mcp.__version__)"
```

Pass criteria:
- `--config` prints valid JSON
- Python import succeeds

### 2) Plugin deployment health

macOS/Linux default per-user directory:
```bash
ls -l ~/.idapro/plugins/ida_fusion_mcp_loader.py
```

macOS explicit application-bundle directory:
```bash
ls -l "/Applications/IDA Professional 9.3.app/Contents/MacOS/plugins/ida_fusion_mcp_loader.py"
```

Windows (PowerShell):
```powershell
Get-Item "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins\\ida_fusion_mcp_loader.py"
```

Pass criteria:
- loader file exists in IDA plugins directory

### 3) Runtime registration health (requires IDA open with a binary)

```bash
ida-fusion-mcp --list
```

Pass criteria:
- at least 1 registered instance appears

### 4) MCP tool-plane health (from AI client)

Required calls:
1. `list_instances()`
2. one safe tool with explicit `instance_id` (e.g. `list_funcs` with small pagination)

Pass criteria:
- both calls succeed without transport/protocol errors

## Auto-Remediation Playbook

If post-flight checks fail, apply fixes in order.

1. Python mismatch suspected:
   - Re-check IDA console Python version (`import sys; print(sys.version)`).
   - On macOS/Linux, reinstall with the exact IDA version: `python3.11 -m pip install --upgrade git+https://github.com/andsopwn/ida-fusion-mcp.git`.
   - On Windows, use: `py -3.12 -m pip install --upgrade git+https://github.com/andsopwn/ida-fusion-mcp.git`.
2. Plugin loader missing:
   - Re-run `ida-fusion-mcp --install` for the per-user plugin directory.
   - For the macOS application bundle, run `ida-fusion-mcp --install --ida-dir "/Applications/IDA Professional 9.3.app"`.
3. No instances registered:
   - Restart IDA.
   - Open any binary.
   - Confirm IDA output contains registration log.
   - Re-run `ida-fusion-mcp --list`.
4. MCP client cannot call tools:
   - Restart the MCP client process.
   - Re-check client config (`ida-fusion-mcp --config`).
5. Still failing:
   - Run clean reinstall:
     - Run `ida-fusion-mcp --uninstall` for a per-user install, or `ida-fusion-mcp --uninstall --ida-dir "/Applications/IDA Professional 9.3.app"` for the explicit application-bundle install.
     - uninstall package (`pip uninstall ida-fusion-mcp` and/or `pipx uninstall ida-fusion-mcp`)
     - reinstall with `python -m pip install git+https://github.com/andsopwn/ida-fusion-mcp.git` or `pipx install git+https://github.com/andsopwn/ida-fusion-mcp.git`

## Troubleshooting

### "No module named 'ida_fusion_mcp.plugin'" in IDA

If the message also says `'ida_fusion_mcp' is not a package`, an historical
`ida_fusion_mcp.py` loader is shadowing the installed package. Run
`ida-fusion-mcp --install` again so the bootstrap is replaced by
`ida_fusion_mcp_loader.py`, then restart IDA.

Otherwise, IDA's Python cannot find the installed package. The most common
cause is **Python version mismatch**.

1. Check IDA's Python version in the IDA console:
   ```
   Python> import sys; print(sys.version)
   ```
2. Install the package using that exact Python version:
   ```bash
   # macOS example (if IDA uses 3.11):
   python3.11 -m pip install --user git+https://github.com/andsopwn/ida-fusion-mcp.git

   # Windows example (if IDA uses 3.12):
   py -3.12 -m pip install git+https://github.com/andsopwn/ida-fusion-mcp.git
   ```
3. Restart IDA Pro

### Plugin loader shows searched paths

If the loader prints `Searched paths:`, check if any of those paths contain `ida_fusion_mcp/`. If none do, the package needs to be installed for IDA's Python version (see above).

## Coexistence with ida-pro-mcp

ida-fusion-mcp and an independent ida-pro-mcp installation may coexist on
different ports. The ida-fusion installer never migrates or deletes
`ida-pro-mcp`, `github.com/mrexodia/ida-pro-mcp`, or the `ida_mcp.py` loader.
Remove those manually only if you intentionally choose to stop using the
independent project.

## Uninstallation

`ida-fusion-mcp --uninstall` removes only the `ida-fusion-mcp` client entries,
the `ida_fusion_mcp_loader.py` loader, the shadowing historical
`ida_fusion_mcp.py` loader, the owned legacy `ida_multi_mcp.py` loader, and
fusion's registry files. Independent ida-pro-mcp client entries and loaders are
preserved.

If installation used an explicit IDA directory, repeat the same override so
the matching loader is removed:

```bash
ida-fusion-mcp --uninstall --ida-dir "/Applications/IDA Professional 9.3.app"
```
