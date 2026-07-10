# ida-fusion-mcp

`ida-fusion-mcp` is a fork and continuation of [`MeroZemory/ida-multi-mcp`](https://github.com/MeroZemory/ida-multi-mcp). It keeps the original multi-instance IDA routing model, renames the public project, and adds a larger tool surface ported from [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp).

The goal is straightforward: one MCP endpoint for reverse-engineering work that spans more than one IDA database. Your AI client keeps one stable server config, and each tool call is routed to the correct IDA Pro GUI instance or headless `idalib` worker by `instance_id`.

> **v0.1.1 stabilization candidate:** fixes synchronization, installer safety,
> debugger routing/schema parity, macOS detection, and selected correctness
> issues. It is a local candidate only; no tag, package, or public release has
> been published.

The project combines three things that are usually separate:

- multi-binary routing for loaders, payloads, plugins, services, and shared libraries;
- a broad IDA tool surface adapted from `ida-pro-mcp`;
- headless IDA Pro sessions for background analysis without opening another GUI window.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.3%2B-orange.svg)
![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)

![ida-fusion-mcp architecture](docs/assets/ida-fusion-mcp-architecture.svg)

## What Problem It Solves

Most IDA MCP setups assume a single active database. That is awkward once an investigation needs context from several files at once: a dropper and payload, a patched and unpatched build, a client and server pair, or a main executable plus libraries.

`ida-fusion-mcp` makes the target explicit. The AI client first asks for registered instances, receives short IDs such as `k7m2` or `px3a`, and includes one of those IDs in every IDA tool call. That small constraint prevents a common failure mode: the model decompiles, renames, patches, or debugs the wrong database because two IDA windows are open.

## Core Ideas

| Idea | Practical effect |
|---|---|
| One MCP server | Configure Claude Code, Cursor, Codex, VS Code, or another MCP client once. |
| Many IDA backends | GUI IDA instances and headless `idalib` workers register into the same local registry. |
| Required `instance_id` | Tool calls are deliberately scoped to one database. |
| Static + dynamic schemas | Tools are visible before IDA is open, then refreshed from live IDA instances. |
| Local-only transport | IDA listens on loopback HTTP JSON-RPC; the MCP server talks stdio to the client. |
| Compatibility aliases | The public name is `ida-fusion-mcp`; the Python implementation package remains `ida_fusion_mcp` to avoid breaking existing imports. |

## Tool Surface

The IDA-side tools cover the normal reverse-engineering loop: discovery, navigation, decompilation, xrefs, memory reads, patching, type work, comments, stack variables, debugger access, and binary triage.

The recent port from `ida-pro-mcp` adds these higher-level capabilities:

| Category | Tools |
|---|---|
| Signature generation | `make_signature`, `make_signature_for_function`, `make_signature_for_range`, `find_xref_signatures` |
| Type catalog | `type_query`, `type_inspect`, `type_apply_batch` |
| Unified search | `entity_query`, `search_text` |
| IDAPython file execution | `py_exec_file` |
| Debugger control | `dbg_start`, `dbg_status`, `dbg_exit`, `dbg_continue`, `dbg_run_to`, `dbg_step_into`, `dbg_step_over` |
| Breakpoints | `dbg_bps`, `dbg_add_bp`, `dbg_delete_bp`, `dbg_toggle_bp`, `dbg_set_bp_condition` |
| Registers and stack | `dbg_regs_all`, `dbg_regs`, `dbg_regs_remote`, `dbg_gpregs`, `dbg_gpregs_remote`, `dbg_regs_named`, `dbg_regs_named_remote`, `dbg_stacktrace` |
| Debugger memory | `dbg_read`, `dbg_write` |

Router-level tools add multi-instance operations:

| Tool | Purpose |
|---|---|
| `list_instances` | Show every registered GUI or headless IDA backend. |
| `refresh_tools` | Refresh schemas from currently connected IDA instances. |
| `compare_binaries` | Compare metadata and segments from two registered instances. |
| `decompile_to_file` | Save decompiler output to disk without stuffing huge output into chat. |
| `get_cached_output` | Retrieve follow-up chunks from truncated large responses. |
| `idalib_open` / `idalib_close` / `idalib_list` / `idalib_status` | Manage headless IDA Pro sessions. |

## Comparison

| Capability | ida-fusion-mcp | ida-pro-mcp | Typical single-instance MCP |
|---|---|---|---|
| Multiple GUI IDA windows | First-class workflow | Not the main focus | Usually awkward |
| Per-call target selection | Required `instance_id` | Context/session dependent | Often implicit |
| Headless IDA Pro | Managed `idalib` workers in the same registry | `idalib-mcp` supervisor model | Often absent |
| Signature/type/search tools | Included from the port | Included upstream | Varies |
| Cross-binary helpers | Included at router level | Not the focus | Usually absent |
| Best fit | Multi-file investigations and agent workflows | Upstream single-database IDA tooling | One binary at a time |

## Quick Start

Install the package, install the IDA loader, then open binaries in IDA.

```bash
python -m pip install git+https://github.com/andsopwn/ida-fusion-mcp.git
ida-fusion-mcp --install
ida-fusion-mcp --list
```

Example client prompt:

```text
Call list_instances, identify the two open binaries, decompile their entry points, and compare the initialization paths.
```

The legacy `ida-multi-mcp` console command is still provided as an alias. New configuration uses `ida-fusion-mcp`.

## Installation Details

### Requirements

| Mode | IDA edition/version | Python | Extra package |
|---|---|---|---|
| GUI plugin | IDA Pro/Home 8.3+ | IDA's matching Python, server on 3.11+ | none |
| Managed headless | IDA Pro 9.x with `libidalib` | server/worker on 3.11+ | `ida-fusion-mcp[idalib]` |

Post-change v0.1.1 GUI routing and managed idalib are verified with IDA Pro 9.3
on macOS arm64, including a real GUI restart and managed-session lifecycle.

### macOS

IDA often uses a different Python build than your shell. Check IDA's Python first:

```python
import sys
print(sys.version)
```

Then install with the matching Python version:

```bash
pipx install git+https://github.com/andsopwn/ida-fusion-mcp.git
python3.11 -m pip install --user git+https://github.com/andsopwn/ida-fusion-mcp.git
ida-fusion-mcp --install
```

For Claude Code, a direct CLI registration is usually clearer than a module command:

```bash
claude mcp add ida-fusion-mcp -s user -- ida-fusion-mcp
```

For managed headless sessions, install the optional `idapro` dependency into a
Python 3.11 environment. Persist that exact worker interpreter in the MCP
client registration; running the server once with the flag does not update the
client's saved configuration. Use this registration instead of the GUI-only
Claude Code command above:

```bash
python3.11 -m pip install \
  "ida-fusion-mcp[idalib] @ git+https://github.com/andsopwn/ida-fusion-mcp.git"
claude mcp add ida-fusion-mcp -s user -- \
  ida-fusion-mcp --idalib-python /absolute/path/to/idalib-python
```

For JSON-based clients, store the same argument in the server entry:

```json
{
  "command": "/absolute/path/to/server-python",
  "args": ["-m", "ida_fusion_mcp", "--idalib-python", "/absolute/path/to/idalib-python"]
}
```

GUI mode does not require `idapro`. Headless mode requires IDA Pro 9.x with
`libidalib` and an interpreter where `import idapro` is discoverable.

### Windows

```powershell
py -3.11 -m pip install git+https://github.com/andsopwn/ida-fusion-mcp.git
ida-fusion-mcp --install
```

If IDA uses a different Python version, replace `3.11` with IDA's version. For a custom IDA directory:

```powershell
ida-fusion-mcp --install --ida-dir "C:\Program Files\IDA Professional 9.3"
```

### Linux

```bash
python3 -m pip install --user git+https://github.com/andsopwn/ida-fusion-mcp.git
ida-fusion-mcp --install
```

### Manual MCP Config

`ida-fusion-mcp --install` writes client configs automatically when it recognizes the client. To inspect the raw MCP config:

```bash
ida-fusion-mcp --config
```

Typical output:

```json
{
  "mcpServers": {
    "ida-fusion-mcp": {
      "command": "/path/to/python3",
      "args": ["-m", "ida_fusion_mcp"]
    }
  }
}
```

## Using It

Open one or more binaries in IDA Pro. The loader installed by `--install` starts an IDA-local HTTP server and registers the database in `~/.ida-mcp/instances.json`.

Check what is live:

```bash
ida-fusion-mcp --list
```

Then use the displayed `instance_id` in prompts or tool arguments:

```text
Use instance k7m2. Find functions referencing the string "license", decompile the callers, and summarize the validation path.
```

For two binaries:

```text
Use k7m2 as the old build and px3a as the patched build. Compare the functions around the entry point and report changed calls.
```

For headless work:

```text
Open /samples/payload.bin with idalib_open, wait for analysis, then run survey_binary on the returned instance.
```

## Architecture

```text
AI client
  |
  | MCP stdio
  v
ida-fusion-mcp router
  |-- local registry and schema cache
  |-- output cache for large responses
  |-- idalib worker manager
  |
  | HTTP JSON-RPC on loopback
  v
IDA GUI #1    IDA GUI #2    idalib worker #1
```

The router does not own IDA analysis state. It validates the requested `instance_id`, forwards the call to the matching backend, normalizes large outputs, and returns the MCP response to the client.

## Operational Notes

- The installed IDA loader is named `ida_fusion_mcp_loader.py` so it does not
  shadow the `ida_fusion_mcp` package when IDA imports plugins by filename.
- The implementation module remains `ida_fusion_mcp`.
- The registry lives under `~/.ida-mcp/` by default.
- GUI instances send heartbeats; stale entries are cleaned up.
- If an IDA window opens a different input file, the old instance expires and a new ID is registered.
- The stdio router advertises debugger tools normally and internally enables
  the IDA backend's `dbg` extension for discovery and invocation. Clients pass
  only `instance_id`; unsafe-tool configuration and debugger-state checks stay
  enforced by the backend.
- `py_eval` and `py_exec_file` are unsafe, in-process code-execution tools. Their
  reduced builtins/import surface is defense in depth, not containment; disable
  them in the IDA MCP tool configuration unless the workflow requires them.
  Managed idalib workers omit `@unsafe` tools unless opened with `unsafe=true`;
  the GUI plugin retains its existing enabled-tool defaults for compatibility.

## Troubleshooting

### IDA does not show the plugin

Check that the loader exists:

```bash
ls ~/.idapro/plugins/ida_fusion_mcp_loader.py
```

On Windows:

```powershell
Get-Item "$env:APPDATA\Hex-Rays\IDA Pro\plugins\ida_fusion_mcp_loader.py"
```

If IDA reports `No module named 'ida_fusion_mcp'`, install the package with the Python version used by IDA. If IDA itself is using Python older than 3.11, switch IDA to a supported Python build with `idapyswitch`.

### The MCP client starts the wrong Python

Run:

```bash
ida-fusion-mcp --config
```

If the generated command points to an unexpected interpreter, configure the client to call the `ida-fusion-mcp` CLI directly.

### No instances are listed

Start IDA with a binary loaded, then run:

```bash
ida-fusion-mcp --list
```

If the list is still empty, check the IDA output window for `[ida-fusion-mcp]` messages.

## Development

```bash
git clone https://github.com/andsopwn/ida-fusion-mcp.git
cd ida-fusion-mcp
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m compileall -q src
python -m ida_fusion_mcp --config
```

The public package exposes both commands:

```bash
ida-fusion-mcp --config
ida-multi-mcp --config   # compatibility alias
```

## Lineage And License

`ida-fusion-mcp` is MIT licensed. See [LICENSE](LICENSE).

This repository is based on and extends MIT-licensed work from:

- [`ida-multi-mcp`](https://github.com/MeroZemory/ida-multi-mcp), the original multi-instance IDA MCP router.
- [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp), copyright (c) 2025 Duncan Ogilvie.
- [`ida-sigmaker`](https://github.com/mahmoudimus/ida-sigmaker), copyright (c) 2024 Mahmoud Abdelkader.

Those attributions are intentional: this project is `ida-multi-mcp` plus additional ported functionality, packaging the useful IDA tool surface into a router-oriented workflow for multi-binary analysis.
