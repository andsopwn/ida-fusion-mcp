# Changelog

## 0.1.1 - 2026-07-10

### Fixed

- Prevent concurrent MCP calls from leaving GUI IDA in batch/silent mode.
- Prevent reentrant synchronized calls from freezing IDA's main thread.
- Preserve independent ida-pro-mcp client configurations during install and uninstall.
- Install the IDA bootstrap as `ida_fusion_mcp_loader.py` so its module name
  cannot shadow the `ida_fusion_mcp` package, while removing owned historical
  loader names after the replacement succeeds.
- Route the advertised debugger extension through the multi-instance router.
- Preserve restricted IDA-module imports in `py_eval` and Python file execution.
- Detect standard macOS IDA application bundles and clarify optional idalib setup.
- Close failed backend connections, bound structure-field xrefs, canonicalize function addresses, and confine decompiler file output by default.

### Changed

- Synchronize bundled tool schemas with the implemented IDA tool registry.
- Save IDBs using GUI/headless-appropriate flags.

### Known limitations

- Function-similarity tools are deferred to 0.2.0.
- `py_eval` and `py_exec_file` remain unsafe in-process capabilities; their
  restricted execution context is not a security sandbox. Managed idalib keeps
  unsafe tools off by default, while the GUI retains its existing tool defaults.
- No package, tag, or public release has been published from this candidate.
- License provenance must be confirmed before any public publication.
