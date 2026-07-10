# ida-pro-mcp upstream comparison

Last updated: 2026-07-10
Upstream head reviewed: `abb2732ad0d759d750c2e38b616f7f3e949ed2f9`

This is a point-in-time implementation comparison, not a license or provenance
statement. ida-fusion-mcp keeps its router-native multi-instance and managed
idalib lifecycle instead of wholesale cherry-picking upstream.

## Adapted in the v0.1.1 candidate

| Area | Fusion adaptation |
|---|---|
| IDA synchronization | Batch save/restore runs inside serialized `execute_sync`; reentrancy cannot drain an outer marker. |
| Cancellation | Native cancellation timer, profiler/request checks, joined cleanup, and cancelled search cursors. |
| IDB saving | GUI-safe current/copy behavior and headless `DBFL_KILL | DBFL_COMP`; runtime-detection failure never selects destructive flags. |
| Process/HTTP lifecycle | Undrained worker stdout is discarded and backend connections close in `finally`. |
| API boundaries | Canonical function starts, bounded field xrefs, and confined decompiler output. |

## Already present in fusion

- BSS zero-fill correctness via `read_bytes_bss_safe` / `read_int_bss_safe`.
- Whitespace compaction, compact JSON serialization, and symbol-name address resolution.
- IDA 8.3-9.3 compatibility shims and router-native multi-instance routing.
- Composite analysis, health/warmup, query, cache, and managed idalib tools.

## Deliberately deferred

- Bulk BSS-read performance; the current correct helper still checks bytes individually.
- Windows process-group shutdown, registry caching, FileLock optimization,
  response-preview optimization, and the broader query-cache rewrite.
- Upstream GUI `keep_batch` debugger-start behavior.
- Function-similarity tools and optional neural dependencies, targeted for v0.2.0.

## Fusion-specific architecture

- One stdio MCP endpoint routes explicit `instance_id` calls to multiple GUI or
  headless backends.
- Managed idalib workers share the registry but remain owned by the router
  process that spawned them.
- Debugger extensions are enabled only on the internal router-to-IDA path.
