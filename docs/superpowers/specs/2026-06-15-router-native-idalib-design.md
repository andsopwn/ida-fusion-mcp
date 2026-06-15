# Router-Native idalib Integration Design

Date: 2026-06-15
Status: Approved design direction, pending implementation plan

## Goal

Bring the useful `ida-pro-mcp` `idalib-mcp` capabilities into `ida-fusion-mcp`
without exposing a second public MCP router or replacing the existing
`instance_id` workflow.

The public MCP endpoint remains `ida-fusion-mcp`. Users and agents keep calling
IDA tools with `instance_id`. Headless idalib sessions become another backend
type behind the existing router, alongside GUI IDA instances.

## Non-Goals

- Do not expose upstream's public `database=` argument to normal IDA tools.
- Do not add a separate public `idalib-mcp` MCP server in this phase.
- Do not replace `instances.json` as the shared GUI/headless registry.
- Do not port test directories into the repository unless explicitly requested.
- Do not change the existing `instance_id` requirement for multi-instance safety.

## Current Architecture

`IdaFusionMcpServer` is the only public MCP server. It owns tool listing,
management tools, output caching, and routing. IDA GUI instances and current
idalib workers expose local HTTP JSON-RPC on loopback and register in
`~/.ida-mcp/instances.json`.

`InstanceRouter` forwards each IDA tool call to a selected backend by
`instance_id`. It strips `instance_id` before forwarding and protects against
non-loopback hosts.

`IdalibManager` currently has a simple lifecycle model:

- spawn one worker process per `idalib_open`
- wait until the worker answers HTTP ping
- register the worker in the shared registry
- keep a local `instance_id -> subprocess` map
- terminate owned workers on close or parent shutdown

This works for basic headless analysis but misses the newer upstream behavior:
persistent/adoptable workers, max worker limits, open timeouts, GUI adoption,
idle TTL, and partial database cleanup.

## Upstream Conflict

`ida-pro-mcp` `idalib-mcp` is itself a public MCP supervisor. It lists tools,
injects a `database` argument, resolves sessions, and forwards requests to
workers. If imported directly, `ida-fusion-mcp` would have two MCP-facing
routers:

- `ida-fusion-mcp`: public router using `instance_id`
- `idalib-mcp`: public supervisor using `database`

That would duplicate tool schema injection, session naming, lifecycle ownership,
resource routing, and error behavior. It would also weaken the main product
model: one explicit `instance_id` for every GUI or headless database.

## Chosen Approach

Use a router-native backend design.

The upstream supervisor is treated as a reference implementation, not a public
component. Its useful lifecycle behaviors are absorbed into
`ida-fusion-mcp`'s internal idalib backend manager.

Public shape:

- `ida-fusion-mcp` remains the only MCP server.
- IDA tools continue to require `instance_id`.
- idalib management remains under `idalib_*` tools.
- worker sessions register as normal `instances.json` entries.

Internal shape:

- A new or expanded headless backend manager owns worker lifecycle.
- Workers remain loopback HTTP JSON-RPC backends.
- The existing router keeps forwarding calls by `instance_id`.
- The registry remains the source of truth for GUI and headless backends.

## Public Tool Design

Keep the current management tools:

- `idalib_open`
- `idalib_close`
- `idalib_list`
- `idalib_status`

Extend `idalib_open` rather than adding upstream `idb_open`:

```text
idalib_open(
  input_path,
  mode="prefer_headless",
  timeout=120,
  unsafe=false,
  preferred_instance_id="",
  idle_ttl_sec=600,
  run_auto_analysis=true,
  build_caches=true,
  init_hexrays=true
)
```

Supported `mode` values:

- `prefer_headless`: adopt existing worker for the path, otherwise spawn worker.
- `force_headless`: spawn or adopt only a headless worker, never GUI.
- `prefer_gui`: adopt a running GUI for the path, otherwise spawn worker.
- `force_gui`: adopt a running GUI for the path; if none is running, return an
  error in this phase. Automatic GUI launch is out of scope for the first
  implementation.

The returned session identifier is always `instance_id`, not `database`.

## Registry Model

Reuse the current registry entry shape and add optional idalib metadata:

```json
{
  "pid": 12345,
  "host": "127.0.0.1",
  "port": 49152,
  "binary_name": "sample.exe",
  "binary_path": "/samples/sample.exe",
  "idb_path": "/samples/sample.exe.i64",
  "arch": "metapc-64",
  "type": "idalib",
  "backend": "worker",
  "owned": true,
  "adopted": true,
  "worker_pid": 12345,
  "input_path": "/samples/sample.exe",
  "idle_ttl_sec": 600,
  "registered_at": "...",
  "last_heartbeat": "..."
}
```

Compatibility rule: existing GUI and idalib entries without these new fields
must keep working.

## Worker Lifecycle

The manager should support four states:

- `owned`: worker spawned by this router process.
- `adopted`: worker or GUI discovered and registered by another process.
- `reachable`: TCP and JSON-RPC probes succeed.
- `stale`: registry entry exists but backend is dead or path no longer matches.

Lifecycle rules:

- Router startup cleans stale entries and adopts reachable existing workers.
- Opening a path first checks for an existing GUI or worker with the same
  canonical input path.
- `max_workers` limits only owned headless workers, not GUI instances.
- Workers may outlive a router restart and self-exit after `idle_ttl_sec`.
- `idalib_close` terminates owned workers. For adopted workers or GUI instances,
  it removes only this router's registry/session association and must not kill
  the external process.
- Open timeout must terminate the failed worker and clean partial unpacked IDB
  side files while preserving complete `.i64` or `.idb` databases.

## Data Flow

Opening a headless binary:

```text
client -> ida-fusion-mcp tools/call(idalib_open)
router -> HeadlessBackendManager.open()
manager -> discover existing GUI/worker for path
manager -> adopt or spawn worker
worker -> open database and serve HTTP /mcp
manager -> warmup worker and register instance
router -> refresh tool cache
client <- {instance_id, backend, binary_name, status}
```

Calling an IDA tool:

```text
client -> ida-fusion-mcp tools/call(decompile, instance_id=k7m2)
router -> registry lookup
router -> verify backend path/name
router -> strip instance_id
router -> HTTP JSON-RPC to backend /mcp
backend -> execute tool in IDA context
router -> normalize structuredContent and cache large output
client <- MCP tool result
```

## Tool Schema Rules

- The public schema source remains `ida_tool_schemas.json` plus dynamic backend
  discovery.
- Every IDA tool schema is injected with required `instance_id`.
- The upstream `database` argument is never injected.
- idalib worker-specific management tools such as upstream `idb_open` should not
  leak into the public IDA tool list.
- Profiles can be added later as an internal filter that removes tools from a
  worker registry before schemas are advertised.

## Error Handling

Use explicit, actionable errors:

- Missing `instance_id`: suggest `list_instances`.
- No backend available: suggest opening IDA or calling `idalib_open`.
- Worker limit reached: report current owned worker count and `max_workers`.
- Open timeout: report timeout, whether cleanup ran, and stderr tail if known.
- Adopted GUI close request: do not terminate GUI; return a clear note.
- Stale registry entry: unregister it and ask the caller to retry list/open.

Do not expose arbitrary host/port details in end-user errors beyond loopback
diagnostics already shown by management tools.

## Upstream Feature Port Order

1. Port `search_text` bounded `Heads()` scan and deadline/cancel support.
2. Add missing mutation tools: `force_recompile`, `set_op_type`, `make_data`,
   `add_bookmark`.
3. Replace simple `IdalibManager` spawn/kill behavior with router-native
   lifecycle support: adoption, max worker cap, idle TTL, open timeout, cleanup.
4. Add optional profile filtering for headless workers.
5. Evaluate trace persistence separately. It is useful, but it writes IDB
   netnodes and is not required for lifecycle compatibility.

## Testing Strategy

No repository test upload is planned unless requested. Verification should rely
on focused local checks and manual/automated runtime probes:

- static import and compile checks for changed modules
- JSON schema generation/listing check
- `codex mcp list` registration name check
- fake registry unit probes in temporary directories where possible
- local worker lifecycle probes when idalib is available
- GUI adoption check with one open IDA instance
- timeout cleanup check with a short open timeout on a controlled sample

If tests are later allowed, add them under `tests/` for registry, lifecycle, and
schema injection behavior.

## Rollout Plan

Implement in small commits:

1. Non-invasive tool fix commit: `search_text` bounded scan.
2. Missing tool commit: add `force_recompile`, `set_op_type`, `make_data`,
   `add_bookmark` and refresh static schemas.
3. Lifecycle foundation commit: introduce backend/session dataclasses and
   discovery/adoption helpers without changing public behavior.
4. `idalib_open` extension commit: add modes, worker cap, idle TTL, open timeout.
5. Cleanup/status commit: improve `idalib_list`, `idalib_status`, stale cleanup,
   and close semantics.
6. Documentation commit: update README/install docs with the router-native
   headless model.

Each commit should preserve the public invariant: one MCP server, one routing
identifier, `instance_id`.
