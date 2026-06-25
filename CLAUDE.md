# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the script

```bash
# With uv (no venv setup needed)
uv run --with crowdstrike-falconpy container_node_report.py

# With an existing venv
python container_node_report.py
```

## Credentials

The script loads credentials from `~/.falconpy/credentials` (INI format, `[default]` profile), then falls back to `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` / `FALCON_BASE_URL` env vars, then CLI flags. See `falconpy_auth.py` for the full resolution order.

Required API scope: **Kubernetes Protection: READ**

## Architecture

Two files do all the work:

- **`falconpy_auth.py`** — standalone credential manager; no dependency on the main script. Used by importing `get_falcon_credentials()`.
- **`container_node_report.py`** — main script. Uses `KubernetesProtection` from `crowdstrike-falconpy`.

### Data flow

1. Query `read_nodes_combined` with a `last_seen >= 24h ago` FQL filter to get active nodes.
2. For each node, call `read_container_counts` (filter: `running_status:true + last_seen`) and `read_pod_counts` (filter: `last_seen`) concurrently via `ThreadPoolExecutor(max_workers=20)`.
3. Join counts onto node records, sort by `pod_count` descending, output as table / CSV / JSON.

### Why per-node count calls instead of paginating all containers/pods

The `read_containers_combined` endpoint returns a server error mid-pagination at large result sets (~10k+ records). The count endpoints are stable and the thread pool keeps total wall time to ~30s for 90 nodes (vs ~320s serial).

### Key FQL filters

- Nodes: `last_seen:>='<ISO8601>'`
- Containers: `running_status:true+last_seen:>='<ISO8601>'`
- Pods: `last_seen:>='<ISO8601>'`

Pod `resource_status:'active'` was tested but intentionally removed — it filters too aggressively and the `last_seen` window is sufficient.
