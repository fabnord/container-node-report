# container-node-report

Generates a report of nodes running containers or pods, using the CrowdStrike Falcon Kubernetes Protection API. Results are scoped to nodes, containers, and pods active in the last 24 hours, and sorted by pod count descending.

## Report columns

| Column | Description |
|---|---|
| `hostname` | Node name |
| `host_id` | Falcon sensor agent ID (AID) |
| `cluster_name` | Kubernetes cluster name |
| `cloud_provider` | Cloud provider (AWS, Azure, GCP) |
| `container_count` | Running containers seen in the last 24 hours |
| `pod_count` | Pods seen in the last 24 hours |

## Requirements

- Python 3.7+
- [uv](https://docs.astral.sh/uv/)
- CrowdStrike Falcon API credentials with the **Kubernetes Protection: READ** scope

## Setup

### 1. Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Configure credentials

Create `~/.falconpy/credentials`:

```ini
[default]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
base_url = us1
```

Set file permissions:

```bash
chmod 600 ~/.falconpy/credentials
```

Alternatively, export environment variables:

```bash
export FALCON_CLIENT_ID=YOUR_CLIENT_ID
export FALCON_CLIENT_SECRET=YOUR_CLIENT_SECRET
export FALCON_BASE_URL=us1   # us1, us2, eu1, usgov1, usgov2
```

## Usage

### Print table to terminal

```bash
uv run --with crowdstrike-falconpy container_node_report.py
```

### Export to CSV

```bash
uv run --with crowdstrike-falconpy container_node_report.py -o report.csv
```

### Export as JSON

```bash
uv run --with crowdstrike-falconpy container_node_report.py --json
```

### Filter by cloud provider

```bash
uv run --with crowdstrike-falconpy container_node_report.py -f "cloud_name:'AWS'"
```

### Use a non-default credential profile

```bash
uv run --with crowdstrike-falconpy container_node_report.py -p production
```

### Pass credentials directly

```bash
uv run --with crowdstrike-falconpy container_node_report.py \
  -k YOUR_CLIENT_ID \
  -s YOUR_CLIENT_SECRET \
  -b us1
```

## All options

```
-k, --client_id       Falcon API Client ID (overrides config/env)
-s, --client_secret   Falcon API Client Secret (overrides config/env)
-b, --base_url        Falcon cloud region (us1, us2, eu1, usgov1, usgov2)
-p, --profile         Credential profile from ~/.falconpy/credentials
-m, --member_cid      Member CID for MSSP/Flight Control
-f, --filter          Additional FQL filter applied to node query
-o, --output          Output CSV file path
    --json            Output as JSON instead of a table
```
