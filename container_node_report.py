#!/usr/bin/env python3
"""Generate a report of hosts running containers or pods.

Queries the Kubernetes Protection API for node-level data including
container runtime, cluster name, cloud provider, and container/pod counts.
Container and pod counts are computed by querying those endpoints directly
and grouping by node_name, since the nodes endpoint returns 0 for both.

API Scopes Required:
    Kubernetes Protection - READ
"""
import os
import sys
import csv
import json
from argparse import ArgumentParser, RawTextHelpFormatter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from falconpy import KubernetesProtection
except ImportError as e:
    raise SystemExit(
        "This script requires crowdstrike-falconpy.\n"
        "Install with: pip install crowdstrike-falconpy"
    ) from e

from falconpy_auth import get_falcon_credentials


def parse_args():
    parser = ArgumentParser(
        description=__doc__,
        formatter_class=RawTextHelpFormatter
    )
    parser.add_argument("-k", "--client_id", default=None,
                        help="Falcon API Client ID (overrides config/env)")
    parser.add_argument("-s", "--client_secret", default=None,
                        help="Falcon API Client Secret (overrides config/env)")
    parser.add_argument("-b", "--base_url", default=None,
                        help="Falcon cloud region (us1, us2, eu1, usgov1, usgov2)")
    parser.add_argument("-p", "--profile", default="default",
                        help="Credential profile from ~/.falconpy/credentials")
    parser.add_argument("-m", "--member_cid", default=None,
                        help="Member CID for MSSP/Flight Control")
    parser.add_argument("-f", "--filter", default=None, dest="fql_filter",
                        help="FQL filter applied to node query (e.g. \"cloud_name:'AWS'\")")
    parser.add_argument("-o", "--output", default=None,
                        help="Output CSV file path (default: print table to stdout)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON instead of table/CSV")
    return parser.parse_args()


def _paginate_combined(falcon, method_name, label, fql_filter=None):
    """Generic paginator for KubernetesProtection *_combined endpoints."""
    items = []
    offset = 0
    limit = 500
    total = 1
    method = getattr(falcon, method_name)

    while offset < total:
        params = dict(limit=limit, offset=offset)
        if fql_filter:
            params["filter"] = fql_filter

        response = method(**params)
        status = response.get("status_code")

        if status != 200:
            errors = response.get("body", {}).get("errors", [])
            msg = "; ".join(e.get("message", str(e)) for e in errors) if errors else f"HTTP {status}"
            raise SystemExit(f"API error fetching {label}: {msg}")

        body = response["body"]
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        resources = body.get("resources") or []

        if not resources:
            break

        items.extend(resources)
        offset += len(resources)
        print(f"  Fetched {len(items)}/{total} {label}...", file=sys.stderr)

    return items


def _count_for_node(falcon, node_name, since):
    """Return (container_count, pod_count) of running resources active since `since` for a single node."""
    node_fql = f"node_name:'{node_name}'"
    time_fql = f"last_seen:>='{since}'"

    cr = falcon.read_container_counts(filter=f"{node_fql}+running_status:true+{time_fql}")
    container_count = 0
    if cr.get("status_code") == 200:
        resources = cr["body"].get("resources") or []
        if resources:
            container_count = resources[0].get("count", 0)

    # resource_status:'active' matches pods that are currently running
    pr = falcon.read_pod_counts(filter=f"{node_fql}+{time_fql}")
    pod_count = 0
    if pr.get("status_code") == 200:
        resources = pr["body"].get("resources") or []
        if resources:
            pod_count = resources[0].get("count", 0)

    return container_count, pod_count


def build_counts_by_node(falcon, node_names, since):
    """Return (container_counts, pod_counts) dicts keyed by node_name.

    Uses a thread pool to issue all per-node count API calls concurrently.
    Capped at 20 workers to stay well within API rate limits.
    """
    container_counts = {}
    pod_counts = {}
    total = len(node_names)
    completed = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_count_for_node, falcon, name, since): name
                   for name in node_names}
        for future in as_completed(futures):
            name = futures[future]
            c, p = future.result()
            container_counts[name] = c
            pod_counts[name] = p
            completed += 1
            if completed % 25 == 0 or completed == total:
                print(f"  Counted {completed}/{total} nodes...", file=sys.stderr)

    return container_counts, pod_counts


def _sensor_aid(node):
    """Extract the Falcon sensor AID from the agents list."""
    for agent in node.get("agents") or []:
        if agent.get("type", "").lower().startswith("falcon sensor"):
            return agent.get("aid", "")
    # Fall back to first agent AID if no sensor entry found
    agents = node.get("agents") or []
    return agents[0].get("aid", "") if agents else ""


def extract_node_record(node, container_counts, pod_counts):
    """Build a report row from a node resource and precomputed count lookups."""
    name = node.get("node_name", "")
    return {
        "hostname":        name,
        "host_id":         _sensor_aid(node),
        "cluster_name":    node.get("cluster_name", ""),
        "cloud_provider":  node.get("cloud_name", ""),
        "container_count": container_counts.get(name, 0),
        "pod_count":       pod_counts.get(name, 0),
    }


COLUMNS = [
    "hostname",
    "host_id",
    "cluster_name",
    "cloud_provider",
    "container_count",
    "pod_count",
]


def print_table(records):
    if not records:
        print("No container/pod hosts found.")
        return

    widths = {col: len(col) for col in COLUMNS}
    for r in records:
        for col in COLUMNS:
            widths[col] = max(widths[col], len(str(r[col])))

    header = "  ".join(col.upper().ljust(widths[col]) for col in COLUMNS)
    separator = "  ".join("-" * widths[col] for col in COLUMNS)
    print(header)
    print(separator)
    for r in records:
        print("  ".join(str(r[col]).ljust(widths[col]) for col in COLUMNS))
    print(f"\nTotal: {len(records)} host(s)")


def write_csv(records, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)
    print(f"Report written to: {path}")


def main():
    args = parse_args()

    creds = get_falcon_credentials(
        profile=args.profile,
        client_id=args.client_id,
        client_secret=args.client_secret,
        base_url=args.base_url,
    )

    falcon = KubernetesProtection(
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
        base_url=creds["base_url"],
        member_cid=args.member_cid,
    )

    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    active_filter = f"last_seen:>='{since}'"
    if args.fql_filter:
        active_filter = f"{active_filter}+{args.fql_filter}"

    print("Fetching nodes active in the last 24 hours...", file=sys.stderr)
    nodes = _paginate_combined(falcon, "read_nodes_combined", "nodes",
                               fql_filter=active_filter)

    if not nodes:
        print("No nodes returned. Verify the API scope 'Kubernetes Protection: READ' is granted.")
        return

    node_names = [n.get("node_name", "") for n in nodes if n.get("node_name")]
    print(f"Fetching running container/pod counts (last 24h) for {len(node_names)} nodes...", file=sys.stderr)
    container_counts, pod_counts = build_counts_by_node(falcon, node_names, since)

    records = sorted(
        [extract_node_record(n, container_counts, pod_counts) for n in nodes],
        key=lambda r: r["pod_count"],
        reverse=True,
    )

    if args.json:
        print(json.dumps(records, indent=2))
    elif args.output:
        write_csv(records, args.output)
    else:
        print_table(records)


if __name__ == "__main__":
    main()
