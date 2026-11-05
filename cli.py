"""`hermes wazoo` subcommands: status and a quick world sanity check."""

import argparse
import json

from pathlib import Path

def register_cli(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("wazoo", help="Wazoo memory provider status")
    sub = parser.add_subparsers(dest="wazoo_command")
    sub.add_parser("status", help="Show configured world and credential state")
    sub.add_parser("check", help="Run a search and a SPARQL count against the world")

def _persisted_world():
    try:
        from hermes_constants import get_hermes_home
        path = Path(get_hermes_home()) / "wazoo" / "world.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k: str(data[k]) for k in ("world_id", "world_token") if data.get(k)}
    except Exception:
        return {}

def _config():
    try:
        from hermes_cli.config import load_config_readonly
        return (load_config_readonly().get("memory", {}).get("wazoo", {}) or {})
    except Exception:
        return {}

def run_cli(args: argparse.Namespace) -> int:
    from agent.secret_scope import get_secret
    cfg = _config()
    persisted = _persisted_world()
    world_id = get_secret("WORLD_ID", "") or cfg.get("world_id", "") or persisted.get("world_id", "")
    token = get_secret("WORLDS_TOKEN", "") or persisted.get("world_token", "")
    platform = get_secret("WAZOO_PLATFORM_TOKEN", "") or ""
    if args.wazoo_command in ("status", "check"):
        print(f"data_url:  {cfg.get('data_url') or 'https://data.wazoo.dev'}")
        print(f"world_id:  {world_id or '(auto-provisioned on first use)'}")
        print(f"world token: {'set' if token else 'not set'}")
        print(f"platform token: {'set' if platform else 'not set'}")
        if not token and not platform:
            print("unavailable: set WORLDS_TOKEN or WAZOO_PLATFORM_TOKEN")
            return 1
    if args.wazoo_command == "check":
        if not token:
            print("check needs a world token (set WORLDS_TOKEN)")
            return 1
        base = (cfg.get("data_url") or "https://data.wazoo.dev").rstrip("/")
        from urllib import request as req
        def post(path, body):
            r = req.Request(f"{base}/worlds/{world_id}{path}",
                            data=json.dumps(body).encode(),
                            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                            method="POST")
            with req.urlopen(r, timeout=15) as res:
                return json.loads(res.read())
        search = post("/search", {"query": "the", "topK": 3})
        sparql = post("/sparql", {"query": "SELECT (COUNT(?s) AS ?n) WHERE { ?s ?p ?o }"})
        n = sparql.get("results", {}).get("bindings", [{}])[0].get("n", {}).get("value", "?")
        print(f"search results: {len(search.get('results', []))}")
        print(f"graph triples:  {n}")
    return 0
