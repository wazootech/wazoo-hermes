"""Refresh tests/fixtures/openapi_subset.json from the published OpenAPI specs.

The provider calls seven operations on two services. This keeps just those
operations' request and 2xx response schemas, with $refs inlined and prose
dropped, so the contract test runs offline against a small, reviewable file.

    python tests/sync_openapi.py           # rewrite the fixture
    python tests/sync_openapi.py --check   # exit 1 if the specs moved
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib import request

SPECS = {
    "worlds-api": "https://raw.githubusercontent.com/wazootech/worlds-api/main/openapi/openapi.json",
    "wazoo-api": "https://raw.githubusercontent.com/wazootech/wazoo-api/main/openapi/openapi.json",
}
OPERATIONS = (
    ("worlds-api", "post", "/worlds/{worldId}/search"),
    ("worlds-api", "post", "/worlds/{worldId}/sparql"),
    ("worlds-api", "post", "/worlds/{worldId}/import"),
    ("wazoo-api", "post", "/v1/worlds"),
    ("wazoo-api", "post", "/v1/worlds/{worldId}/auth/tokens"),
)
KEEP = {"type", "properties", "required", "items", "additionalProperties", "enum",
        "anyOf", "oneOf", "allOf", "nullable"}
FIXTURE = Path(__file__).parent / "fixtures" / "openapi_subset.json"


def _inline(node, spec: dict, seen: tuple = ()):
    if isinstance(node, list):
        return [_inline(n, spec, seen) for n in node]
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if ref:
        if ref in seen:
            return {}  # recursive schema: stop rather than loop
        target = spec
        for part in ref.lstrip("#/").split("/"):
            target = target[part]
        return _inline(target, spec, seen + (ref,))
    out = {}
    for key, value in node.items():
        if key == "properties":
            out[key] = {name: _inline(s, spec, seen) for name, s in value.items()}
        elif key in KEEP:
            out[key] = _inline(value, spec, seen)
    return out


def _json_schemas(content: dict, spec: dict) -> dict:
    return {ct: _inline(v.get("schema", {}), spec) for ct, v in sorted(content.items()) if "json" in ct}


def build(specs: dict[str, dict]) -> dict:
    subset = {}
    for service, method, path in OPERATIONS:
        op = specs[service]["paths"][path][method]
        body = op.get("requestBody", {}).get("content", {})
        responses = {code: _json_schemas(r.get("content", {}), specs[service])
                     for code, r in sorted(op.get("responses", {}).items()) if code.startswith("2")}
        subset[f"{service} {method.upper()} {path}"] = {
            "request": _json_schemas(body, specs[service]), "responses": responses}
    return subset


def main(argv: list[str]) -> int:
    specs = {}
    for name, url in SPECS.items():
        with request.urlopen(url, timeout=30) as res:
            specs[name] = json.loads(res.read())
    text = json.dumps(build(specs), indent=2, sort_keys=True) + "\n"
    if "--check" in argv:
        current = FIXTURE.read_text(encoding="utf-8") if FIXTURE.exists() else ""
        if current != text:
            print("OpenAPI specs changed for operations this provider calls; "
                  "run `python tests/sync_openapi.py` and re-run the contract test.")
            return 1
        print("OpenAPI subset is current.")
        return 0
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {FIXTURE}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
