"""Contract test: every request the provider sends, and every response field it
reads, must match the published OpenAPI specs of worlds-api and wazoo-api.

The schemas come from tests/fixtures/openapi_subset.json, refreshed by
tests/sync_openapi.py (CI runs it with --check, so spec drift fails there).
"""

import json
import re
import unittest
from pathlib import Path
from unittest import mock

from test_provider import _SECRETS, _Scripted, make_provider, wz

SUBSET = json.loads((Path(__file__).parent / "fixtures" / "openapi_subset.json").read_text(encoding="utf-8"))

# Response fields the provider reads, per operation (dotted; [] = array items).
READS = {
    "worlds-api POST /worlds/{worldId}/search": ["results[].content", "results[].subject", "results[].score"],
    "worlds-api POST /worlds/{worldId}/import": ["imported.quads", "imported.chunks"],
    "worlds-api POST /worlds/{worldId}/sparql": ["head.vars", "results.bindings"],
    "wazoo-api POST /v1/worlds": ["world.id"],
    "wazoo-api POST /v1/worlds/{worldId}/auth/tokens": ["token.token"],
}
# Fields the API returns but its spec does not declare. Each names its issue;
# the test fails once the spec catches up, so the entry gets removed.
KNOWN_GAPS: dict[tuple[str, str], str] = {}


def _json_schema(content: dict) -> dict:
    return content.get("application/json") or next(iter(content.values()), {})


def _merged(schema: dict) -> dict:
    if "allOf" not in schema:
        return schema
    out = {"type": "object", "properties": {}, "required": []}
    for part in schema["allOf"]:
        part = _merged(part)
        out["properties"].update(part.get("properties", {}))
        out["required"] += part.get("required", [])
    return out


def _errors(value, schema: dict, where: str = "body") -> list[str]:
    """Strict check for request bodies: required keys, no undeclared keys, types."""
    schema = _merged(schema)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [_errors(value, s, where) for s in schema[key]]
            return [] if any(not o for o in options) else options[0]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        if not isinstance(value, dict):
            return [f"{where}: expected object"]
        props = schema.get("properties", {})
        errs = [f"{where}.{k}: required" for k in schema.get("required", []) if k not in value]
        if props and schema.get("additionalProperties") is not True:
            errs += [f"{where}.{k}: not in the spec" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                errs += _errors(v, props[k], f"{where}.{k}")
        return errs
    types = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list}
    if kind in types and not isinstance(value, types[kind]):
        return [f"{where}: expected {kind}"]
    if kind == "array":
        return [e for i, v in enumerate(value) for e in _errors(v, schema.get("items", {}), f"{where}[{i}]")]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{where}: {value!r} not in {schema['enum']}"]
    return []


def _declares(schema: dict, dotted: str):
    """True/False if the spec declares the field; None if the spec leaves it untyped."""
    for part in dotted.split("."):
        schema = _merged(schema)
        if "type" not in schema and "properties" not in schema:
            return None
        name, is_list = part.removesuffix("[]"), part.endswith("[]")
        if name not in schema.get("properties", {}):
            return False
        schema = schema["properties"][name]
        if is_list:
            schema = _merged(schema).get("items", {})
    return True


def _operation(method: str, url: str) -> str:
    for key in SUBSET:
        _service, op_method, template = key.split(" ", 2)
        pattern = re.escape(template).replace(r"\{worldId\}", "[^/]+")
        if op_method == method and re.search(pattern + "$", url.split("?")[0]):
            return key
    raise AssertionError(f"{method} {url} is not an operation in the OpenAPI subset")


def _exercise() -> list:
    """Drive every code path that talks HTTP; return the captured calls."""
    s = _Scripted([("/search", {"results": []}), ("/sparql", {"head": {"vars": []}, "results": {"bindings": []}}),
                   ("/import", {"imported": {"quads": 1, "chunks": 0}}),
                   ("/auth/tokens", {"token": {"token": "wzw_x"}}), ("/v1/worlds", {"world": {"id": "w_1"}})])
    with mock.patch.object(wz._urlrequest, "urlopen", s):
        p = make_provider()
        p.handle_tool_call("wazoo_search", {"query": "x", "top_k": 7})
        p.handle_tool_call("wazoo_sparql", {"query": "SELECT * WHERE { ?s ?p ?o }"})
        p.handle_tool_call("wazoo_memories", {"kind": "decision"})
        p.handle_tool_call("wazoo_remember", {"kind": "decision", "statement": "Use RDF."})
        p.prefetch("what did we decide about storage?")
        wz._provision("https://api.test", "wzp_x", "main")
    return s.calls


class TestOpenApiContract(unittest.TestCase):
    def setUp(self):
        _SECRETS.clear()
        self.calls = _exercise()

    def test_every_operation_is_exercised(self):
        seen = {_operation(m, u) for m, u, _b, _h in self.calls}
        self.assertEqual(seen, set(SUBSET))

    def test_request_bodies_match_spec(self):
        for method, url, body, _h in self.calls:
            op = _operation(method, url)
            with self.subTest(op=op):
                schema = _json_schema(SUBSET[op]["request"])
                self.assertEqual(_errors(json.loads(body or "null"), schema), [])

    def test_search_limit_is_the_spec_field(self):
        searches = [json.loads(b) for m, u, b, _h in self.calls if u.endswith("/search")]
        self.assertIn({"query": "x", "limit": 7}, searches)

    def test_fields_read_are_declared(self):
        for op, fields in READS.items():
            responses = SUBSET[op]["responses"]
            schema = _json_schema(responses[min(responses)])
            for field in fields:
                with self.subTest(op=op, field=field):
                    declared = _declares(schema, field)
                    gap = KNOWN_GAPS.get((op, field))
                    if gap:
                        self.assertFalse(declared, f"{gap} is fixed in the spec; drop it from KNOWN_GAPS")
                    elif declared is not None:  # None: spec leaves it untyped (SPARQL results JSON)
                        self.assertTrue(declared, f"{op} does not declare {field}")

    def test_validator_rejects_undeclared_fields(self):
        schema = _json_schema(SUBSET["worlds-api POST /worlds/{worldId}/search"]["request"])
        self.assertIn("body.topK: not in the spec", _errors({"query": "x", "topK": 5}, schema))


if __name__ == "__main__":
    unittest.main()
