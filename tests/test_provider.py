"""Tests for the wazoo memory provider. All HTTP goes through a scripted urllib."""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, ".")

# Stub the Hermes host modules so the provider imports standalone.
hermes = type(mock.Mock())  # placeholder namespace holder
import types

agent = types.ModuleType("agent")
mp = types.ModuleType("agent.memory_provider")


class MemoryProvider:  # minimal stand-in ABC
    pre_compress_checkpoint_api_version = 1


class RecallStatus:
    def __init__(self, provider_label, count, glyph="*"):
        self.provider_label, self.count, self.glyph = provider_label, count, glyph


def spawn_context_thread(fn, *, name, daemon=True, args=()):
    import threading
    t = threading.Thread(target=fn, args=args, daemon=True)
    return t


mp.MemoryProvider = MemoryProvider
mp.RecallStatus = RecallStatus
mp.spawn_context_thread = spawn_context_thread
agent.memory_provider = mp
secret_scope = types.ModuleType("agent.secret_scope")
secret_scope.get_secret = lambda key, default="": _SECRETS.get(key, default)
agent.secret_scope = secret_scope
tools_mod = types.ModuleType("tools")
registry = types.ModuleType("tools.registry")
registry.tool_error = lambda msg: {"error": msg}
tools_mod.registry = registry
sys.modules["agent"] = agent
sys.modules["agent.memory_provider"] = mp
sys.modules["agent.secret_scope"] = secret_scope
sys.modules["tools"] = tools_mod
sys.modules["tools.registry"] = registry

_SECRETS: dict[str, str] = {}

import importlib.util

spec = importlib.util.spec_from_file_location("wazoo_provider", "__init__.py")
wz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wz)


class _Res:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Scripted:
    """Install a scripted urlopen; each entry matches a URL substring."""

    def __init__(self, routes):
        self.routes = routes  # list of (substring, payload or exception)
        self.calls = []

    def __call__(self, req, timeout=None):
        url = req.get_full_url()
        self.calls.append((req.get_method(), url, (req.data or b"").decode(), dict(req.headers)))
        for sub, payload in self.routes:
            if sub in url:
                if isinstance(payload, Exception):
                    raise payload
                return _Res(payload)
        raise AssertionError(f"unexpected {url}")


def make_provider(**kw):
    p = wz.WazooMemoryProvider()
    p._data_url = "https://data.test"
    p._world_id = "w_test"
    p._world_token = "wzw_test"
    p._ready = True
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class TestRemember(unittest.TestCase):
    def test_typed_memory_saves_turtle(self):
        p = make_provider()
        s = _Scripted([("/import", {"imported": {"quads": 3, "chunks": 0}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call("wazoo_remember", {"kind": "decision", "statement": "ship on Tuesdays"}))
        self.assertNotIn("error", out)
        self.assertIn('"data"', s.calls[0][2])
        body = json.loads(s.calls[0][2])
        self.assertIn("a wz:decision", body["data"])
        self.assertIn('wz:statement "ship on Tuesdays"', body["data"])
        self.assertEqual(body["contentType"], "text/turtle")

    def test_correction_carries_supersedes(self):
        p = make_provider()
        s = _Scripted([("/import", {"imported": {"quads": 4, "chunks": 0}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call(
                "wazoo_remember", {"kind": "correction", "statement": "new fact", "supersedes": "old fact"}))
        self.assertNotIn("error", out)
        body = json.loads(s.calls[0][2])
        self.assertIn('wz:supersedesStatement "old fact"', body["data"])

    def test_rejects_unknown_kind(self):
        p = make_provider()
        out = json.loads(p.handle_tool_call("wazoo_remember", {"kind": "vibe", "statement": "x"}))
        self.assertIn("Unknown memory kind", out["error"])

    def test_rejects_secrets(self):
        p = make_provider()
        out = json.loads(p.handle_tool_call(
            "wazoo_remember", {"kind": "finding", "statement": "the key is wzp_abcdef123456"}))
        self.assertIn("Refused", out["error"])

    def test_escapes_quotes_and_newlines(self):
        p = make_provider()
        s = _Scripted([("/import", {"imported": {"quads": 2, "chunks": 0}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.handle_tool_call("wazoo_remember", {"kind": "preference", 'statement': 'say "hi"\nthen stop'})
        body = json.loads(s.calls[0][2])
        self.assertIn('\\"hi\\"', body["data"])
        self.assertIn("\\nthen", body["data"])


class TestSearchAndSparql(unittest.TestCase):
    def test_search_maps_fields(self):
        p = make_provider()
        s = _Scripted([("/search", {"results": [{"content": "Ethan Davidson", "subject": "https://x/e", "score": 1}]})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call("wazoo_search", {"query": "Ethan", "top_k": 3}))
        self.assertEqual(out["results"][0]["content"], "Ethan Davidson")
        self.assertIn('"topK": 3', s.calls[0][2])

    def test_sparql_returns_rows(self):
        p = make_provider()
        s = _Scripted([("/sparql", {"head": {"vars": ["n"]}, "results": {"bindings": [{"n": {"value": "23"}}]}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call("wazoo_sparql", {"query": "SELECT (COUNT(?s) AS ?n) WHERE { ?s ?p ?o }"}))
        self.assertEqual(out["rows"], [{"n": "23"}])

    def test_memories_filters_by_kind(self):
        p = make_provider()
        s = _Scripted([("/sparql", {"head": {"vars": ["kind"]},
                                    "results": {"bindings": [{"kind": {"value": "https://wazoo.dev/vocab#decision"},
                                                              "statement": {"value": "s"},
                                                              "when": {"value": "2026-11-04T00:00:00Z"}}]}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call("wazoo_memories", {"kind": "decision"}))
        self.assertEqual(out["memories"][0]["kind"], "decision")
        query_sent = s.calls[0][2]
        self.assertIn("FILTER(?kind = wz:decision)", json.loads(query_sent)["query"])


class TestHooks(unittest.TestCase):
    def test_on_memory_write_add_mirrors_as_typed(self):
        p = make_provider()
        s = _Scripted([("/import", {"imported": {"quads": 3, "chunks": 0}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.on_memory_write("add", "user", "Ethan prefers short replies")
        body = json.loads(s.calls[0][2])
        self.assertIn("a wz:preference", body["data"])

    def test_on_memory_write_replace_makes_correction(self):
        p = make_provider()
        s = _Scripted([("/import", {"imported": {"quads": 4, "chunks": 0}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.on_memory_write("replace", "memory", "new text", {"previous_content": "old text"})
        body = json.loads(s.calls[0][2])
        self.assertIn("a wz:correction", body["data"])
        self.assertIn('wz:supersedesStatement "old text"', body["data"])

    def test_on_memory_write_remove_without_previous_skips(self):
        p = make_provider()
        s = _Scripted([])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.on_memory_write("remove", "memory", "gone", {})
        self.assertEqual(s.calls, [])

    def test_prefetch_returns_cached_and_formats(self):
        p = make_provider()
        with p._lock:
            p._prefetch_result, p._prefetch_count = "- fact one", 1
        out = p.prefetch("anything")
        self.assertEqual(out, "[Wazoo memory]\n- fact one")
        status = p.recall_status()
        self.assertEqual(status.count, 1)  # reflects the last injected prefetch

    def test_prefetch_skips_trivial_prompts(self):
        p = make_provider()
        s = _Scripted([])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = p.prefetch("ok")
        self.assertEqual(out, "")
        self.assertEqual(s.calls, [])


class TestProvisioning(unittest.TestCase):
    def test_provision_creates_world_and_token(self):
        s = _Scripted([("/auth/tokens", {"token": {"token": "wzw_new"}}),
                       ("/v1/worlds", {"world": {"id": "w_new"}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            world_id, token = wz._provision("https://api.test", "wzp_key", "hermes main")
        self.assertEqual((world_id, token), ("w_new", "wzw_new"))
        body1 = json.loads(s.calls[0][2])
        self.assertEqual(body1["world"]["displayName"], "Hermes hermes main")

    def test_lazy_provision_on_first_tool_call(self):
        p = wz.WazooMemoryProvider()
        p._platform_token = "wzp_key"
        p._agent_label = "main"
        s = _Scripted([("/auth/tokens", {"token": {"token": "wzw_new"}}),
                       ("/search", {"results": []}),
                       ("/v1/worlds", {"world": {"id": "w_new"}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call("wazoo_search", {"query": "x"}))
        self.assertIn("results", out)
        self.assertEqual(p._world_id, "w_new")

    def test_unconfigured_tool_call_is_friendly(self):
        p = wz.WazooMemoryProvider()
        out = json.loads(p.handle_tool_call("wazoo_search", {"query": "x"}))
        self.assertIn("not configured", out["error"])

    def test_provision_failure_returns_error_not_crash(self):
        p = wz.WazooMemoryProvider()
        p._platform_token = "wzp_bad"
        err = _urlerror(403)
        s = _Scripted([("/v1/worlds", err)])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call("wazoo_search", {"query": "x"}))
        self.assertIn("not configured", out["error"])


def _urlerror(code):
    from urllib.error import HTTPError
    return HTTPError("https://api.test", code, "nope", {}, None)


class TestAvailability(unittest.TestCase):
    def test_available_with_world_token(self):
        _SECRETS["WORLDS_TOKEN"] = "wzw_x"
        self.assertTrue(wz.WazooMemoryProvider().is_available())
        _SECRETS.clear()

    def test_available_with_platform_token(self):
        _SECRETS["WAZOO_PLATFORM_TOKEN"] = "wzp_x"
        self.assertTrue(wz.WazooMemoryProvider().is_available())
        _SECRETS.clear()

    def test_unavailable_without_secrets(self):
        _SECRETS.clear()
        self.assertFalse(wz.WazooMemoryProvider().is_available())
        self.assertIn("WORLDS_TOKEN", wz.WazooMemoryProvider().unavailable_reason())


if __name__ == "__main__":
    unittest.main()


class TestQueuePrefetch(unittest.TestCase):
    def test_queue_prefetch_fills_cache_for_next_turn(self):
        p = make_provider()
        s = _Scripted([("/search", {"results": [{"content": "queued fact", "score": 1}]})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.queue_prefetch("what was decided about shipping")
            t = p._prefetch_thread
            if t:
                t.join(timeout=5)
            out = p.prefetch("what was decided about shipping")
        self.assertEqual(out, "[Wazoo memory]\n- queued fact")
        self.assertEqual(p.recall_status().count, 1)

    def test_queue_prefetch_failure_leaves_cache_empty(self):
        p = make_provider()
        s = _Scripted([("/search", _err())])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.queue_prefetch("query")
            t = p._prefetch_thread
            if t:
                t.join(timeout=5)
            self.assertEqual(p.prefetch("query"), "")


def _err():
    from urllib.error import HTTPError
    return HTTPError("https://data.test", 500, "boom", {}, None)


class TestRecallContract(unittest.TestCase):
    def test_trivial_prompt_returns_cached_recall(self):
        # The queue was filled for this turn before the user typed a trivial reply;
        # returning it is correct and the status reflects what was injected.
        p = make_provider()
        with p._lock:
            p._prefetch_result, p._prefetch_count = "- old fact", 3
        self.assertEqual(p.prefetch("ok"), "[Wazoo memory]\n- old fact")
        self.assertEqual(p.recall_status().count, 3)

    def test_trivial_prompt_with_empty_cache_resets_count(self):
        p = make_provider()
        with p._lock:
            p._prefetch_result, p._prefetch_count = "", 3
        self.assertEqual(p.prefetch("ok"), "")
        self.assertIsNone(p.recall_status())

    def test_failed_inline_search_also_resets_count(self):
        p = make_provider()
        p._world_token = "wzw_dead"  # ready=True, but the search will fail
        s = _Scripted([("/search", _err())])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            with p._lock:
                p._prefetch_result, p._prefetch_count = "", 2
            self.assertEqual(p.prefetch("real question"), "")
        self.assertIsNone(p.recall_status())


class TestSaveConfigSafety(unittest.TestCase):
    def _write(self, tmp, text):
        import os
        os.makedirs(tmp, exist_ok=True)
        path = os.path.join(tmp, "config.yaml")
        if text is not None:
            with open(path, "w") as fh:
                fh.write(text)
        return tmp

    def test_appends_memory_block_when_absent(self):
        import tempfile
        tmp = self._write(tempfile.mkdtemp(), "model:\n  name: gpt\n")
        p = wz.WazooMemoryProvider()
        p.save_config({"world_id": "w_1", "data_url": "https://data.test"}, tmp)
        content = open(os.path.join(tmp, "config.yaml")).read()
        self.assertIn("memory:", content)
        self.assertIn("wazoo:", content)
        self.assertIn("world_id: w_1", content)

    def test_skips_when_memory_block_exists(self):
        import tempfile
        tmp = self._write(tempfile.mkdtemp(), "memory:\n  provider: builtin\n")
        p = wz.WazooMemoryProvider()
        p.save_config({"world_id": "w_1"}, tmp)
        content = open(os.path.join(tmp, "config.yaml")).read()
        self.assertNotIn("wazoo", content)  # no duplicate/corrupted key

    def test_idempotent_when_wazoo_already_present(self):
        import tempfile
        tmp = self._write(tempfile.mkdtemp(), "memory:\n  wazoo:\n    world_id: w_old\n")
        p = wz.WazooMemoryProvider()
        p.save_config({"world_id": "w_1"}, tmp)
        content = open(os.path.join(tmp, "config.yaml")).read()
        self.assertIn("w_old", content)  # dashboard-owned section untouched


class TestLocalMode(unittest.TestCase):
    def _cfg(self, monkey):
        return {"data_url": monkey}

    def test_local_url_available_without_secrets(self):
        _SECRETS.clear()
        p = wz.WazooMemoryProvider()
        p._data_url = "http://localhost:8080"
        with mock.patch.object(p, "_load_config_block", return_value={"data_url": "http://localhost:8080"}):
            self.assertTrue(p.is_available())

    def test_hosted_unavailable_without_secrets(self):
        _SECRETS.clear()
        p = wz.WazooMemoryProvider()
        with mock.patch.object(p, "_load_config_block", return_value={}):
            self.assertFalse(p.is_available())

    def test_local_initialize_is_ready_without_token(self):
        _SECRETS.clear()
        p = wz.WazooMemoryProvider()
        with mock.patch.object(p, "_load_config_block", return_value={"data_url": "http://127.0.0.1:8080", "world_id": "w_local"}):
            p.initialize("s", hermes_home="/tmp")
        self.assertTrue(p._ready)
        self.assertEqual(p._world_id, "w_local")

    def test_local_requests_send_no_auth_header_when_no_token(self):
        p = make_provider()
        p._world_token = ""
        p._data_url = "http://127.0.0.1:8080"
        s = _Scripted([("/search", {"results": []})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.handle_tool_call("wazoo_search", {"query": "x"})
        self.assertNotIn("Authorization", s.calls[0][3])

    def test_hosted_requests_still_send_auth(self):
        p = make_provider()  # token set, hosted url
        s = _Scripted([("/search", {"results": []})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.handle_tool_call("wazoo_search", {"query": "x"})
        self.assertEqual(s.calls[0][3].get("Authorization"), "Bearer wzw_test")


class TestSelfHostedWithLocalKey(unittest.TestCase):
    """Stock worlds-api always requires a Bearer key; self-hosted users mint a
    local namespace key from their own admin key. The provider passes it through
    as a normal token."""

    def test_local_url_with_local_key_works_end_to_end(self):
        _SECRETS.clear()
        p = wz.WazooMemoryProvider()
        p._data_url = "http://localhost:8787"
        p._world_id = "w_local"
        p._world_token = "wzw_local_key"
        p._ready = True
        s = _Scripted([("/import", {"imported": {"quads": 3, "chunks": 0}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            out = json.loads(p.handle_tool_call(
                "wazoo_remember", {"kind": "decision", "statement": "local key works"}))
        self.assertNotIn("error", out)
        self.assertEqual(s.calls[0][3].get("Authorization"), "Bearer wzw_local_key")


class TestIdempotentRemember(unittest.TestCase):
    """worlds-api blank-node imports accumulate duplicates (#177); the provider
    must use stable subject IRIs so retries and repeats upsert."""

    def test_same_statement_produces_identical_triples(self):
        t1 = wz._memory_turtle("decision", "ship on Tuesdays")
        t2 = wz._memory_turtle("decision", "ship on Tuesdays")
        self.assertEqual(t1, t2)
        self.assertIn(f"<{wz.VOCAB}memory/decision-", t1)
        self.assertNotIn("[] a wz:", t1)

    def test_different_kind_same_statement_is_distinct(self):
        t1 = wz._memory_turtle("decision", "x")
        t2 = wz._memory_turtle("preference", "x")
        self.assertNotEqual(t1, t2)

    def test_repeated_remember_does_not_duplicate(self):
        p = make_provider()
        s = _Scripted([("/import", {"imported": {"quads": 3, "chunks": 0}}),
                       ("/import", {"imported": {"quads": 3, "chunks": 0}}),
                       ("/sparql", {"head": {"vars": ["n"]},
                                    "results": {"bindings": [{"n": {"type": "literal", "value": "3"}}]}})])
        with mock.patch.object(wz._urlrequest, "urlopen", s):
            p.handle_tool_call("wazoo_remember", {"kind": "decision", "statement": "same fact"})
            p.handle_tool_call("wazoo_remember", {"kind": "decision", "statement": "same fact"})
            out = json.loads(p.handle_tool_call("wazoo_memories", {"kind": "decision", "limit": 10}))
        body1 = json.loads(s.calls[0][2])
        body2 = json.loads(s.calls[1][2])
        # both imports sent the IDENTICAL document (same subject IRI)
        self.assertEqual(body1["data"], body2["data"])
        self.assertIn(f"<{wz.VOCAB}memory/decision-", body1["data"])
        self.assertNotIn("[] a wz:", body1["data"])
