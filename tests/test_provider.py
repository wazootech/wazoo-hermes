"""Tests for the wazoo memory provider. All HTTP goes through a scripted urllib."""

import json
import os
import time
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
    def test_save_config_is_noop_and_never_touches_config_yaml(self):
        import tempfile, os
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "config.yaml")
        with open(path, "w") as fh:
            fh.write("model:\n  name: gpt\n")
        before = open(path).read()
        p = wz.WazooMemoryProvider()
        p.save_config({"world_id": "w_1"}, tmp)
        self.assertEqual(open(path).read(), before)  # core owns persistence


class TestPersistedState(unittest.TestCase):
    """Provisioned ids live in the plugin-owned state file (0600), not .env."""

    def test_save_then_initialize_reads_state_file(self):
        import tempfile, os, stat
        tmp = tempfile.mkdtemp()
        p = wz.WazooMemoryProvider()
        p._save_provisioned(tmp, "w_state", "wzw_state")
        path = os.path.join(tmp, "wazoo", "world.json")
        self.assertTrue(os.path.exists(path))
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0)  # owner-only

        _SECRETS.clear()
        p2 = wz.WazooMemoryProvider()
        p2.initialize("s", hermes_home=tmp, platform="cli")
        self.assertEqual(p2._world_id, "w_state")
        self.assertEqual(p2._world_token, "wzw_state")
        self.assertTrue(p2._ready)

    def test_secrets_win_over_state_file(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        p = wz.WazooMemoryProvider()
        p._save_provisioned(tmp, "w_state", "wzw_state")
        _SECRETS["WORLDS_TOKEN"] = "wzw_env"
        _SECRETS["WORLD_ID"] = "w_env"
        p2 = wz.WazooMemoryProvider()
        p2.initialize("s", hermes_home=tmp, platform="cli")
        self.assertEqual((p2._world_id, p2._world_token), ("w_env", "wzw_env"))
        _SECRETS.clear()

    def test_missing_state_file_is_fine(self):
        import tempfile
        p = wz.WazooMemoryProvider()
        self.assertEqual(p._load_provisioned(tempfile.mkdtemp()), {})
        self.assertEqual(p._load_provisioned("/nonexistent-home"), {})


class TestPrefetchBackpressure(unittest.TestCase):
    """A query arriving while a recall is in flight must be requeued, not dropped."""

    def test_second_query_runs_after_first_completes(self):
        import threading
        p = make_provider()
        gate = threading.Event()
        calls = []

        bodies = []

        class _Gate:
            def __call__(self, req, timeout=None):
                calls.append(req.get_full_url())
                bodies.append((req.data or b"").decode())
                gate.wait(2.0)
                return _payload({"results": [{"content": f"hit {len(calls)}"}]})

        def _payload(b):
            return _RespShim(b)

        with mock.patch.object(wz._urlrequest, "urlopen", _Gate()):
            p.queue_prefetch("first question")
            t1 = p._prefetch_thread
            p.queue_prefetch("second question")
            self.assertEqual(p._pending_query, "second question")
            gate.set()
            t1.join(3)
            time.sleep(0.3)  # let the requeued worker start and finish
            t2 = p._prefetch_thread
            if t2 and t2 is not t1:
                t2.join(3)
        self.assertEqual(len(calls), 2)
        self.assertEqual(p._pending_query, "")
        self.assertIn("second question", bodies[1])

    def test_same_query_parked_once_not_looped(self):
        import threading
        p = make_provider()
        gate = threading.Event()
        calls = []

        class _Gate:
            def __call__(self, req, timeout=None):
                calls.append(req.get_full_url())
                gate.wait(2.0)
                return _RespShim({"results": []})

        with mock.patch.object(wz._urlrequest, "urlopen", _Gate()):
            p.queue_prefetch("same")
            t1 = p._prefetch_thread
            p.queue_prefetch("same")
            gate.set()
            t1.join(3)
            time.sleep(0.3)
        # same query was parked, requeued once, ran once more, no loop
        self.assertLessEqual(len(calls), 3)
        self.assertEqual(p._pending_query, "")


class _RespShim:
    def __init__(self, b):
        self._b = json.dumps(b).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
