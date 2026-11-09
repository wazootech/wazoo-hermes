"""Wazoo memory provider for Hermes Agent.

Stores the agent's cross-session knowledge in a Wazoo world: typed memories
(decision, preference, person, project, finding, correction) in an RDF graph,
hybrid search for recall, and SPARQL for structural questions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib import request as _urlrequest
from urllib.error import HTTPError, URLError

from agent.memory_provider import MemoryProvider, RecallStatus, spawn_context_thread
from agent.secret_scope import get_secret
from tools.registry import tool_error

logger = logging.getLogger(__name__)

DEFAULT_DATA_URL = "https://data.wazoo.dev"
DEFAULT_CONTROL_URL = "https://api.wazoo.dev"
VOCAB = "https://wazoo.dev/vocab#"

MEMORY_KINDS = ("decision", "preference", "person", "project", "finding", "correction")

SECRET_PATTERNS = (
    re.compile(r"\bwzp_[A-Za-z0-9_]+\b"),
    re.compile(r"\bwzw_[A-Za-z0-9_]+\b"),
    re.compile(r"\bsk-[A-Za-z0-9-]{8,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bbearer\s+[A-Za-z0-9._-]+\b", re.IGNORECASE),
    re.compile(r"\b(api[_-]?key|password|passwd|secret)\s*[:=]\s*\S+", re.IGNORECASE),
)


TRIVIAL_PROMPT_RE = re.compile(
    r"^(yes|no|ok|okay|sure|thanks|thank you|y|n|yep|nope|yeah|nah|hi|hey|hello|yo|sup|"
    r"continue|go ahead|do it|proceed|got it|cool|nice|great|done|next|lgtm|k)"
    r"[\s!?.:;,\"'~\u2018\u2019\u201c\u201d\u2014\u2013\u2026()\[\]{}<>*&^%$#@!+=`\u00a0]*$",
    re.IGNORECASE,
)

# Module-level config schema: the setup wizard and dashboard load CONFIG_SCHEMA
# directly; get_config_schema() returns it. Secrets go to core's scoped store;
# non-secret fields persist through save_config to $HERMES_HOME/wazoo/config.json.
CONFIG_SCHEMA = [
    {"key": "world_token", "description": "Wazoo world token (wzw_)", "secret": True, "required": False,
     "env_var": "WORLDS_TOKEN", "url": "https://wazoo.dev"},
    {"key": "platform_token", "description": "Wazoo platform token (wzp_); provisions a world automatically",
     "secret": True, "required": False, "env_var": "WAZOO_API_KEY", "url": "https://wazoo.dev"},
    {"key": "world_id", "description": "World id (w_...); optional with a world token, ignored when provisioning",
     "default": ""},
    {"key": "data_url", "description": "Worlds data-plane endpoint", "default": DEFAULT_DATA_URL},
]


def _looks_like_secret(text: str) -> bool:
    return any(p.search(text) for p in SECRET_PATTERNS)


def _turtle_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "").replace("\t", " ")


def _memory_iri(kind: str, statement: str) -> str:
    """Stable subject IRI: re-importing the same memory upserts instead of
    duplicating (worlds-api blank-node imports are not idempotent, #177)."""
    digest = hashlib.sha256(f"{kind}|{statement}".encode("utf-8")).hexdigest()[:16]
    return f"<{VOCAB}memory/{kind}-{digest}>"


def _memory_turtle(kind: str, statement: str, supersedes: str | None = None) -> str:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = [
        f"@prefix wz: <{VOCAB}> .",
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
        f"{_memory_iri(kind, statement)} a wz:{kind} ;",
        f'  wz:statement "{_turtle_escape(statement)}" ;',
    ]
    if supersedes:
        lines.append(f'  wz:supersedesStatement "{_turtle_escape(supersedes)}" ;')
    lines.append(f'  wz:recordedAt "{now}"^^xsd:dateTime .')
    return "\n".join(lines) + "\n"


def _http_json(url: str, *, method: str = "GET", token: str = "", body: Any = None, timeout: float = 15.0) -> Any:
    headers = {"Accept": "application/json"}
    if token:  # tokenless only against a custom endpoint the user configured
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = _urlrequest.Request(url, data=data, headers=headers, method=method)
    with _urlrequest.urlopen(req, timeout=timeout) as res:
        payload = res.read()
    return json.loads(payload) if payload else None


def _p(description: str, type_: str = "string", **extra) -> dict:
    return {"type": type_, **extra, "description": description}


def _schema(name: str, description: str, properties: dict | None = None, required: tuple = ()) -> dict:
    return {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties or {}, "required": list(required)}}


_SCHEMAS = (
    _schema("wazoo_search", "Search the agent's Wazoo world memory. Hybrid keyword + vector (vector active when embeddings are configured). Keyword search matches literal values, not predicate names.",
            {"query": _p("What to search for."),
             "top_k": _p("Max results (default: 5, max: 25).", "integer", minimum=1, maximum=25)},
            ("query",)),
    _schema("wazoo_sparql", "Run a SPARQL 1.1 SELECT query against the world's graph. Use for structural questions: lists, relations, counts. Prefix wz: is <https://wazoo.dev/vocab#>.",
            {"query": _p("A SPARQL SELECT query.")}, ("query",)),
    _schema("wazoo_remember", "Save one memory to the world, filed by kind: decision, preference, person, project, finding, or correction. Save only stated facts, never inferred preferences; never secrets. For a correction, set supersedes to the outdated statement.",
            {"kind": _p("What kind of memory this is.", enum=list(MEMORY_KINDS)),
             "statement": _p("The fact to keep, one sentence."),
             "supersedes": _p("For corrections: the outdated statement this replaces.")},
            ("kind", "statement")),
    _schema("wazoo_memories", "List recent memories by kind, newest first. Omit kind to list everything.",
            {"kind": _p("Filter to one kind.", enum=list(MEMORY_KINDS)),
             "limit": _p("Max entries (default: 20, max: 100).", "integer")}),
)


def _provision(control_url: str, platform_token: str, agent_label: str) -> tuple[str, str]:
    """Create a world and mint a world token. Returns (world_id, world_token)."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", agent_label)[:40] or "agent"
    created = _http_json(f"{control_url}/v1/worlds", method="POST", token=platform_token,
                         body={"world": {"displayName": f"Hermes {agent_label}", "region": "auto"}})
    world_id = (created or {}).get("world", {}).get("id")
    if not world_id:
        raise RuntimeError("Wazoo provisioning returned no world id")
    minted = _http_json(f"{control_url}/v1/worlds/{world_id}/auth/tokens", method="POST", token=platform_token,
                        body={"name": f"hermes-{safe}"})
    world_token = (minted or {}).get("token", {}).get("token")
    if not world_token:
        raise RuntimeError("Wazoo token minting returned no secret")
    return world_id, world_token


class WazooMemoryProvider(MemoryProvider):
    """Wazoo world-model memory: typed memories in an RDF graph, hybrid search, SPARQL."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data_url = DEFAULT_DATA_URL
        self._control_url = DEFAULT_CONTROL_URL
        self._world_id = ""
        self._world_token = ""
        self._platform_token = ""
        self._session_id = ""
        self._agent_label = "agent"
        self._ready = False
        self._prefetch_result = ""
        self._prefetch_count = 0
        self._prefetch_thread: threading.Thread | None = None
        self._pending_query = ""

    @property
    def name(self) -> str:
        return "wazoo"

    # -- availability and setup ----------------------------------------------

    @staticmethod
    def _custom_endpoint(cfg: dict[str, str]) -> bool:
        """A non-default data_url plus a world_id: the server decides whether
        a token is needed. The plugin never guesses from the hostname."""
        url = (cfg.get("data_url") or "").rstrip("/")
        return bool(url and url != DEFAULT_DATA_URL and cfg.get("world_id"))

    def is_available(self) -> bool:
        if get_secret("WORLDS_TOKEN") or get_secret("WAZOO_API_KEY"):
            return True
        cfg = self._load_config_block()
        cfg.setdefault("world_id", get_secret("WORLD_ID", "") or "")
        return self._custom_endpoint(cfg)

    def unavailable_reason(self) -> str:
        return ("Set WORLDS_TOKEN (a wzw_ world token) or WAZOO_API_KEY (a wzp_ platform token; "
                "a world is provisioned automatically) in Hermes secrets, or set data_url and world_id for "
                "your own worlds endpoint, then run 'hermes memory setup wazoo'.")

    def get_config_schema(self) -> list[dict[str, Any]]:
        return CONFIG_SCHEMA

    _CONFIG_PATH = "wazoo/config.json"
    _CONFIG_KEYS = ("world_id", "data_url")  # non-secret schema fields only

    def save_config(self, values: dict[str, Any], hermes_home: str) -> None:
        """Persist non-secret setup values (world_id, data_url) to the
        provider's own file, $HERMES_HOME/wazoo/config.json. The CLI setup
        wizard and the dashboard both keep non-secret fields only through this
        hook, so a no-op would drop a self-hosted data_url and send its token
        to the hosted cloud. Secrets are never written here."""
        if not hermes_home:
            return
        path = Path(hermes_home) / self._CONFIG_PATH
        merged = self._read_json(path)
        for key in self._CONFIG_KEYS:
            if key in values and values[key] is not None:
                merged[key] = str(values[key]).strip()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _read_json(path: Path) -> dict[str, str]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {k: str(v).strip() for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    # -- lifecycle ------------------------------------------------------------

    def initialize(self, session_id: str, **kwargs) -> None:
        self._session_id = session_id
        self._agent_label = str(kwargs.get("agent_identity") or "agent")
        # Non-secret config from the provider file / memory.wazoo; secrets from the scoped store.
        home = str(kwargs.get("hermes_home", "") or "")
        base = self._load_config_block(home)
        self._data_url = (base.get("data_url") or DEFAULT_DATA_URL).rstrip("/")
        persisted = self._load_provisioned(home) if home else {}
        self._world_id = get_secret("WORLD_ID", "") or base.get("world_id", "") or persisted.get("world_id", "")
        self._world_token = get_secret("WORLDS_TOKEN", "") or persisted.get("world_token", "")
        self._platform_token = get_secret("WAZOO_API_KEY", "") or ""
        self._home = home
        # A token, or a configured custom endpoint + world (the server decides on auth).
        self._ready = bool(self._world_token) or self._custom_endpoint(
            {"data_url": self._data_url, "world_id": self._world_id})
        # Provision lazily on first use when only a platform token is present; never block startup.
        if not self._ready and self._platform_token:
            self._agent_label = self._agent_label or "agent"

    def _load_config_block(self, hermes_home: str = "") -> dict[str, str]:
        """memory.wazoo from config.yaml, overlaid by what setup saved to
        $HERMES_HOME/wazoo/config.json (the provider's native config)."""
        block: dict[str, str] = {}
        try:
            from hermes_cli.config import load_config_readonly
            raw = load_config_readonly().get("memory", {}).get("wazoo", {})
            if isinstance(raw, dict):
                block = {k: str(v).strip() for k, v in raw.items()}
        except Exception:
            pass
        if not hermes_home:
            try:
                from hermes_constants import get_hermes_home
                hermes_home = str(get_hermes_home())
            except Exception:
                return block
        saved = self._read_json(Path(hermes_home) / self._CONFIG_PATH)
        block.update({k: v for k, v in saved.items() if k in self._CONFIG_KEYS and v})
        return block

    def _ensure_ready(self) -> bool:
        """Resolve credentials; provision once when only a platform token is set."""
        if self._ready:
            return True
        if not self._platform_token:
            return False
        with self._lock:
            if self._ready:
                return True
            try:
                world_id, world_token = _provision(self._control_url, self._platform_token, self._agent_label)
            except Exception as exc:
                logger.debug("Wazoo provisioning failed: %s", exc)
                return False
            self._world_id, self._world_token = world_id, world_token
            self._ready = True
            # Persist the minted ids so restarts reuse the same world.
            _quiet("persist ids", lambda: self._save_provisioned(self._home, world_id, world_token))
            return True

    _STATE_PATH = "wazoo/world.json"

    def _state_file(self, hermes_home: str) -> Path:
        return Path(hermes_home) / self._STATE_PATH

    def _save_provisioned(self, hermes_home: str, world_id: str, world_token: str) -> None:
        """Persist the provisioned ids in the plugin's own file (0600), NOT the
        profile .env: credentials belong in scoped secrets or here, and hand-
        editing shared dotfiles from a plugin is out of bounds."""
        path = self._state_file(hermes_home)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"world_id": world_id, "world_token": world_token}, indent=2) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)

    def _load_provisioned(self, hermes_home: str) -> dict[str, str]:
        path = self._state_file(hermes_home)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {k: str(data[k]) for k in ("world_id", "world_token") if data.get(k)}
        except (OSError, ValueError, KeyError):
            return {}

    # -- system prompt and recall ----------------------------------------------

    def system_prompt_block(self) -> str:
        world = self._world_id or "auto-provisioned"
        return (f"# Wazoo Memory\nActive. World: {world}.\n"
                "wazoo_search recalls facts; wazoo_sparql answers structural questions (lists, relations, counts); "
                "wazoo_remember saves a typed memory (decision, preference, person, project, finding, correction) — "
                "never secrets or inferred preferences; corrections carry supersedes.")

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        if not self._ensure_ready() or not query.strip():
            return
        if self._prefetch_thread and self._prefetch_thread.is_alive():
            # A recall is already in flight. Park this query behind it instead
            # of dropping it: on rapid turns the newest question is the one the
            # next prefetch should answer. The running worker requeues it.
            self._pending_query = query[:512]
            return
        self._start_prefetch(query, session_id)

    def _start_prefetch(self, query: str, session_id: str) -> None:
        world_id, token, data_url = self._world_id, self._world_token, self._data_url

        def fetch() -> tuple[str, int]:
            data = _http_json(f"{data_url}/worlds/{world_id}/search", method="POST", token=token,
                              body={"query": query[:512], "limit": 5})
            results = (data or {}).get("results") or []
            lines = []
            for r in results[:5]:
                text = r.get("content") or ""
                if text:
                    lines.append(f"- {text}")
            return ("\n".join(lines), len(lines)) if lines else ("", 0)

        def store() -> None:
            try:
                text, count = fetch()
            except Exception as exc:
                logger.debug("Wazoo prefetch failed: %s", exc)
                return
            with self._lock:
                self._prefetch_result, self._prefetch_count = text, count
            # A query arrived while this recall was running; start it now.
            # _start_prefetch, not queue_prefetch: the alive check would see
            # this very thread and re-park the query forever.
            pending = getattr(self, "_pending_query", "")
            if pending:
                self._pending_query = ""
                self._start_prefetch(pending, session_id)

        self._prefetch_thread = spawn_context_thread(store, name="wazoo-prefetch")
        self._prefetch_thread.start()

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        """Consume the queued recall. On a cache miss with time in hand, search inline."""
        with self._lock:
            text, count = self._prefetch_result, self._prefetch_count
            self._prefetch_result = ""
        if not text and (not self._ensure_ready() or not query.strip() or TRIVIAL_PROMPT_RE.match(query.strip())):
            with self._lock:
                self._prefetch_count = 0
            return ""
        if not text:
            try:
                data = _http_json(f"{self._data_url}/worlds/{self._world_id}/search", method="POST",
                                  token=self._world_token, body={"query": query[:512], "limit": 5}, timeout=6.0)
                results = (data or {}).get("results") or []
                lines = [f"- {r.get('content')}" for r in results[:5] if r.get("content")]
                text, count = ("\n".join(lines), len(lines)) if lines else ("", 0)
            except Exception as exc:
                logger.debug("Wazoo inline prefetch failed: %s", exc)
                count = 0  # a failed search injected nothing; never report a stale count
            with self._lock:
                self._prefetch_count = count
        return f"[Wazoo memory]\n{text}" if text else ""


    def recall_status(self) -> RecallStatus | None:
        with self._lock:
            count = self._prefetch_count
        if count <= 0:
            return None
        return RecallStatus(provider_label="wazoo", count=count)

    def sync_turn(self, user_content: str, assistant_content: str, *, session_id: str = "",
                  messages: list[dict[str, Any]] | None = None) -> None:
        """Deliberately a no-op: the world holds curated typed facts, not transcripts.
        Facts reach it through wazoo_remember and on_memory_write mirroring."""

    # -- tools -----------------------------------------------------------------

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        return list(_SCHEMAS)

    def handle_tool_call(self, tool_name: str, args: dict, **kwargs) -> str:
        if not self._ensure_ready():
            return json.dumps(tool_error("Wazoo is not configured: set WORLDS_TOKEN or WAZOO_API_KEY"))
        if not self._world_id:
            return json.dumps(tool_error("Wazoo world id is not set: set WORLD_ID (or memory.wazoo.world_id in config.yaml), or provision with WAZOO_API_KEY"))
        try:
            return json.dumps(self._dispatch(tool_name, args))
        except HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8", "replace")).get("error", {}).get("message", "")
            except Exception:
                detail = ""
            return json.dumps(tool_error(f"Wazoo API error {exc.code}: {detail or exc.reason}"))
        except (URLError, TimeoutError, ConnectionError) as exc:
            return json.dumps(tool_error(f"Wazoo API unreachable: {exc}"))
        except Exception as exc:
            return json.dumps(tool_error(str(exc)))

    def _dispatch(self, tool_name: str, args: dict) -> Any:
        if tool_name == "wazoo_search":
            query = str(args.get("query", "")).strip()
            if not query:
                return {"error": "query is required"}
            top_k = max(1, min(int(args.get("top_k", 5) or 5), 25))
            data = _http_json(f"{self._data_url}/worlds/{self._world_id}/search", method="POST",
                              token=self._world_token, body={"query": query, "limit": top_k})
            results = [{"content": r.get("content"), "subject": r.get("subject"), "score": r.get("score")}
                       for r in (data or {}).get("results") or []]
            return {"results": results}

        if tool_name == "wazoo_sparql":
            query = str(args.get("query", "")).strip()
            if not query:
                return {"error": "query is required"}
            data = _http_json(f"{self._data_url}/worlds/{self._world_id}/sparql", method="POST",
                              token=self._world_token, body={"query": query})
            bindings = (data or {}).get("results", {}).get("bindings") or []
            vars_ = (data or {}).get("head", {}).get("vars") or []
            rows = [{v: b[v]["value"] for v in vars_ if v in b} for b in bindings]
            return {"rows": rows}

        if tool_name == "wazoo_remember":
            kind = str(args.get("kind", "")).strip()
            statement = str(args.get("statement", "")).strip()
            supersedes = str(args.get("supersedes", "")).strip() or None
            if kind not in MEMORY_KINDS:
                return {"error": f"Unknown memory kind '{kind}'. Use one of: {', '.join(MEMORY_KINDS)}"}
            if not statement:
                return {"error": "statement is required"}
            if _looks_like_secret(statement) or (supersedes and _looks_like_secret(supersedes)):
                return {"error": "Refused: this looks like a secret (token, key, or credential). Secrets are never stored in the world."}
            return self._import(_memory_turtle(kind, statement, supersedes))

        if tool_name == "wazoo_memories":
            kind = str(args.get("kind", "")).strip()
            limit = max(1, min(int(args.get("limit", 20) or 20), 100))
            kind_filter = f"FILTER(?kind = wz:{kind})" if kind in MEMORY_KINDS else ""
            query = (f"PREFIX wz: <{VOCAB}>\nSELECT ?kind ?statement ?when WHERE {{ "
                     f"?m a ?kind ; wz:statement ?statement ; wz:recordedAt ?when . {kind_filter} }} "
                     f"ORDER BY DESC(?when) LIMIT {limit}")
            data = _http_json(f"{self._data_url}/worlds/{self._world_id}/sparql", method="POST",
                              token=self._world_token, body={"query": query})
            bindings = (data or {}).get("results", {}).get("bindings") or []
            rows = [{"kind": b.get("kind", {}).get("value", "").rsplit("#", 1)[-1],
                     "statement": b.get("statement", {}).get("value"),
                     "recorded_at": b.get("when", {}).get("value")} for b in bindings]
            return {"memories": rows}

        return {"error": f"Unknown tool: {tool_name}"}

    # -- mirroring, shutdown -----------------------------------------------------

    def on_memory_write(self, action: str, target: str, content: str, metadata: dict | None = None) -> None:
        """Mirror built-in memory writes into the world as typed memories."""
        if not content or not self._ready:
            return
        if action == "add":
            kind = "preference" if target == "user" else "finding"
            _quiet("memory mirror", lambda: self._import(_memory_turtle(kind, content.strip())))
        elif action in ("replace", "remove"):
            previous = (metadata or {}).get("previous_content")
            if not previous:
                return  # exact identity unavailable; skip destructive mirroring
            kind = "correction"
            _quiet("memory mirror", lambda: self._import(_memory_turtle(kind, content.strip(), previous.strip())))

    def _import(self, turtle: str) -> dict:
        url = f"{self._data_url}/worlds/{self._world_id}/import"
        data = _http_json(url, method="POST", token=self._world_token,
                          body={"data": turtle, "contentType": "text/turtle"})
        imported = (data or {}).get("imported") or (data or {})
        # Search indexing is not required for SPARQL; skip reindex to keep writes fast.
        return {"quads": imported.get("quads", 0), "chunks": imported.get("chunks", 0)}

    def shutdown(self) -> None:
        thread, self._prefetch_thread = self._prefetch_thread, None
        if thread and thread.is_alive():
            thread.join(timeout=3.0)


def _quiet(label: str, fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception as exc:
        logger.debug("Wazoo %s failed: %s", label, exc)
        return None


def register(ctx) -> None:
    """Register Wazoo as a memory provider plugin."""
    ctx.register_memory_provider(WazooMemoryProvider())
