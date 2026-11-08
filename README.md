# Wazoo memory provider for Hermes Agent

A [memory provider plugin](https://hermes-agent.nousresearch.com/docs/developer-guide/memory-provider-plugin)
for Hermes Agent. Stores the agent's cross-session knowledge in a
[Wazoo](https://wazoo.dev) world: typed memories in an RDF graph, hybrid search
for recall, SPARQL for structural questions.

## What Hermes gets

| Surface | What it does |
| --- | --- |
| Prefetch recall | Before each turn, the provider searches the world and injects the top results as a context block (background recall, cached; trivial prompts skip the round trip). |
| `wazoo_search` | Hybrid keyword + vector search over the world's memory. |
| `wazoo_sparql` | SPARQL 1.1 SELECT against the graph, for lists, relations and counts. |
| `wazoo_remember` | Save one typed memory: decision, preference, person, project, finding, correction. Corrections carry the statement they supersede. Statements that look like tokens or keys are refused by the tool. |
| `wazoo_memories` | Recent memories by kind, newest first. |
| Memory mirroring | Built-in MEMORY.md / USER.md writes are mirrored into the world as typed memories; `replace` and `remove` writes become corrections with `wz:supersedesStatement`. |

The provider deliberately does not mirror transcripts (`sync_turn` is a
no-op): the world holds curated typed facts, not raw conversation.

## Install

From the Hermes plugin catalog (once listed):

```
hermes plugins install wazoo
```

Or from this repository at a pinned commit.

## Setup

Three paths, all through `hermes memory setup wazoo` (or Hermes secrets):

- **One world per agent (default):** set `WORLDS_TOKEN` (a `wzw_` world
  token) and `WORLD_ID`. Get both from the Wazoo console.
- **Zero-config:** set `WAZOO_PLATFORM_TOKEN` (a `wzp_` token). On first use
  the provider provisions a world named after the profile, mints a scoped
  world token, and persists both to `$HERMES_HOME/wazoo/world.json` (mode
  0600). Explicit `WORLDS_TOKEN` / `WORLD_ID` secrets always win over the
  state file.
- **Self-hosted:** set `data_url` to your own worlds endpoint (for example
  `http://localhost:8787`) and `world_id`. No Wazoo account involved. The
  provider sends `WORLDS_TOKEN` when one is set and no `Authorization`
  header otherwise, so the server decides whether a key is required.
  Today's worlds-api always requires one: mint a namespace key from your own
  `WORLDS_API_ADMIN_KEY` once and set it as `WORLDS_TOKEN`.

  ```
  curl -s -X POST http://localhost:8787/api-keys \
    -H "Authorization: Bearer $WORLDS_API_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{"name":"hermes","namespace":"local"}'
  ```

Optional config keys: `data_url` (default `https://data.wazoo.dev`),
`world_id`. `hermes memory setup wazoo` saves them to
`$HERMES_HOME/wazoo/config.json`, which overrides a hand-written
`memory.wazoo` section in `config.yaml`. Tokens are never written there.

## Why an RDF graph for agent memory

Every memory is a node with a class and a timestamp, so "what did we decide
about X" is one query, retractions are recorded instead of overwritten, and
structural questions ("list every decision from November") are answerable
exactly, not by vibes. Text search still works for the fuzzy cases.

```
PREFIX wz: <https://wazoo.dev/vocab#>
SELECT ?kind ?statement ?when WHERE {
  ?m a ?kind ; wz:statement ?statement ; wz:recordedAt ?when .
} ORDER BY DESC(?when) LIMIT 20
```

## Development

```
python3 -m unittest discover tests
```

The test suite stubs the Hermes host modules, so it runs without a Hermes
install. HTTP is scripted per test; no network in CI.

Apache-2.0
