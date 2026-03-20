# openline-skills-receipt

**OpenLine Skills Receipt records when an AI skill runs and creates a signed receipt showing which skill was used, which tools it touched, and what output it produced.**

Part of the [OpenLine](https://github.com/terryncew/openline-core) ecosystem.

## What this is

This repo is a small Python library for instrumenting AI skill execution.

When an agent runs a skill, the library emits a signed JSON receipt for that step. The receipt includes:

- the hash of the `SKILL.md` file used at invocation time
- the invoking session and agent token
- any MCP or runtime tools touched during the step
- the hash of the output produced at that step
- the eval label and optional eval score
- an optional coherence payload (`kappa`, `delta_hol`, `vkd`)
- the hash of the previous receipt in the chain
- an Ed25519 signature

The point is simple: make skill execution legible after the fact.

## Why it exists

Skills are portable. MCP gives agents reach. What is usually missing is the record of what actually happened when a skill ran.

This repo explores one narrow fix: emit a receipt at the moment of invocation.

That receipt is meant to answer basic questions later:

- Which skill ran?
- Which version was used?
- Which tools did it touch?
- What output hash did it produce?
- What step came before it in the chain?

## Status

This is a prototype. It works as a local library and demo emitter.

| Area | Status | Notes |
|---|---|---|
| Skill hashing | Working | Hashes the exact `SKILL.md` content at invocation time |
| Receipt construction | Working | Emits signed JSON receipts |
| Signature format | Working | Uses Ed25519 signatures |
| Local verification | Working | Verifies receipt ID and signature |
| Hash chaining | Working | Links each step to the previous receipt |
| Per-session state | Working | Thread-safe session tracking inside one process |
| Output persistence | Working | Optional atomic write to disk |
| Schema validation | Not added yet | No JSON Schema enforcement in this repo yet |
| Cross-process chain persistence | Not added yet | Session state is in-memory only |
| Production privacy defaults | Not finished | You choose what identifiers to pass in |
| Framework adapters | Not included yet | No bundled LangChain/LangGraph/MCP middleware adapters yet |
| Settlement / payouts | Not included | Out of scope for this repo version |

## Quick start

```bash
git clone https://github.com/terryncew/openline-skills-receipt
cd openline-skills-receipt
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python openline_receipt.py examples/example-skill/SKILL.md
```

That demo creates a two-step receipt chain and writes receipt JSON files into `./receipts`.

## Minimal example

```python
from openline_receipt import SkillReceiptHook

hook = SkillReceiptHook(skill_path="./examples/example-skill/SKILL.md", output_dir="./receipts")

receipt = hook.emit(
    session_id="sess_001",
    output={"status": "ok"},
    eval_label="pass",
    eval_score=0.97,
    agent_token="anon_abc123",
    mcp_tools=[{"server": "filesystem", "tool": "write_file", "resource": "draft.txt"}],
    coherence={"kappa": 0.08, "delta_hol": 0.02, "vkd": 0.91, "flag": "nominal"},
)
```

## Example receipt shape

```json
{
  "receipt_id": "...",
  "schema_version": "0.2.0",
  "timestamp_utc": "2026-03-20T00:00:00Z",
  "skill": {
    "name": "example-skill",
    "hash": "...",
    "version": "0.1.0",
    "license": "MIT"
  },
  "invocation": {
    "agent_token": "demo_agent",
    "session_id": "demo_session_001",
    "step_index": 1,
    "runtime": "custom"
  },
  "mcp_tools_touched": [
    {
      "server": "filesystem",
      "tool": "write_file",
      "resource": "final.txt"
    }
  ],
  "outcome": {
    "eval_label": "pass",
    "eval_score": 0.95,
    "eval_source": "automated",
    "output_hash": "..."
  },
  "coherence": {
    "kappa": 0.11,
    "delta_hol": 0.05,
    "vkd": 0.79,
    "coherence_flag": "nominal"
  },
  "prev_receipt_hash": "...",
  "signature": {
    "alg": "Ed25519",
    "key_id": "...",
    "public_key": "...",
    "sig": "..."
  }
}
```

## Current API

### `build_receipt(...)`
Builds a receipt dict for a single skill invocation.

### `verify_receipt(receipt)`
Checks the receipt ID and Ed25519 signature.

### `SkillReceiptHook(...)`
Maintains per-session chain state and emits receipts step by step.

## Design notes

This repo keeps the payload small and leaves raw tool payloads out of the receipt by default. If you pass tool `input` or `output`, the library hashes them instead of storing them in the receipt.

Receipts are signed with Ed25519 so they can be verified later from the embedded public key. That is a better fit for portable verification than a shared-secret HMAC.

## Relation to OpenLine

This repo is a concrete extension of the broader OpenLine idea: emit compact, checkable records at the points where agent systems hand work off across boundaries.

If COLE measures coherence during a run, this repo attaches skill-level provenance to that step.

## Prior work

**White, T. (2025). _Coherence Dynamics: A Framework for Measuring Structural Stress in Bounded Processing Systems._**  
Zenodo. DOI: 10.5281/zenodo.17476985

## License

MIT.
