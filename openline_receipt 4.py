"""
openline_receipt.py

OpenLine Skills Receipt
Creates signed, tamper-evident receipts for AI skill invocations.

This is a prototype library. It emits JSON receipts that bind:
- which SKILL.md ran
- which agent/session invoked it
- which MCP or runtime tools were touched
- what output hash was produced
- what the previous step in the chain was

Signing uses Ed25519.

Usage:
    from openline_receipt import SkillReceiptHook

    hook = SkillReceiptHook(skill_path="./my-skill/SKILL.md")
    receipt = hook.emit(
        session_id="sess_001",
        output={"status": "ok"},
        eval_label="pass",
        agent_token="anon_abc123",
        mcp_tools=[{"server": "filesystem", "tool": "write_file"}],
    )

Prior art:
    White, T. (2025). Coherence Dynamics.
    DOI: 10.5281/zenodo.17476985
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA_VERSION = "0.2.0"
DEFAULT_OUTPUT_DIR = "receipts"


class ReceiptError(ValueError):
    """Raised when a receipt cannot be built or verified."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _hash_jsonable(value: Any) -> str:
    try:
        return _sha256(_canonical_json(value))
    except TypeError:
        return _sha256(repr(value))


def _validate_non_empty_string(name: str, value: str, max_len: int = 512) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ReceiptError(f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise ReceiptError(f"{name} exceeds max length {max_len}")


def _validate_step_index(step_index: int) -> None:
    if not isinstance(step_index, int) or step_index < 0:
        raise ReceiptError("step_index must be a non-negative integer")


def _validate_eval_label(eval_label: str) -> None:
    allowed = {"pass", "fail", "uncertain"}
    if eval_label not in allowed:
        raise ReceiptError(f"eval_label must be one of {sorted(allowed)}")


def _validate_eval_score(eval_score: Optional[float]) -> None:
    if eval_score is None:
        return
    if not isinstance(eval_score, (int, float)):
        raise ReceiptError("eval_score must be numeric")
    if eval_score < 0.0 or eval_score > 1.0:
        raise ReceiptError("eval_score must be between 0.0 and 1.0")


@dataclass(frozen=True)
class Ed25519Signer:
    signing_key: Ed25519PrivateKey
    key_id: str

    @property
    def public_key_b64(self) -> str:
        raw = self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("utf-8")

    def sign_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        message = _canonical_json(payload).encode("utf-8")
        signature = self.signing_key.sign(message)
        return {
            "alg": "Ed25519",
            "key_id": self.key_id,
            "public_key": self.public_key_b64,
            "sig": base64.b64encode(signature).decode("utf-8"),
        }


def _load_signer_from_env() -> Ed25519Signer:
    """
    Load an Ed25519 signer.

    Supported env vars:
    - OPENLINE_ED25519_SEED_HEX: 32-byte seed encoded as 64 hex chars
    - OPENLINE_ED25519_PRIVATE_KEY_B64: base64-encoded 32-byte seed

    If neither is set, a deterministic dev key is derived from a static phrase.
    That fallback is for demo use only.
    """
    seed_hex = os.environ.get("OPENLINE_ED25519_SEED_HEX")
    seed_b64 = os.environ.get("OPENLINE_ED25519_PRIVATE_KEY_B64")

    if seed_hex:
        raw = bytes.fromhex(seed_hex)
        if len(raw) != 32:
            raise ReceiptError("OPENLINE_ED25519_SEED_HEX must decode to 32 bytes")
        signing_key = Ed25519PrivateKey.from_private_bytes(raw)
    elif seed_b64:
        raw = base64.b64decode(seed_b64)
        if len(raw) != 32:
            raise ReceiptError("OPENLINE_ED25519_PRIVATE_KEY_B64 must decode to 32 bytes")
        signing_key = Ed25519PrivateKey.from_private_bytes(raw)
    else:
        raw = hashlib.sha256(b"openline-dev-key-change-me").digest()
        signing_key = Ed25519PrivateKey.from_private_bytes(raw)

    pub = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = _sha256(pub)[:16]
    return Ed25519Signer(signing_key=signing_key, key_id=key_id)


def _verify_signature(payload_without_signature: dict[str, Any], signature_block: dict[str, str]) -> bool:
    if not isinstance(signature_block, dict):
        return False
    if signature_block.get("alg") != "Ed25519":
        return False

    public_key_b64 = signature_block.get("public_key", "")
    sig_b64 = signature_block.get("sig", "")
    if not public_key_b64 or not sig_b64:
        return False

    try:
        verify_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        signature = base64.b64decode(sig_b64)
        verify_key.verify(signature, _canonical_json(payload_without_signature).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _hash_skill_md(skill_path: str) -> dict[str, Any]:
    """Read SKILL.md and extract minimal metadata + full file hash."""
    p = Path(skill_path)
    if not p.exists() or not p.is_file():
        raise ReceiptError(f"skill_path does not exist: {skill_path}")

    content = p.read_text(encoding="utf-8")
    skill_hash = _sha256(content)

    name = p.parent.name or p.stem
    version = "0.1.0"
    license_str = "unknown"
    author_id = None

    in_frontmatter = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "---":
            in_frontmatter = not in_frontmatter
            continue
        if not in_frontmatter or ":" not in stripped:
            continue

        key, raw_value = stripped.split(":", 1)
        value = raw_value.strip().strip('"').strip("'")
        key = key.strip().lower()

        if key == "name":
            name = value or name
        elif key == "version":
            version = value or version
        elif key == "license":
            license_str = value or license_str
        elif key in {"author", "author_id"}:
            author_id = value or author_id

    result: dict[str, Any] = {
        "name": name,
        "hash": skill_hash,
        "version": version,
        "license": license_str,
        "skill_path": str(p),
    }
    if author_id:
        result["author_id"] = author_id
    return result


def _normalize_tool_entry(tool: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(tool, dict):
        raise ReceiptError("each mcp tool entry must be a dict")

    server = str(tool.get("server", "unknown"))
    tool_name = str(tool.get("tool", "unknown"))
    entry: dict[str, Any] = {"server": server, "tool": tool_name}

    if "resource" in tool and tool["resource"] is not None:
        entry["resource"] = str(tool["resource"])
    if "input" in tool:
        entry["input_hash"] = _hash_jsonable(tool["input"])
    if "output" in tool:
        entry["output_hash"] = _hash_jsonable(tool["output"])
    return entry


def build_receipt(
    skill_path: str,
    session_id: str,
    step_index: int,
    output: Any,
    eval_label: str = "uncertain",
    eval_score: Optional[float] = None,
    eval_source: str = "automated",
    agent_token: str = "anonymous",
    model_id: Optional[str] = None,
    runtime: str = "custom",
    mcp_tools: Optional[list[dict[str, Any]]] = None,
    prev_receipt_hash: Optional[str] = None,
    coherence: Optional[dict[str, Any]] = None,
    signer: Optional[Ed25519Signer] = None,
) -> dict[str, Any]:
    """Build a complete OpenLine skill receipt."""
    _validate_non_empty_string("skill_path", skill_path, max_len=4096)
    _validate_non_empty_string("session_id", session_id)
    _validate_non_empty_string("agent_token", agent_token)
    _validate_non_empty_string("eval_source", eval_source)
    _validate_non_empty_string("runtime", runtime)
    _validate_step_index(step_index)
    _validate_eval_label(eval_label)
    _validate_eval_score(eval_score)

    signer = signer or _load_signer_from_env()

    skill_meta = _hash_skill_md(skill_path)
    output_hash = _hash_jsonable(output)
    mcp_tools_touched = [_normalize_tool_entry(tool) for tool in (mcp_tools or [])]

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": _iso_utc_now(),
        "skill": skill_meta,
        "invocation": {
            "agent_token": agent_token,
            "session_id": session_id,
            "step_index": step_index,
            "runtime": runtime,
        },
        "mcp_tools_touched": mcp_tools_touched,
        "outcome": {
            "eval_label": eval_label,
            "eval_source": eval_source,
            "output_hash": output_hash,
        },
    }

    if eval_score is not None:
        payload["outcome"]["eval_score"] = round(float(eval_score), 6)

    if model_id:
        payload["invocation"]["model_id"] = str(model_id)

    if coherence:
        normalized_coherence: dict[str, Any] = {}
        if "kappa" in coherence:
            normalized_coherence["kappa"] = round(float(coherence["kappa"]), 6)
        if "delta_hol" in coherence:
            normalized_coherence["delta_hol"] = round(float(coherence["delta_hol"]), 6)
        if "vkd" in coherence:
            normalized_coherence["vkd"] = round(float(coherence["vkd"]), 6)
        if "flag" in coherence:
            normalized_coherence["coherence_flag"] = str(coherence["flag"])
        if normalized_coherence:
            payload["coherence"] = normalized_coherence

    if prev_receipt_hash:
        payload["prev_receipt_hash"] = prev_receipt_hash

    receipt_id = _sha256(_canonical_json(payload))
    payload["receipt_id"] = receipt_id
    payload["signature"] = signer.sign_payload({k: v for k, v in payload.items() if k != "signature"})
    return payload


def verify_receipt(receipt: dict[str, Any]) -> bool:
    """Verify the receipt_id and Ed25519 signature."""
    if not isinstance(receipt, dict):
        return False

    signature_block = receipt.get("signature")
    payload_for_id = {k: v for k, v in receipt.items() if k not in {"receipt_id", "signature"}}
    expected_id = _sha256(_canonical_json(payload_for_id))
    if receipt.get("receipt_id") != expected_id:
        return False

    payload_for_sig = {k: v for k, v in receipt.items() if k != "signature"}
    return _verify_signature(payload_for_sig, signature_block)


class SkillReceiptHook:
    """
    Emit receipts for each skill invocation.

    Thread-safe by session_id. Each session maintains its own step index and
    previous receipt hash, so concurrent sessions do not smear into one chain.
    """

    def __init__(
        self,
        skill_path: str,
        output_dir: Optional[str] = None,
        signer: Optional[Ed25519Signer] = None,
    ) -> None:
        _validate_non_empty_string("skill_path", skill_path, max_len=4096)
        self.skill_path = skill_path
        self.output_dir = output_dir
        self.signer = signer or _load_signer_from_env()
        self._lock = threading.Lock()
        self._session_state: dict[str, dict[str, Any]] = {}

        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)

    def _get_session_state(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            if session_id not in self._session_state:
                self._session_state[session_id] = {"step_index": 0, "prev_receipt_hash": None}
            return dict(self._session_state[session_id])

    def _update_session_state(self, session_id: str, receipt_id: str) -> None:
        with self._lock:
            state = self._session_state.setdefault(session_id, {"step_index": 0, "prev_receipt_hash": None})
            state["prev_receipt_hash"] = receipt_id
            state["step_index"] += 1

    @staticmethod
    def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(path.parent), delete=False) as tmp:
            json.dump(payload, tmp, indent=2, ensure_ascii=False)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_name = tmp.name
        os.replace(temp_name, path)

    def emit(
        self,
        session_id: str,
        output: Any,
        eval_label: str = "uncertain",
        eval_score: Optional[float] = None,
        agent_token: str = "anonymous",
        mcp_tools: Optional[list[dict[str, Any]]] = None,
        coherence: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Emit a receipt for this skill invocation and advance chain state."""
        state = self._get_session_state(session_id)
        receipt = build_receipt(
            skill_path=self.skill_path,
            session_id=session_id,
            step_index=state["step_index"],
            output=output,
            eval_label=eval_label,
            eval_score=eval_score,
            agent_token=agent_token,
            mcp_tools=mcp_tools,
            prev_receipt_hash=state["prev_receipt_hash"],
            coherence=coherence,
            signer=self.signer,
            **kwargs,
        )
        self._update_session_state(session_id, receipt["receipt_id"])

        if self.output_dir:
            out_path = Path(self.output_dir) / f"{receipt['receipt_id'][:16]}.json"
            self._atomic_write_json(out_path, receipt)

        return receipt

    def reset(self, session_id: Optional[str] = None) -> None:
        """Reset chain state for one session or all sessions."""
        with self._lock:
            if session_id is None:
                self._session_state.clear()
            else:
                self._session_state.pop(session_id, None)


def _demo(skill_path: str) -> int:
    print("OpenLine Skills Receipt — demo run")
    print("=" * 48)

    hook = SkillReceiptHook(skill_path=skill_path, output_dir=DEFAULT_OUTPUT_DIR)

    r1 = hook.emit(
        session_id="demo_session_001",
        output="Step 1 output: draft created",
        eval_label="pass",
        eval_score=0.88,
        agent_token="demo_agent",
        mcp_tools=[{"server": "filesystem", "tool": "write_file", "resource": "draft.txt"}],
        coherence={"kappa": 0.08, "delta_hol": 0.02, "vkd": 0.82, "flag": "nominal"},
    )

    r2 = hook.emit(
        session_id="demo_session_001",
        output="Step 2 output: final revision",
        eval_label="pass",
        eval_score=0.95,
        agent_token="demo_agent",
        mcp_tools=[{"server": "filesystem", "tool": "write_file", "resource": "final.txt"}],
        coherence={"kappa": 0.11, "delta_hol": 0.05, "vkd": 0.79, "flag": "nominal"},
    )

    print(f"Receipt 1 ID:  {r1['receipt_id'][:32]}...")
    print(f"Receipt 2 ID:  {r2['receipt_id'][:32]}...")
    print(f"Chain intact:  {r2.get('prev_receipt_hash', '')[:32]}...")
    print(f"Verify r1:     {verify_receipt(r1)}")
    print(f"Verify r2:     {verify_receipt(r2)}")
    print()
    print("Full receipt 2:")
    print(json.dumps(r2, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "./SKILL.md"
    raise SystemExit(_demo(path))
