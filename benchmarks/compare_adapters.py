"""
benchmarks/compare_adapters.py — base vs v2 vs v3 patch-generation comparison.

Loads Qwen2.5-Coder-3B-Instruct once in 4-bit and attaches both LoRA
adapters, switching between them rather than reloading the base. The base
model is measured through disable_adapter(), so all three conditions see
identical weights apart from the adapter.

Scoring mirrors ModelRouter._structural_score so the numbers map onto the
0.7 confidence threshold the router actually uses.

Two prompt shapes are tested:
  train  — the format in training_pairs_v3.jsonl, what v3 was fitted to
  prod   — the format PatchGenerator._build_patch_prompt emits at runtime

They differ, so the gap between them is the cost of that mismatch.

Usage:
    uv run python -m benchmarks.compare_adapters
    uv run python -m benchmarks.compare_adapters --shapes train
    uv run python -m benchmarks.compare_adapters --max-new 512
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

BASE_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"
ADAPTERS = {
    "v2": _ROOT / "models" / "sentinel-coder-v2",
    "v3": _ROOT / "models" / "sentinel-coder-v3",
}

_SYSTEM = """\
You are a security engineer generating minimal, targeted code patches.

Rules:
- Return ONLY a unified diff in standard format:
    --- a/filename
    +++ b/filename
    @@ -line,count +line,count @@
     context line
    -removed line
    +added line
- The line marked with ">>>" is the EXACT vulnerable line. Only modify that line.
- Do NOT include any explanation, markdown code fences, or prose.
- Make the smallest change that addresses the vulnerability.
- If you truly cannot produce a safe patch, output: # CANNOT_PATCH: <reason>
"""

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

CASES = [
    {
        "name": "sql-injection",
        "cwe": "CWE-89",
        "rule": "B608",
        "file": "app/views.py",
        "lang": "python",
        "desc": "User input concatenated into a SQL statement",
        "line": 12,
        "code": [
            "def search(request):",
            '    term = request.GET.get("q", "")',
            "    cursor = connection.cursor()",
            "    query = \"SELECT id, name FROM products WHERE name LIKE '%\" + term + \"%'\"",
            "    cursor.execute(query)",
            "    return cursor.fetchall()",
        ],
        "vuln_index": 3,
    },
    {
        "name": "command-injection",
        "cwe": "CWE-78",
        "rule": "B605",
        "file": "app/net.py",
        "lang": "python",
        "desc": "User input passed to a shell command",
        "line": 8,
        "code": [
            "import os",
            "",
            "def ping(request):",
            '    host = request.GET.get("host", "localhost")',
            '    os.system("ping -c 1 " + host)',
            '    return {"status": "sent"}',
        ],
        "vuln_index": 4,
    },
    {
        "name": "hardcoded-secret",
        "cwe": "CWE-798",
        "rule": "B105",
        "file": "app/config.py",
        "lang": "python",
        "desc": "Credential embedded in source code",
        "line": 4,
        "code": [
            "import os",
            "",
            "DEBUG = False",
            'SECRET_KEY = "s3cr3t-signing-key-do-not-ship"',
            'ALLOWED_HOSTS = ["example.com"]',
        ],
        "vuln_index": 3,
    },
    {
        "name": "unsafe-deserialization",
        "cwe": "CWE-502",
        "rule": "B301",
        "file": "app/restore.py",
        "lang": "python",
        "desc": "Untrusted data deserialized with pickle",
        "line": 6,
        "code": [
            "import pickle",
            "",
            "def restore(request):",
            '    blob = request.files["backup"].read()',
            "    state = pickle.loads(blob)",
            "    return state",
        ],
        "vuln_index": 4,
    },
    {
        "name": "weak-hash",
        "cwe": "CWE-327",
        "rule": "B324",
        "file": "app/auth.py",
        "lang": "python",
        "desc": "Password hashed with a broken algorithm",
        "line": 5,
        "code": [
            "import hashlib",
            "",
            "def hash_password(raw):",
            "    return hashlib.md5(raw.encode()).hexdigest()",
        ],
        "vuln_index": 3,
    },
]


def prompt_train(case: dict) -> str:
    """The shape used in training_pairs_v3.jsonl."""
    code = "\n".join(case["code"])
    return (
        f"CVE: n/a  CWE: {case['cwe']}\n"
        f"File: {case['file']}\n"
        f"Description: {case['desc']}\n\n\n"
        f"Vulnerable code (before fix):\n"
        f"```{case['lang']}\n{code}\n```\n\n"
        f"Generate the unified diff that applies the security fix.\n"
        f"The diff header must be:\n"
        f"--- a/{case['file']}"
    )


def prompt_prod(case: dict) -> str:
    """The shape PatchGenerator._build_patch_prompt emits."""
    numbered = []
    for i, line in enumerate(case["code"]):
        marker = ">>>" if i == case["vuln_index"] else "   "
        numbered.append(f"{i + 1:4d} {marker} {line}")
    block = "\n".join(numbered)
    return (
        f"Finding: {case['rule']}\n"
        f"File: {case['file']}  Line: {case['vuln_index'] + 1}\n"
        f"CWE: {case['cwe']}\n"
        f"Description: {case['desc']}\n"
        f"\nAffected code (>>> marks the vulnerable line):\n{block}\n"
        f"\nGenerate the unified diff.\n"
        f"The diff header must be:\n"
        f"--- a/{case['file']}\n"
        f"+++ b/{case['file']}"
    )


SHAPES = {"train": prompt_train, "prod": prompt_prod}

# ---------------------------------------------------------------------------
# Scoring — mirrors ModelRouter._structural_score
# ---------------------------------------------------------------------------

_DIFF_HEADER_RE = re.compile(r"^--- .+\n\+\+\+ .+", re.MULTILINE)
_HUNK_LINE_RE = re.compile(r"^@@ -(\d+)", re.MULTILINE)


def _hunk_lines_valid(diff: str) -> bool:
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        if line.startswith(("--- ", "+++ ")):
            continue
        if in_hunk and line and line[0] not in (" ", "-", "+", "\\"):
            return False
    return True


def score(diff: str, case: dict) -> tuple[float, dict]:
    """Return (0-1 structural score, per-check breakdown)."""
    cleaned = re.sub(r"```(?:diff|patch)?\n?", "", diff).strip()
    checks = {
        "header": bool(_DIFF_HEADER_RE.search(cleaned)),
        "hunk": bool(_HUNK_LINE_RE.search(cleaned)),
        "lines_valid": _hunk_lines_valid(cleaned),
        "covers_line": any(
            abs(int(m.group(1)) - (case["vuln_index"] + 1)) <= 5
            for m in _HUNK_LINE_RE.finditer(cleaned)
        ),
    }
    return sum(checks.values()) / len(checks), checks


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------


def _vram() -> str:
    import torch
    if not torch.cuda.is_available():
        return "cpu"
    used = torch.cuda.memory_allocated() / 1e9
    total = torch.cuda.get_device_properties(0).total_memory / 1e9
    return f"{used:.2f}/{total:.1f} GB"


def load_for(condition: str):
    """Load the base model with at most one adapter attached.

    Holding both adapters plus the quantised base at once killed the process
    on a 6 GB card without raising, so each condition gets its own load and
    the previous one is freed first.
    """
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, quantization_config=bnb, device_map="auto",
        trust_remote_code=True, dtype=torch.float16,
    )
    print(f"    base loaded, VRAM {_vram()}", flush=True)

    if condition != "base":
        from peft import PeftModel
        path = ADAPTERS[condition]
        model = PeftModel.from_pretrained(model, str(path), adapter_name=condition)
        model.eval()
        print(f"    adapter {condition} attached, VRAM {_vram()}", flush=True)

    return model, tokenizer


def free(model) -> None:
    import gc
    import torch
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def generate(model, tokenizer, system: str, user: str, max_new: int) -> str:
    import torch

    text = tokenizer.apply_chat_template(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        tokenize=False, add_generation_prompt=True,
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs, max_new_tokens=max_new, do_sample=False,
            temperature=None, top_p=None, top_k=None,
            pad_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(out[0][inputs["input_ids"].shape[1]:],
                            skip_special_tokens=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(description="Compare base / v2 / v3 adapters")
    p.add_argument("--shapes", nargs="+", default=["train", "prod"], choices=list(SHAPES))
    p.add_argument("--conditions", nargs="+", default=["base", "v2", "v3"])
    p.add_argument("--max-new", type=int, default=400)
    p.add_argument("--limit", type=int, default=None, help="Only the first N cases")
    p.add_argument("--save", default=None, help="Write raw outputs to this JSON file")
    args = p.parse_args()

    cases = CASES[: args.limit] if args.limit else CASES
    results: dict = {}
    raw: list[dict] = []

    # Outer loop is the condition, so each model is loaded and freed once
    # rather than held alongside the others.
    for cond in args.conditions:
        if cond != "base" and not (ADAPTERS[cond] / "adapter_config.json").exists():
            print(f"[skip] {cond}: no adapter on disk", flush=True)
            continue
        print(f"\n--- loading condition: {cond}", flush=True)
        model, tokenizer = load_for(cond)

        for shape in args.shapes:
            build = SHAPES[shape]
            scores = []
            t0 = time.time()
            for case in cases:
                try:
                    out = generate(model, tokenizer, _SYSTEM, build(case), args.max_new)
                except Exception as e:
                    out = f"# GENERATION FAILED: {type(e).__name__}: {e}"
                s, checks = score(out, case)
                scores.append(s)
                raw.append({"shape": shape, "condition": cond, "case": case["name"],
                            "score": s, "checks": checks, "output": out})
                print(f"    [{shape}] {case['name']:<24} {s:.2f}", flush=True)
            elapsed = time.time() - t0
            mean = sum(scores) / len(scores)
            passed = sum(1 for s in scores if s >= 0.7)
            results[(shape, cond)] = (mean, passed, elapsed)
            print(f"  {cond} / {shape}: mean={mean:.3f}  >=0.7: {passed}/{len(cases)}"
                  f"  ({elapsed:.0f}s)", flush=True)

        free(model)

    print(f"\n{'=' * 70}")
    print(f"  {'shape':<8} {'model':<6} {'mean structural':>16} {'clears 0.7':>12}")
    print(f"  {'-' * 50}")
    for (shape, cond), (mean, passed, _) in sorted(results.items()):
        print(f"  {shape:<8} {cond:<6} {mean:>16.3f} {f'{passed}/{len(cases)}':>12}")

    if args.save:
        import json
        Path(args.save).write_text(json.dumps(raw, indent=2), encoding="utf-8")
        print(f"\n  raw outputs → {args.save}")


if __name__ == "__main__":
    main()
