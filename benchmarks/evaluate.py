"""
benchmarks/evaluate.py — ML ranker experiment (Week 19–21).

Trains Logistic Regression and Random Forest on the Juice Shop annotated
ground truth and compares Precision@K across four ranker variants:

  1. severity-only      — rank by scanner severity score alone
  2. rule-based         — RuleBasedRanker score (weighted formula)
  3. logistic-regression— LR trained on extracted features, 5-fold CV
  4. random-forest      — RF trained on extracted features, 5-fold CV

Metrics reported:
  - Precision@K (K=3,5,10)
  - AUC-ROC
  - 5-fold cross-validation accuracy for ML models

Usage:
    python -m benchmarks.evaluate
    python -m benchmarks.evaluate --gt benchmarks/results/ground_truth.json
    python -m benchmarks.evaluate --gt ... --save-model benchmarks/results/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sentinel.ml.features import FEATURE_NAMES, extract
from sentinel.ranker import _CONFIDENCE_SCORE, _SEVERITY_SCORE

_DEFAULT_GT = Path(__file__).parent / "results" / "ground_truth.json"

# ──────────────────────────────────────────────────────────────────
# Ground truth loading
# ──────────────────────────────────────────────────────────────────


def load_ground_truth(path: Path) -> list[dict]:
    records = json.loads(path.read_text(encoding="utf-8"))
    # Keep only tp and fp; skip "skip" rows for binary classification
    return [r for r in records if r["consensus_label"] in ("tp", "fp")]


# ──────────────────────────────────────────────────────────────────
# Feature matrix assembly
# ──────────────────────────────────────────────────────────────────


def _gt_to_mock_objects(records: list[dict]):
    """
    Build lightweight mock SecurityFinding + ContextAnnotation objects from
    the ground truth JSON so we can reuse the feature extractor without
    running the full pipeline again.
    """
    from types import SimpleNamespace

    findings, contexts = [], []
    for r in records:
        f = SimpleNamespace(
            id=r["canonical_id"],
            canonical_id=r["canonical_id"],
            scanner=r["scanner"],
            rule_id=r["rule_id"],
            cwe_id=r.get("cwe_id") or None,
            severity=r["severity"],
            confidence="high",   # ground truth has no confidence column; assume high
            file_path=r["file_path"],
            line_start=int(r["line_start"]),
            message="",
        )
        route = r.get("route_path") or ""
        c = SimpleNamespace(
            route_path=route or None,
            http_methods=[],
            middleware_names=[],
        )
        findings.append(f)
        contexts.append(c)
    return findings, contexts


def build_feature_matrix(records: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    findings, contexts = _gt_to_mock_objects(records)
    X = np.array([extract(f, c) for f, c in zip(findings, contexts)], dtype=float)
    y = np.array([1 if r["consensus_label"] == "tp" else 0 for r in records])
    return X, y


# ──────────────────────────────────────────────────────────────────
# Severity-only scores (baseline 1)
# ──────────────────────────────────────────────────────────────────


def severity_only_scores(records: list[dict]) -> np.ndarray:
    scores = []
    for r in records:
        sev = _SEVERITY_SCORE.get(r["severity"], 0) / 4.0   # normalise 0–1
        scores.append(sev)
    return np.array(scores, dtype=float)


# ──────────────────────────────────────────────────────────────────
# Rule-based scores (baseline 2, already stored in ground truth)
# ──────────────────────────────────────────────────────────────────


def rule_based_scores(records: list[dict]) -> np.ndarray:
    return np.array([float(r["score"]) for r in records])


# ──────────────────────────────────────────────────────────────────
# Precision@K
# ──────────────────────────────────────────────────────────────────


def precision_at_k(scores: np.ndarray, labels: np.ndarray, k: int) -> float:
    """Rank by score descending; return fraction of top-K that are TP."""
    k = min(k, len(scores))
    top_k = np.argsort(scores)[::-1][:k]
    return float(np.sum(labels[top_k])) / k


# ──────────────────────────────────────────────────────────────────
# AUC-ROC (handles the near-degenerate case with few FPs)
# ──────────────────────────────────────────────────────────────────


def auc_roc(scores: np.ndarray, labels: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score
    if len(np.unique(labels)) < 2:
        return float("nan")
    return float(roc_auc_score(labels, scores))


# ──────────────────────────────────────────────────────────────────
# Train + CV for ML models
# ──────────────────────────────────────────────────────────────────


def train_lr(X: np.ndarray, y: np.ndarray):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",   # compensates for tp >> fp imbalance
            random_state=42,
        )),
    ])
    pipe.fit(X, y)
    return pipe


def train_rf(X: np.ndarray, y: np.ndarray):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline

    pipe = Pipeline([
        ("rf", RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])
    pipe.fit(X, y)
    return pipe


def cross_val_proba(
    model_factory,
    X: np.ndarray,
    y: np.ndarray,
    n_splits: int = 5,
) -> np.ndarray:
    """
    5-fold CV: for each fold fit on train, predict_proba on val.
    Returns out-of-fold P(TP) scores aligned with y.
    """
    from sklearn.model_selection import StratifiedKFold

    oof = np.zeros(len(y), dtype=float)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    for train_idx, val_idx in skf.split(X, y):
        m = model_factory(X[train_idx], y[train_idx])
        oof[val_idx] = m.predict_proba(X[val_idx])[:, 1]

    return oof


# ──────────────────────────────────────────────────────────────────
# Feature importance (RF only)
# ──────────────────────────────────────────────────────────────────


def print_feature_importance(rf_pipe, top_n: int = 8) -> None:
    rf = rf_pipe.named_steps["rf"]
    importances = rf.feature_importances_
    pairs = sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1])
    print(f"\n  {'Feature':<25} {'Importance':>10}")
    print(f"  {'-'*25}  {'-'*10}")
    for name, imp in pairs[:top_n]:
        bar = "█" * int(imp * 30)
        print(f"  {name:<25} {imp:>10.4f}  {bar}")


# ──────────────────────────────────────────────────────────────────
# Spearman rank correlation (RQ1 proxy)
# ──────────────────────────────────────────────────────────────────


def spearman_rho(scores_a: np.ndarray, scores_b: np.ndarray) -> float:
    from scipy.stats import spearmanr
    rho, _ = spearmanr(scores_a, scores_b)
    return float(rho)


# ──────────────────────────────────────────────────────────────────
# Main report
# ──────────────────────────────────────────────────────────────────


def report(
    gt_path: Path,
    save_dir: Path | None,
) -> None:
    records = load_ground_truth(gt_path)
    n = len(records)
    n_tp = sum(1 for r in records if r["consensus_label"] == "tp")
    n_fp = n - n_tp

    print(f"\n{'='*65}")
    print(f"  Sentinel ML Ranker Experiment — Week 19–21")
    print(f"{'='*65}")
    print(f"  Ground truth : {gt_path}")
    print(f"  Findings     : {n}  (TP={n_tp}, FP={n_fp})")
    print(f"  Features     : {len(FEATURE_NAMES)}")
    print(f"{'='*65}\n")

    X, y = build_feature_matrix(records)
    scores_sev = severity_only_scores(records)
    scores_rule = rule_based_scores(records)

    print("Training ML models (5-fold CV) …")
    oof_lr = cross_val_proba(train_lr, X, y)
    oof_rf = cross_val_proba(train_rf, X, y)
    print("Done.\n")

    # Train full-data models for final ranking + feature importance
    final_lr = train_lr(X, y)
    final_rf = train_rf(X, y)
    scores_lr_full = final_lr.predict_proba(X)[:, 1]
    scores_rf_full = final_rf.predict_proba(X)[:, 1]

    # ── Metrics table ──────────────────────────────────────────────
    K_VALUES = [3, 5, 10]
    rankers = [
        ("severity-only",  scores_sev),
        ("rule-based",     scores_rule),
        ("LR (oof-CV)",    oof_lr),
        ("RF (oof-CV)",    oof_rf),
    ]

    header = f"{'Ranker':<22}"
    for k in K_VALUES:
        header += f"  P@{k:>2}"
    header += f"  {'AUC-ROC':>8}"
    print(header)
    print("─" * len(header))

    for name, scores in rankers:
        row = f"{name:<22}"
        for k in K_VALUES:
            p = precision_at_k(scores, y, k)
            row += f"  {p:.3f}"
        auc = auc_roc(scores, y)
        row += f"  {auc:>8.4f}"
        print(row)

    # ── Spearman ρ: severity-only vs rule-based (RQ1) ──────────────
    rho = spearman_rho(scores_sev, scores_rule)
    print(f"\n  Spearman ρ (severity-only vs rule-based): {rho:.4f}")
    print(f"  (RQ1: rank correlation between the two ranker orderings)")

    # ── Feature importance ──────────────────────────────────────────
    print(f"\n  Random Forest — top feature importances (full-data model):")
    print_feature_importance(final_rf)

    # ── Summary ────────────────────────────────────────────────────
    p5_sev  = precision_at_k(scores_sev,   y, 5)
    p5_rule = precision_at_k(scores_rule,  y, 5)
    p5_lr   = precision_at_k(oof_lr,       y, 5)
    p5_rf   = precision_at_k(oof_rf,       y, 5)

    print(f"\n{'─'*65}")
    print("  Summary (Precision@5):")
    best = max(p5_sev, p5_rule, p5_lr, p5_rf)
    for name, score in [
        ("severity-only",  p5_sev),
        ("rule-based",     p5_rule),
        ("LR",             p5_lr),
        ("RF",             p5_rf),
    ]:
        marker = "  ← best" if score == best else ""
        print(f"    {name:<20} {score:.3f}{marker}")

    if p5_rf > p5_rule or p5_lr > p5_rule:
        winner = "RF" if p5_rf >= p5_lr else "LR"
        delta = max(p5_rf, p5_lr) - p5_rule
        print(f"\n  ML ({winner}) outperforms rule-based by {delta:+.3f} at P@5.")
    else:
        print(f"\n  Rule-based ranker matches or beats ML at P@5 — reporting")
        print(f"  that as an honest result (small dataset, high baseline precision).")

    # ── Persist models ─────────────────────────────────────────────
    if save_dir is not None:
        import joblib
        save_dir.mkdir(parents=True, exist_ok=True)
        lr_path = save_dir / "lr_model.pkl"
        rf_path = save_dir / "rf_model.pkl"
        joblib.dump(final_lr, lr_path)
        joblib.dump(final_rf, rf_path)
        print(f"\n  Models saved:")
        print(f"    LR → {lr_path}")
        print(f"    RF → {rf_path}")

    print(f"\n{'='*65}\n")


def main() -> None:
    p = argparse.ArgumentParser(description="ML ranker evaluation — Week 19–21")
    p.add_argument("--gt", default=str(_DEFAULT_GT),
                   help="Path to ground_truth.json")
    p.add_argument("--save-model", metavar="DIR", default=None,
                   help="Directory to save fitted LR and RF models (joblib)")
    args = p.parse_args()

    gt_path = Path(args.gt)
    if not gt_path.exists():
        print(f"[ERROR] ground truth not found: {gt_path}", file=sys.stderr)
        sys.exit(1)

    save_dir = Path(args.save_model) if args.save_model else None
    report(gt_path, save_dir)


if __name__ == "__main__":
    main()
