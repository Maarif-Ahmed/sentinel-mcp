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
_DEFAULT_SCAN = Path(__file__).parent / "results" / "scan_results.json"


class InsufficientDataError(RuntimeError):
    """Raised when the ground truth cannot support the requested statistic."""

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


def load_scan_index(path: Path) -> dict[str, dict]:
    """Index the pipeline's own scan output by canonical_id.

    The ground truth CSV carries only the annotation columns. Confidence and
    middleware live in the scan output, and inventing them here (confidence
    always 'high', middleware always empty) left four of the thirteen
    features constant at training time — including the route-context
    features the experiment exists to test.
    """
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("findings", payload) if isinstance(payload, dict) else payload
    index: dict[str, dict] = {}
    for row in rows:
        finding = row.get("finding", {})
        cid = finding.get("canonical_id")
        if cid:
            index[cid] = row
    return index


def _gt_to_mock_objects(records: list[dict], scan_index: dict[str, dict] | None = None):
    """
    Build SecurityFinding + ContextAnnotation objects for the feature
    extractor, preferring the real pipeline output over the annotation CSV.
    """
    from types import SimpleNamespace

    scan_index = scan_index or {}
    findings, contexts = [], []

    for r in records:
        scanned = scan_index.get(r["canonical_id"], {})
        sf = scanned.get("finding", {})
        sc = scanned.get("context", {})

        f = SimpleNamespace(
            id=r["canonical_id"],
            canonical_id=r["canonical_id"],
            scanner=sf.get("scanner", r["scanner"]),
            rule_id=sf.get("rule_id", r["rule_id"]),
            cwe_id=sf.get("cwe_id") or r.get("cwe_id") or None,
            severity=sf.get("severity", r["severity"]),
            confidence=sf.get("confidence", "medium"),
            file_path=sf.get("file_path", r["file_path"]),
            line_start=int(sf.get("line_start", r["line_start"])),
            message=sf.get("message", ""),
            is_dev_dependency=bool(
                sf.get("is_dev_dependency", r.get("is_dev_dependency", False))
            ),
            corroborated_by=sf.get("corroborated_by", []),
        )
        route = sc.get("route_path") or r.get("route_path") or None
        c = SimpleNamespace(
            route_path=route,
            http_methods=sc.get("http_methods", []),
            middleware_names=sc.get("middleware_names", []),
        )
        findings.append(f)
        contexts.append(c)
    return findings, contexts


def build_feature_matrix(
    records: list[dict], scan_index: dict[str, dict] | None = None
) -> tuple[np.ndarray, np.ndarray]:
    findings, contexts = _gt_to_mock_objects(records, scan_index)
    X = np.array([extract(f, c) for f, c in zip(findings, contexts)], dtype=float)
    y = np.array([1 if r["consensus_label"] == "tp" else 0 for r in records])
    return X, y


def report_dead_features(X: np.ndarray) -> list[str]:
    """Name the features with zero variance — they cannot inform any model."""
    return [
        name for name, col in zip(FEATURE_NAMES, X.T)
        if float(np.std(col)) == 0.0
    ]


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


def rule_based_scores_computed(
    records: list[dict],
    scan_index: dict[str, dict] | None,
    with_context: bool,
) -> np.ndarray:
    """Re-run RuleBasedRanker, optionally withholding the context annotation.

    This is the RQ1 ablation. Correlating severity-only against rule-based
    answers nothing, because the rule-based score already contains severity
    as its dominant term, so a high correlation is guaranteed by
    construction. The question is whether route context changes the ordering,
    which only an on/off comparison of that one input can answer.
    """
    from sentinel.ranker import RuleBasedRanker

    findings, contexts = _gt_to_mock_objects(records, scan_index)
    ranker = RuleBasedRanker()
    return np.array([
        ranker.rank(f, c if with_context else None).score
        for f, c in zip(findings, contexts)
    ])


# ──────────────────────────────────────────────────────────────────
# Precision@K
# ──────────────────────────────────────────────────────────────────


def precision_at_k(
    scores: np.ndarray,
    labels: np.ndarray,
    k: int,
    tiebreak: list[str] | None = None,
) -> float:
    """Rank by score descending; return fraction of top-K that are TP.

    Ties are broken by canonical_id rather than array position. The feature
    set is mostly small integers, so tied scores are common and plain argsort
    would make Precision@K depend on the order of the ground-truth file.
    """
    k = min(k, len(scores))
    if k == 0:
        return float("nan")
    keys = tiebreak if tiebreak is not None else [str(i) for i in range(len(scores))]
    order = sorted(range(len(scores)), key=lambda i: (-float(scores[i]), keys[i]))
    top_k = order[:k]
    return float(np.sum(labels[top_k])) / k


def boundary_ties(scores: np.ndarray, k: int) -> int:
    """How many items share the score at the K-th position.

    Reported alongside Precision@K so a result that rests on an arbitrary
    tie-break is visible rather than implied to be a real separation.
    """
    k = min(k, len(scores))
    if k == 0:
        return 0
    cutoff = sorted(scores, reverse=True)[k - 1]
    return int(np.sum(scores == cutoff))


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

    minority = int(min(np.sum(y == 0), np.sum(y == 1)))
    if minority < 2:
        raise InsufficientDataError(
            f"only {minority} sample(s) in the minority class — "
            "cross-validation is not defined"
        )

    # StratifiedKFold needs at least one minority sample per fold.
    effective_splits = min(n_splits, minority)
    if effective_splits < n_splits:
        print(
            f"  [warn] minority class has {minority} samples; "
            f"reducing folds {n_splits} → {effective_splits}"
        )

    oof = np.zeros(len(y), dtype=float)
    skf = StratifiedKFold(n_splits=effective_splits, shuffle=True, random_state=42)

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
    scan_path: Path | None = None,
) -> None:
    records = load_ground_truth(gt_path)
    n = len(records)
    n_tp = sum(1 for r in records if r["consensus_label"] == "tp")
    n_fp = n - n_tp
    base_rate = n_tp / n if n else float("nan")

    scan_index = load_scan_index(scan_path or _DEFAULT_SCAN)
    ids = [r["canonical_id"] for r in records]

    print(f"\n{'='*65}")
    print(f"  Sentinel ML Ranker Experiment — Week 19–21")
    print(f"{'='*65}")
    print(f"  Ground truth : {gt_path}")
    print(f"  Scan context : {len(scan_index)} findings joined by canonical_id")
    print(f"  Findings     : {n}  (TP={n_tp}, FP={n_fp})")
    print(f"  Features     : {len(FEATURE_NAMES)}")
    print(f"{'='*65}\n")

    X, y = build_feature_matrix(records, scan_index)

    # ── Dataset validity checks ────────────────────────────────────
    # These bound what any downstream number can mean, so they are printed
    # before the metrics rather than discovered afterwards.
    print("Dataset validity")
    print("─" * 65)
    print(f"  Majority-class base rate     : {base_rate:.3f}")
    if base_rate >= 0.9 or n_fp < 5:
        print(f"  [WARN] With {n_fp} negative(s), Precision@K has almost no")
        print(f"         headroom above the {base_rate:.0%} base rate and AUC is")
        print(f"         determined by a handful of points. Treat the ranker")
        print(f"         comparison below as indicative only, not as evidence.")

    dead = report_dead_features(X)
    if dead:
        print(f"  [WARN] Zero-variance features ({len(dead)}/{len(FEATURE_NAMES)}):")
        print(f"         {', '.join(dead)}")
        print(f"         These cannot contribute to any model.")

    n_routed = int(np.sum(X[:, FEATURE_NAMES.index("has_route")] > 0))
    print(f"  Findings with route context  : {n_routed}/{n}")
    if n_routed < 5:
        print(f"  [WARN] Route context is present on {n_routed} finding(s), so the")
        print(f"         context contribution cannot be measured on this dataset.")
    print()

    scores_sev = severity_only_scores(records)
    scores_rule = rule_based_scores_computed(records, scan_index, with_context=True)
    scores_noctx = rule_based_scores_computed(records, scan_index, with_context=False)

    rankers = [
        ("severity-only",     scores_sev),
        ("rule-based (ctx)",  scores_rule),
        ("rule-based (no ctx)", scores_noctx),
    ]

    print("Training ML models (cross-validated) …")
    try:
        oof_lr = cross_val_proba(train_lr, X, y)
        oof_rf = cross_val_proba(train_rf, X, y)
        rankers += [("LR (oof-CV)", oof_lr), ("RF (oof-CV)", oof_rf)]
        ml_ok = True
    except InsufficientDataError as e:
        print(f"  [SKIP] {e}")
        print(f"         RQ3 cannot be answered with this ground truth.")
        oof_lr = oof_rf = None
        ml_ok = False
    print("Done.\n")

    final_lr = train_lr(X, y) if ml_ok else None
    final_rf = train_rf(X, y) if ml_ok else None

    # ── Metrics table ──────────────────────────────────────────────
    K_VALUES = [3, 5, 10]
    header = f"{'Ranker':<22}"
    for k in K_VALUES:
        header += f"  P@{k:>2}"
    header += f"  {'AUC-ROC':>8}"
    print(header)
    print("─" * len(header))

    for name, scores in rankers:
        row = f"{name:<22}"
        for k in K_VALUES:
            p = precision_at_k(scores, y, k, tiebreak=ids)
            row += f"  {p:.3f}"
        auc = auc_roc(scores, y)
        row += f"  {auc:>8.4f}"
        print(row)

    ties5 = boundary_ties(scores_rule, 5)
    if ties5 > 1:
        print(f"\n  Note: {ties5} findings share the rule-based score at rank 5;")
        print(f"        that boundary is resolved by canonical_id, not by the ranker.")

    # ── RQ1: does route context change the ordering? ───────────────
    rho_ablation = spearman_rho(scores_rule, scores_noctx)
    print(f"\n  RQ1 — context ablation")
    print(f"  {'─'*40}")
    print(f"  Spearman ρ (rule-based with vs without context): {rho_ablation:.4f}")
    if np.allclose(scores_rule, scores_noctx):
        print(f"  Orderings are identical — context changed nothing on this data.")
    print(f"  ρ = 1.0 means context did not reorder any finding.")
    print(f"  (Reference only — severity-only vs rule-based: "
          f"{spearman_rho(scores_sev, scores_rule):.4f}; that pair shares the")
    print(f"   severity term, so its correlation is high by construction.)")

    # ── Feature importance ──────────────────────────────────────────
    if final_rf is not None:
        print(f"\n  Random Forest — top feature importances (full-data model):")
        print_feature_importance(final_rf)

    # ── Summary ────────────────────────────────────────────────────
    print(f"\n{'─'*65}")
    print("  Summary (Precision@5):")
    summary = [(name, precision_at_k(s, y, 5, tiebreak=ids)) for name, s in rankers]
    best = max(score for _, score in summary)
    for name, score in summary:
        marker = "  ← best" if score == best else ""
        print(f"    {name:<22} {score:.3f}{marker}")

    if not ml_ok:
        print(f"\n  ML comparison skipped — see the dataset warnings above.")

    # ── Persist models ─────────────────────────────────────────────
    if save_dir is not None and ml_ok:
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
    p.add_argument("--scan", default=str(_DEFAULT_SCAN),
                   help="Path to scan_results.json (supplies confidence + context)")
    args = p.parse_args()

    gt_path = Path(args.gt)
    if not gt_path.exists():
        print(f"[ERROR] ground truth not found: {gt_path}", file=sys.stderr)
        sys.exit(1)

    save_dir = Path(args.save_model) if args.save_model else None
    report(gt_path, save_dir, Path(args.scan))


if __name__ == "__main__":
    main()
