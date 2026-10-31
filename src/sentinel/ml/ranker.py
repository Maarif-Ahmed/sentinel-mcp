"""
sentinel.ml.ranker — MLRanker: scikit-learn backed RankerProvider.

The MLRanker wraps a trained sklearn Pipeline and plugs into the same
RankerProvider ABC as RuleBasedRanker. It is NOT the default — it must be
explicitly loaded by passing a model path to __init__.

Typical use:
    from sentinel.ml.ranker import MLRanker
    ranker = MLRanker.from_file("benchmarks/results/ml_model.pkl")
    assessment = ranker.rank(finding, context)

Training is done in benchmarks/evaluate.py, which also serialises the
fitted pipeline with joblib.

Model output is a probability score P(TP) in [0, 1]. The ranked_severity
bucket is derived from that score using the same thresholds as the rule-based
ranker so the two systems are comparable in the pipeline.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

from sentinel.ml.features import FEATURE_NAMES, extract
from sentinel.ranker import RankerProvider, _score_to_severity
from sentinel.schemas import ContextAnnotation, RiskAssessment, SecurityFinding


class MLRanker(RankerProvider):
    """
    Scikit-learn model wrapped as a RankerProvider.

    The model must expose a predict_proba method (Logistic Regression or
    Random Forest). The positive class (index 1) is treated as P(TP).
    """

    def __init__(self, model: Any, model_name: str = "ml") -> None:
        self._model = model
        self._model_name = model_name

    @classmethod
    def from_file(cls, path: str | Path) -> "MLRanker":
        import joblib
        path = Path(path)
        model = joblib.load(path)
        return cls(model, model_name=path.stem)

    def rank(
        self,
        finding: SecurityFinding,
        context: ContextAnnotation | None,
    ) -> RiskAssessment:
        feat = extract(finding, context)
        # predict_proba returns shape (1, n_classes); class order is [0, 1]
        prob_tp = float(self._model.predict_proba([feat])[0][1])

        ranked_severity = _score_to_severity(prob_tp)

        breakdown = {name: val for name, val in zip(FEATURE_NAMES, feat)}
        breakdown["prob_tp"] = prob_tp

        return RiskAssessment(
            finding_id=finding.id,
            ranked_severity=ranked_severity,
            ranker="ml",
            score=round(prob_tp, 4),
            feature_breakdown=breakdown,
            context_factors=[
                f"ML model ({self._model_name}): P(TP) = {prob_tp:.3f}",
                "Score is the probability this finding is a true positive.",
            ],
        )
