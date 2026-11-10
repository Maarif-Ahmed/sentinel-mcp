# Vulnerable benchmark targets

Static-analysis fixtures for the Sentinel evaluation harness. **These apps are
intentionally insecure and must never be deployed or run as a service.** They
are only ever read by scanners.

## flask-vulnerable

A Flask application used as the Python evaluation target. Bandit is a Python
SAST scanner, so a Python target is what lets scanner findings and the route
context graph meet on the same files — the JavaScript targets cannot do this,
because the only findings they produce come from dependency manifests, which
have no route.

The fixture is built to exercise the features the ranking experiment depends
on:

| Property | Why it is there |
|---|---|
| Unauthenticated routes in `app.py` | `exposure_score` has a high value to take |
| Decorated routes in `admin.py` | `has_auth_middleware` / `middleware_count` vary instead of being constant |
| Findings in `utils.py` | Reached only via an import edge, so transitive attribution is exercised |
| Benign-but-flagged patterns | The dataset needs real negatives; a target with only genuine bugs produces a base rate too high for Precision@K to mean anything |
| Pinned outdated dependencies | Trivy contributes dependency findings alongside Bandit's SAST findings |

Which findings are true or false positives is **not** recorded here. That is
decided independently by two annotators, and pre-labelling the fixture would
defeat the purpose of measuring inter-rater agreement.

## Regenerating the dataset

```bash
uv run python -m benchmarks.harness --repo "<abs path>/vulnerable-apps/flask-vulnerable" --out benchmarks/results/flask-vulnerable
```

That writes `scan_results.json` and an empty `annotation_template.csv`. Two
annotators fill in `annotator1_label` / `annotator2_label` (`tp` / `fp` /
`skip`), then:

```bash
uv run python -m benchmarks.annotate --csv benchmarks/results/flask-vulnerable/annotation_template.csv
```

Cohen's κ must reach 0.6 before `ground_truth.json` is written.
