# Example reports

Real output from `python -m engine.cli compare` with the full scenario suite on Chromium, using the
controlled test extensions in `data/corpus/controlled/`. All sensitive values were synthetic. Nothing
here was edited, apart from removing a local output directory prefix from each `report.json`.

| Directory | Compared | Result |
|---|---|---|
| [malicious_update/](malicious_update/report.md) | `pair_v1` to `pair_v2` | Critical, 99/100 |
| [benign_update/](benign_update/report.md) | `pair_v1` to `pair_v1_1_benign` | No significant suspicious behaviour, 2/100 |
