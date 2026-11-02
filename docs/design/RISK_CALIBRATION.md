# How the risk score behaves on labelled data

Reproduce with `python -m experiments.risk_calibration`. Results are written to
`out/risk_calibration/results.json`.

## What this measures, and its limits

The experiment runs the Mode B scorer over all 1,152 labelled update pairs: 1,000 synthetic, plus 150
real captures and 2 fixtures in `data/dataset`. Classifier inputs are out-of-fold, grouped by extension,
so no pair is scored by a model that saw that extension.

Read these results with three limits in mind:

1. **"Malicious" means synthetic weaponisation.** No real-world malicious update pair is included,
   because none is publicly available (see `docs/PROJECT_REPORT.md`). These numbers do not validate
   the system against real malicious extensions.
2. **The strongest evidence is absent.** These traces predate the Docker pipeline, so they have no
   wire record or markers, and the direct-exfiltration indicators cannot fire. Timing-based candidates
   stand in for them, so scores here understate what a Docker run would produce for the same behaviour.
3. **The score bands were not fitted.** The weights are expert priors, and the bands are the initial
   ones requested for the project. This section records how they perform. It does not make them
   probabilities.

## Results

All numbers are on the full labelled set, unless marked as real captures.

| Score threshold | Rules: recall | Rules: FPR | Combined: recall | Combined: FPR |
|---|---:|---:|---:|---:|
| 20 or more | 83.8% | 10.7% | 95.4% | 12.5% |
| 40 or more | 63.1% | 5.5% | **91.9%** | **6.5%** |
| 60 or more | 48.5% | 0.2% | 48.5% | 0.2% |
| 80 or more | 22.4% | 0.0% | 22.4% | 0.0% |

| Measure | Rules | Combined | Classifier alone |
|---|---:|---:|---:|
| ROC-AUC | 0.928 | 0.963 | 0.983 |
| PR-AUC | 0.914 | 0.951 | 0.984 |

**Real captures only** (99 weaponised, 51 benign, score 40 or more): rules recall 94.9% at 3.9% FPR,
combined recall 97.9% at 7.8% FPR. That FPR is 4 benign updates of 51, and the sample is small.

### What each band contains (combined score)

| Band | Benign | Malicious | Share malicious |
|---|---:|---:|---:|
| 0-19 Low | 555 | 24 | 4.1% |
| 20-39 Mild | 38 | 18 | 32.1% |
| 40-59 Moderate | 40 | 225 | 84.9% |
| 60-79 High | 1 | 135 | 99.3% |
| 80-100 Critical | 0 | 116 | 100% |

The bands are ordered as intended on this data. The top two bands were almost entirely malicious.
The share in a band reflects this dataset's roughly 45% malicious mix. Real extension updates are far
less often malicious, so the same score would carry a lower real-world likelihood. **These shares are
not probabilities of malice for a new extension.**

### Recall at a score of 40 or more, by synthetic family

| Family | Rules | Combined | Reading |
|---|---:|---:|---|
| form_jacking | 100% | 100% | Clear behavioural signal |
| credential_theft | 99% | 99% | Clear behavioural signal |
| history_exfil | 95% | 100% | Clear behavioural signal |
| cookie_theft | 96% | 99% | Clear behavioural signal |
| redirect_hijack | 62% | 100% | The classifier adds a lot |
| sw_beacon | 15% | 100% | The classifier adds a lot |
| keylogger | 10% | 94% | The classifier adds a lot |
| ad_affiliate | 7% | 58% | **Weak** |
| clipboard_steal | 13% | 50% | **Weak** |

The weak families have no credential or cookie access in their traces, so the explainable rules see
only mild signals, and detection depends on the model. A family with a high combined figure and
a low rule figure has been flagged largely by the classifier, whose score is capped below "High" and
is labelled in the report as a model-only flag.

## Changes made because of this evaluation

Both were errors the evaluation exposed. Neither involved tuning numbers to the test data:

1. **The lexical domain-reputation signal was too strong.** At weight 0.45 it flagged 144 benign
   synthetic updates in the moderate band. The docstring on `domain_low_reputation` already warns that
   this should be a weak signal, not a rule. It is now 0.15.
2. **Beacon detection accepted bursts.** Three requests 0.2 s apart counted as beaconing. It now
   requires an interval of at least one second.

The combination's values were not adjusted after seeing results, and the remaining weights are the
original priors. If they are tuned in future, this should be done on separate data, with the current
results kept as a baseline, because the current evaluation has already been used for the two
corrections above.

## Combination method

The rule score and classifier probability are never averaged, as they are different quantities.
`engine/scoring/combined.py` applies a decision table, with thresholds in `config/risk_scoring.toml`:

| Situation | Result |
|---|---|
| A synthetic secret was seen leaving the browser | Rule score stands. The model cannot lower it |
| Rules quiet, model probability of 0.5 or more | Raised to 40, capped at 59, labelled a model-only flag |
| Rules 40-79 on indirect evidence, model probability of 0.1 or less | Lowered by 15, to no less than 20 |
| Anything else, or no model available | Rule score stands |

The rule score is always reported separately, so any adjustment can be seen and undone.
The Random Forest's output is the fraction of trees voting malicious and is **not calibrated**.
The report says so, and it is suited to ranking rather than to reading as a likelihood.

## Model domain

The classifier was trained on the existing dataset: synthetic pairs, real benign Firefox updates and
real extensions with injected payloads, all using a narrower instrumentation. To keep its input
meaningful, the pipeline gives it a per-scenario delta built only from the event kinds it was trained
on. Docker Chromium runs still differ from its training data, and this has not been separately
evaluated beyond the controlled extensions.
