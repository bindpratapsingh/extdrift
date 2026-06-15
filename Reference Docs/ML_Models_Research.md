# Model Research & Selection — Which ML Model Should `extdrift` Use?

**Audience:** Bind & Suhani. Written assuming **little machine-learning background**. Every
acronym is spelled out, every model is explained in plain language with an analogy, and every
claim about "what the field uses" is tied to a real paper. Read it once top-to-bottom; then use
the tables and the glossary as a reference.

**Why this file exists:** In the advisor meeting, Dr. Mishra said two things that drive this
whole document:
1. *"Consider a more state-of-the-art model than Random Forest."*
2. *"Implement the existing state of the art first, reproduce that result, then compare and
   show improvement."* (Plus: get the heuristics, understand the malicious approach, and
   justify *why ML is needed at all*.)

This file answers: **Is Random Forest good enough? What is the actual state of the art for our
topic? What do industry and research use? And what should *we* do?**

---

## 0. The 30-second answer

- Random Forest is **not wrong** — for the way we currently shape our data (a flat list of
  numbers), tree-based models like Random Forest and XGBoost are genuinely **near the top**.
- BUT the *frontier* of the field is not "a fancier classifier on the same numbers." It is
  **changing how we represent the behavior** — from a flat list of numbers into a **sequence**
  (order of events) or a **graph** (how events connect) — and then using **deep-learning**
  models built for those shapes.
- **Recommendation:** keep Random Forest + add **XGBoost** as the explainable, reproducible
  **baseline**, and add a **sequence model (Transformer/LSTM)** or **graph model (GNN)** as the
  "state-of-the-art improvement" — which is *also* where our publishable novelty lives.

The rest of this file explains *why*, in detail, from first principles.

---

## 1. The absolute basics (skip if you know them)

**Machine Learning (ML)** — instead of a human writing rules ("if it reads cookies AND posts to
a new domain, flag it"), we show a program many labelled examples ("here are 500 malicious
updates and 500 benign ones") and it *learns the rule itself*. The learned program is called a
**model**.

**Classifier** — a model whose job is to put an input into a category. Ours is **binary**:
`benign update` vs `malicious update`.

**Feature** — one measurable input number describing an example. For us, e.g.
`number_of_new_domains = 3`, `reads_cookies = 1`, `posts_form_data = 1`. A list of features for
one example is a **feature vector**.

**Training / Test** — we *fit* (train) the model on one set of examples, then measure it on a
**separate** set it has never seen (test). Measuring on data it trained on is cheating — it
would just memorise.

**Overfitting** — when a model **memorises** the training examples instead of learning the
general pattern, so it looks great in the lab and fails in the real world. The enemy.

**The three "shapes" of data** (this is the single most important idea in this whole file):

| Shape | What it looks like | Everyday example | Best model family |
|---|---|---|---|
| **Tabular** | rows & columns of numbers (a spreadsheet) | a bank's customer table | **Tree ensembles** (Random Forest, XGBoost) |
| **Sequence** | an *ordered* list where order matters | a sentence; a list of actions over time | **LSTM / Transformer** |
| **Graph** | things (nodes) connected by relationships (edges) | a social network; a data-flow diagram | **Graph Neural Network (GNN)** |

Our `Δ = f(T₂) − f(T₁)` is currently **tabular**. That single fact is why Random Forest is a
reasonable choice — and also why, to do something more "state of the art," we'd change the shape.

---

## 2. Family A — Classic / "tabular" models (where Random Forest lives)

These are the workhorses of practical ML. They work on the spreadsheet shape.

### 2.1 Decision Tree
A flowchart of yes/no questions learned from data:
`Does it post to a new domain? → yes → Does it read cookies? → yes → MALICIOUS`.
- **Pro:** dead simple, totally explainable.
- **Con:** a single tree is unstable and overfits easily.

### 2.2 Random Forest (RF)
**Full form:** Random *Forest* = a **forest of many decision trees**.
**How it works:** it builds hundreds of decision trees, each trained on a **random** subset of
the data and a **random** subset of the features, then they **vote**. The majority vote is the
answer. The randomness is what stops it overfitting.
- The underlying trick is called **Bagging** (= **B**ootstrap **Agg**regat**ing**): train many
  models on random samples and average them to reduce error.
- **Analogy:** instead of asking one slightly-biased expert, you ask 500 experts who each saw a
  different slice of the evidence, and take the majority vote.
- **Why it's good for us:** works on **small data**, robust, hard to misuse, and it can tell you
  **which features mattered most** (feature importance) — great for explainability.
- **Why the professor pushed back:** it's a 2001 algorithm. It's reliable but "safe/old," and on
  tabular data it is usually **beaten slightly by gradient boosting** (next).

### 2.3 XGBoost / LightGBM / CatBoost (Gradient-Boosted Trees)
**Full forms:** **XGBoost** = e**X**treme **G**radient **Boost**ing. **LightGBM** = **Light**
**G**radient **B**oosting **M**achine (by Microsoft). **CatBoost** = **Cat**egorical **Boost**ing
(by Yandex).
**How it works:** instead of training trees independently and voting (bagging), it trains trees
**one after another**, where **each new tree focuses on fixing the mistakes of the trees so far**.
This sequential error-correction is called **Boosting**.
- **Analogy:** a student takes a practice test, sees what they got wrong, studies *exactly those*
  topics, retests, repeats. Each round targets the remaining weaknesses.
- **Why it matters for us:** on **tabular data, gradient-boosted trees are the de-facto state of
  the art** — they win the majority of Kaggle competitions on spreadsheet data and consistently
  edge out Random Forest. Swapping/adding XGBoost is a **tiny code change** and immediately lets
  us say *"we used the tabular state-of-the-art, not just Random Forest."*

### 2.4 Support Vector Machine (SVM)
**Full form:** **S**upport **V**ector **M**achine.
**How it works:** draws the **best dividing line** (in high dimensions, a "hyperplane") between
the two classes, maximising the gap (**margin**) between them. A "**kernel**" trick lets it draw
curved boundaries.
- **Pro:** strong on small/medium, high-dimensional data. **Con:** less explainable, slower to
  tune, less popular now than boosting. A reasonable *secondary* baseline.

### 2.5 Logistic Regression
The simplest possible classifier: a weighted sum of the features squashed into a probability.
- **Use:** as the **floor baseline** ("can a dead-simple model already do this?"). If your fancy
  model can't beat logistic regression, something is wrong.

### Why deep learning usually LOSES on tabular data
This is counter-intuitive, so it's worth stating plainly. A landmark study —
**Grinsztajn et al., "Why do tree-based models still outperform deep learning on tabular data?"
(NeurIPS 2022)** — showed that on spreadsheet-shaped data, **tree ensembles beat neural
networks**, especially when data is limited. Reasons: tabular features are unrelated to each
other (no "nearby pixels" or "next word" structure for a neural net to exploit), and neural nets
are data-hungry. **So if we keep the flat feature-vector representation, switching to deep
learning would likely make results *worse*, not better.** This is the key nuance behind "is RF
good enough?": *for that representation, yes.*

---

## 3. Family B — Deep learning for SEQUENCES (the real "state of the art")

A **Neural Network** is a stack of layers of simple math units ("neurons") that learn to
transform raw input into an answer. **Deep learning** just means a neural network with many
layers. These shine when the data has **structure** — like *order*.

Our behavior is naturally a **sequence**: the extension did action 1, then 2, then 3
(`read cookie → open socket → POST data`). A flat count vector throws the *order* away. Sequence
models keep it — and order is often where the maliciousness hides.

### 3.1 RNN → LSTM → BiLSTM
- **RNN** = **R**ecurrent **N**eural **N**etwork: reads a sequence one step at a time, carrying a
  little "memory" forward. **Problem:** it forgets long-range context (the "vanishing gradient").
- **LSTM** = **L**ong **S**hort-**T**erm **M**emory: an upgraded RNN with internal **gates** that
  decide what to remember and what to forget, so it handles **long** sequences. **Analogy:** a
  reader with a notepad who jots down only the important earlier facts and crosses out the rest.
- **BiLSTM** = **Bi**directional LSTM: reads the sequence **both forward and backward**, so each
  event is understood using both past and future context.

### 3.2 Transformer & BERT (the technology behind ChatGPT, applied to malware)
- **Transformer** — the architecture that replaced LSTMs as state-of-the-art. Its core trick is
  **self-attention**: every event in the sequence can directly "look at" every other event and
  decide how relevant it is, all at once (in parallel). **Analogy:** instead of reading a story
  word by word, you see the whole page and instantly connect "the *cookie* it read on line 2" to
  "the *POST* on line 40."
- **Attention** — the mechanism that scores "how much should A pay attention to B?" It's *the*
  idea that made modern AI work.
- **BERT** = **B**idirectional **E**ncoder **R**epresentations from **T**ransformers. A
  Transformer **pre-trained** on huge amounts of data, then **fine-tuned** for your task. In
  malware research, people treat a program's **API-call sequence like a sentence** and feed it to
  BERT — the model learns which "phrases" of behavior are malicious.

**How research uses these (real papers):**
- **Ransomware Detection via LSTM and BERT on API-call sequences** (The Computer Journal, 2024).
- **BERT-Transformer-TextCNN** for Advanced Persistent Threat malware (ACM, 2024).
- **CAFTrans**, a Transformer model for malware identification robust to obfuscation (2024).
- **BEACON** (2025) — uses **L**arge **L**anguage **M**odel (LLM) embeddings + deep learning to
  classify malware *behavior*.

---

## 4. Family C — Graph Neural Networks (arguably the best fit for "exfiltration")

A **graph** is nodes connected by edges. Malicious behavior is often best described as a graph:
`[reads document.cookie] --feeds--> [variable x] --sent in--> [POST to evil.com]`. That
**cookie-read → network-send** connection is a **data-flow / taint** path, and it is *exactly*
what data theft looks like. A flat count vector can't see the connection; a graph model can.

- **GNN** = **G**raph **N**eural **N**etwork: a neural network that operates on graphs by
  **message passing** — each node repeatedly mixes in information from its neighbours, so the
  model learns from *structure*, not just isolated facts. **Analogy:** rumour spreading — each
  person updates their belief based on their neighbours, and after a few rounds the whole network
  "understands" itself.
- **GCN** = **G**raph **C**onvolutional **N**etwork: the most common GNN; each node averages its
  neighbours' features.
- **GAT** = **G**raph **A**ttention **Net**work: a GNN that learns *how much* to weight each
  neighbour (attention, applied to graphs).

**How research uses these (real papers):**
- **GraphShield** (2025) — dynamic **graph-based** malware detection using GNNs.
- **GCN** behavioral malware detectors reporting ~98% accuracy, on par with LSTMs.
- **GIT-GuardNet** — a "Graph-Informed Transformer" that fuses **static features + dynamic
  behavior traces + graph structure** (combines all three families).

---

## 5. So what does *our exact topic* — browser-extension detection — actually use?

This is the honest, specific picture for **browser extensions** (not malware in general):

| Paper / work | Model(s) used | Features | Headline result | Lesson for us |
|---|---|---|---|---|
| **ExtPrivA** — Bui, Tang, Shin (IEEE S&P 2023) — *our base paper* | Rule/flow analysis (network-request initiators); not a deep classifier | **Dynamic** — emulates user interaction, watches outbound requests | 85% precision finding privacy-practice inconsistencies | Our method is its update-aware extension; reuse its "emulate + watch network" idea |
| Wang et al. (combining ML + feature engineering, Springer 2023) | Classic ML (tree/ensemble) | **Static + dynamic** (JS/HTML/CSS) | >95% accuracy | Engineered features + classic ML already gets high *lab* numbers |
| **"It's not Easy"** (arXiv 2509.21590, **2025**) | **3 supervised classifiers** (classic ML) | Static/metadata | **98% in lab**, but flagged >1,000 in the wild and **only 68 were real** | ⚠️ The hard part is **NOT the model** — it's false positives + concept drift in the real world |
| Concept-drift study (TWeb 2025, Rosenzweig) | Supervised ML | Extension features over time | Performance **decays over time** | Models trained on old data go stale — applies to us too |

**Two blunt takeaways from our own field:**
1. **Published extension detectors still mostly use classic tabular ML** (Random Forest / XGBoost
   / SVM). So Random Forest is *normal* here, not embarrassing.
2. **The bottleneck in the real world is data quality and false positives, not the classifier.**
   The 2025 paper proves a 98%-accurate model can be useless in production. **Our record/replay
   determinism is aimed straight at that bottleneck — which is why it, not the model, is our
   strongest contribution.**

---

## 6. What *industry* uses (briefly, and why it differs)

Antivirus / Endpoint-Detection-and-Response vendors and app-store scanners (think Microsoft
Defender, CrowdStrike, Google Play Protect / Chrome Web Store review) typically run **layered**
systems:
- **Gradient-boosted trees** (XGBoost-style) on engineered telemetry for the fast, cheap,
  explainable first pass.
- **Deep learning** (CNNs on byte/opcode data, LSTMs/Transformers on behavior sequences, GNNs on
  call graphs) for harder cases.
- Plus heaps of **heuristics/rules** and human review.

**Why industry leans on ensembles + heuristics:** they need **explainability** (analysts must
justify a takedown), **low false-positive rates** (a wrong flag on a popular extension is a PR
disaster), and **robustness** at scale. That mix — *rules + tree ensemble as the backbone, deep
learning as a booster* — is **exactly the tiered design we recommend below.**

---

## 7. The recommendation for `extdrift` (this is the plan)

This directly satisfies the professor's "reproduce existing state of the art, *then* improve."

### Tier 1 — Baseline / reproduction (MUST-HAVE this semester)
- **Weighted-rule scorer** = our **heuristics** (the professor explicitly asked for these). This
  is also our "why ML?" control: ML only earns its place if it beats these rules.
- **Random Forest** — the reliable, explainable learned baseline.
- **XGBoost (or LightGBM)** — the **tabular state-of-the-art**; a trivial add that answers
  *"why not something better than Random Forest?"* on its own.
- **SHAP** for explanations (see glossary) so every verdict is justifiable.
- **This whole tier runs fine on Bind's i3/4 GB laptop** — these models are light.

### Tier 2 — The "more state-of-the-art" model + our novelty (STRETCH / Phase 2)
Change the **representation**, then apply a deep model:
- **Option A — Sequence:** turn each trace into an **ordered event sequence** and run a small
  **Transformer or BiLSTM**. Captures the *order* of behavior. Cleanest "SOTA" story.
- **Option B — Graph:** build a **behavior/data-flow graph** (cookie-read → network-POST) and run
  a **GNN/GCN**. Captures *structure*; best fit for detecting exfiltration. **Most novel.**
- Either way, the genuinely new contribution is **comparing (diffing) these sequence/graph
  representations across two versions** — no published work does cross-version behavioral diffing
  with sequence/graph models.
- **Run these on Codespaces / a cloud VM**, not the i3 laptop.

### The honest caveats (put these in the report — they make you look *more* credible)
1. **Deep models need lots of data.** We have very few *real* malicious update pairs. A
   Transformer/GNN trained on a thin dataset will **overfit**. So Tier 2 depends on a large,
   diverse **synthetic** corpus, and is correctly scoped as a stretch goal.
2. **Concept drift is real** (2025 papers): a model trained on 2024 attacks degrades on 2026
   ones. Report this limitation rather than hiding it.
3. **The classifier is not the hero.** The 2025 "It's not Easy" result shows 98% lab accuracy can
   mean nothing in the wild. Our headline contribution is the **deterministic record/replay
   update-diff pipeline**; the model is one component.

---

## 8. Glossary — every acronym in one place

| Term | Full form | One-line meaning |
|---|---|---|
| ML | Machine Learning | Learning rules from examples instead of hand-coding them |
| RF | Random Forest | Many decision trees that vote; strong tabular baseline |
| Bagging | Bootstrap Aggregating | Train many models on random samples, average them |
| XGBoost | eXtreme Gradient Boosting | Trees built sequentially, each fixing the last's errors; tabular SOTA |
| LightGBM | Light Gradient Boosting Machine | Microsoft's fast gradient-boosting variant |
| CatBoost | Categorical Boosting | Yandex's gradient-boosting variant |
| Boosting | — | Sequential error-correcting ensemble |
| SVM | Support Vector Machine | Finds the maximum-margin dividing boundary between classes |
| NN | Neural Network | Layers of math units that learn from raw data |
| DL | Deep Learning | A neural network with many layers |
| CNN | Convolutional Neural Network | Detects local patterns; great for images/byte data |
| RNN | Recurrent Neural Network | Reads sequences step-by-step with memory |
| LSTM | Long Short-Term Memory | RNN with gates that remembers long-range context |
| BiLSTM | Bidirectional LSTM | LSTM that reads the sequence forwards and backwards |
| Transformer | — | Uses self-attention; the architecture behind modern AI |
| Attention | — | Mechanism scoring how relevant each item is to each other |
| BERT | Bidirectional Encoder Representations from Transformers | Pre-trained Transformer giving context-aware embeddings |
| LLM | Large Language Model | Very large Transformer trained on massive text |
| Embedding | — | A numeric vector capturing the "meaning" of something |
| GNN | Graph Neural Network | Neural network that learns from graph structure |
| GCN | Graph Convolutional Network | GNN that averages neighbour features |
| GAT | Graph Attention Network | GNN that weights neighbours via attention |
| SHAP | SHapley Additive exPlanations | Explains a prediction by crediting each feature's contribution |
| Feature | — | One input number describing an example |
| Overfitting | — | Memorising training data; fails on new data |
| Class imbalance | — | One class (malicious) far rarer than the other (benign) |
| Concept drift | — | The pattern changes over time, so old models go stale |
| Accuracy | — | Fraction of predictions that are correct |
| Precision | — | Of items flagged malicious, the fraction truly malicious |
| Recall / TPR | True Positive Rate | Of all real malicious items, the fraction caught |
| FPR | False Positive Rate | Of all benign items, the fraction wrongly flagged |
| F1 | — | Harmonic mean of precision and recall |
| ROC / AUC | Receiver Operating Characteristic / Area Under Curve | Threshold-independent quality score (1.0 = perfect) |
| Cross-validation | — | Rotate train/test splits to estimate honest performance |
| Tabular / Sequence / Graph | — | The three data "shapes" (table / ordered list / network) |

---

## 9. References (with links)

1. D. Bui, B. Tang, K. G. Shin — *Detection of Inconsistencies in Privacy Practices of Browser
   Extensions (ExtPrivA)*, IEEE S&P 2023. **[Base paper.]**
   https://ieeexplore.ieee.org/document/10179338/
2. *It's not Easy: Applying Supervised ML to Detect Malicious Extensions in the Chrome Web Store*,
   arXiv:2509.21590, 2025. https://arxiv.org/abs/2509.21590
3. *Detecting Malicious Browser Extensions by Combining ML and Feature Engineering*, Springer,
   2023. https://link.springer.com/chapter/10.1007/978-3-031-28332-1_13
4. Rosenzweig et al. — concept-drift in extension detection, TWeb 2025.
   https://aurore54f.github.io/papers/2025-tweb_rosenzweig_extensionsconcdrift.pdf
5. L. Grinsztajn et al. — *Why do tree-based models still outperform deep learning on tabular
   data?*, NeurIPS 2022. https://arxiv.org/abs/2207.08815
6. *Ransomware Detection by Distinguishing API Call Sequences through LSTM and BERT*, The Computer
   Journal, 2024. https://academic.oup.com/comjnl/article-abstract/67/2/632/7067524
7. *BERT-Transformer-TextCNN for APT Malware Detection*, ACM, 2024.
   https://dl.acm.org/doi/10.1145/3665348.3665389
8. *GraphShield: dynamic graph-based malware detection using GNNs*, 2025.
   https://www.sciencedirect.com/science/article/pii/S095741742503427X
9. *BEACON: Behavioral Malware Classification with LLM Embeddings*, arXiv:2509.14519, 2025.
   https://arxiv.org/pdf/2509.14519
10. A. Kapravelos et al. — *Hulk: Eliciting Malicious Behavior in Browser Extensions*, USENIX
    Security 2014. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/kapravelos

---

*Companion docs: see [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) for how the whole system
is built, and the root [`README.md`](../README.md) for the project overview.*
