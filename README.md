# 🛡️ Card-Testing Sentinel

> Explainable behavioral detection and bounded response system for coordinated card-testing attacks.

## 🚨 Problem

Card-testing attacks generate large numbers of small payment attempts to discover valid card details.

Traditional transaction-level rules can miss coordinated behavior because attackers distribute activity across:

- Multiple merchants
- Devices
- IP addresses
- Card BINs
- Short time windows

The result can be increased payment failures, unnecessary merchant exposure, and missed coordinated attacks.

---

## 💡 Solution

**Card-Testing Sentinel** converts raw payment transactions into behavioral time windows, calculates an explainable risk score, identifies coordinated attack clusters, and generates bounded response recommendations.

> ⚠️ **Note on data:** All transactions used in this project are **synthetically generated** to simulate normal payment behavior and injected card-testing-attack patterns, since real merchant transaction data is not publicly available. Metrics below reflect performance on this synthetic dataset.

The system follows:
Raw Transactions
↓
Behavioral Windows
↓
Risk Detection
↓
Suspicious Transactions
↓
Attack Clustering
↓
Attack Explanation
↓
Bounded Recommendation
↓
Human Approval
↓
Action


The system is designed to **recommend** defensive actions rather than automatically blocking transactions.

---

## 🎯 Core Features

### 1. Behavioral Detection
Analyzes transaction behavior using:
- Transaction velocity
- Payment failure rate
- Low-value transaction concentration
- Device diversity
- IP diversity
- Card BIN diversity

Each window receives an explainable 0–100 risk score.

### 2. Coordinated Attack Clustering
Suspicious transactions are grouped using shared behavioral and infrastructure signals, helping identify attacks that span merchants, devices, IP addresses, and card BINs.

### 3. Explainable Risk Analysis
Instead of only producing a risk score, Sentinel explains *why* activity was flagged — e.g., high failure rate, high low-value concentration, rapid transaction volume, shared infrastructure.

### 4. Bounded Response Engine
Generates controlled recommendations such as `PAUSE_SUSPECTED_BIN` or `RATE_LIMIT_SUSPECTED_TRAFFIC`. Every recommendation includes: severity, confidence, action, duration, reasoning, and an approval requirement.

### 5. Safety Controls
Sentinel follows a human-in-the-loop architecture. Automatic blocking is disabled by design.

---

## 📊 Verified Results

Evaluated on 500,000 synthetic transactions:

| Metric | Result |
|---|---|
| Transactions analyzed | 500,000 |
| Time windows | 43,200 |
| Suspicious windows | 5,001 |
| Suspicious transactions | 103,316 |
| Attack clusters | 2 |
| Recommendations | 2 |
| Automatic blocks | 0 |

Held-out test set performance:

| Metric | Result |
|---|---|
| Precision | 91.62% |
| Recall | 82.85% |
| F1 Score | 87.01% |
| Threshold | 79 |

**Honest trade-off:** At the current threshold, some genuine transactions are flagged for review rather than instantly approved — a real trade-off between catching attacks and disrupting legitimate customers, reported here rather than hidden.

---

## 🧠 Detection Model

The risk score combines six behavioral signals:

| Signal | Weight |
|---|---|
| Transaction Count | 25% |
| Failure Rate | 30% |
| Low-Value Rate | 25% |
| Unique Devices | 10% |
| Unique IPs | 5% |
| Unique BINs | 5% |

Production threshold: **Risk Score ≥ 79**, generated using percentile-based comparison against baseline behavior. This makes the system explainable, auditable, and threshold-driven.

---

## 🔐 Safety Architecture

Sentinel intentionally avoids uncontrolled automatic blocking.

- **Bounded actions** — recommendations have predefined scopes and durations.
- **Human approval** — high-impact responses require operator approval before execution.
- **No automatic blocking** — the system never directly blocks payment activity on its own.

This reduces the risk of false-positive operational impact and keeps a full audit trail for every decision.

---

## 🔧 What Broke & How I Fixed It

- Initial clustering grouped unrelated transactions together → fixed by tightening the shared-signal similarity threshold in the clustering logic.
- Risk score was initially too sensitive to raw transaction count alone, causing high-traffic-but-legitimate windows to be flagged → rebalanced the six signal weights shown above to reduce false positives.
- Early design allowed the system to act on its own → redesigned around a mandatory human-approval gate to keep the system strictly defense-only.

---

## ⚠️ Known Limitations / Future Work

- Live Razorpay Test Mode API execution is designed into the architecture but not yet wired into the action engine — approved actions are currently logged, not auto-executed against the API.
- Evaluated only on synthetic data; real merchant data would likely surface additional edge cases not represented here.

---

## 🏗️ Project Architecture

card-testing-sentinel/
│
├── README.md
├── requirements.txt
├── .gitignore
├── 01_data_exploration.ipynb
├── app.py
├── data_generator.py
├── detector.py
├── clusterer.py
├── action_engine.py
├── sentinel.py
├── test_detector.py
├── test_clusterer.py
└── test_action_engine.py


---

## ⚙️ Tech Stack

Python · Pandas · NumPy · Scikit-learn · Streamlit · Matplotlib · Git · GitHub

---

## 🚀 How to Run

```bash
git clone https://github.com/MMeghana8/card-testing-sentinel.git
cd card-testing-sentinel
python -m venv venv
venv\Scripts\activate      # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```
