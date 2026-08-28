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

# 💡 Solution

**Card-Testing Sentinel** converts raw payment transactions into behavioral time windows, calculates an explainable risk score, identifies coordinated attack clusters, and generates bounded response recommendations.

The system follows:

```text
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

The system is designed to recommend defensive actions rather than automatically blocking transactions.

🎯 Core Features
1. Behavioral Detection

Analyzes transaction behavior using:

Transaction velocity
Payment failure rate
Low-value transaction concentration
Device diversity
IP diversity
Card BIN diversity

Each window receives an explainable 0–100 risk score.

2. Coordinated Attack Clustering

Suspicious transactions are grouped using shared behavioral and infrastructure signals.

This helps identify attacks that span:

Merchants
Devices
IP addresses
Card BINs
3. Explainable Risk Analysis

Instead of only producing a risk score, Sentinel explains why activity was flagged.

Example:

High failure rate
High low-value concentration
Rapid transaction volume
Shared infrastructure
4. Bounded Response Engine

The system generates controlled recommendations such as:

PAUSE_SUSPECTED_BIN
RATE_LIMIT_SUSPECTED_TRAFFIC

Every recommendation has:

Severity
Confidence
Action
Duration
Reasoning
Approval requirement
5. Safety Controls

Sentinel follows a human-in-the-loop architecture.

Detection
   ↓
Risk Assessment
   ↓
Recommendation
   ↓
Human Approval
   ↓
Action

Automatic blocking is disabled.

📊 Verified Results

The pipeline was evaluated on 500,000 transactions.

Metric	Result
Transactions analyzed	500,000
Time windows	43,200
Suspicious windows	5,001
Suspicious transactions	103,316
Attack clusters	2
Recommendations	2
Automatic blocks	0

The detector was also evaluated on a held-out test set:

Metric	Result
Precision	91.62%
Recall	82.85%
F1 Score	87.01%
Threshold	79
🧠 Detection Model

The risk score combines six behavioral signals:

Transaction Count       25%
Failure Rate             30%
Low-Value Rate           25%
Unique Devices           10%
Unique IPs                5%
Unique BINs               5%

The final production threshold is:

Risk Score >= 79

The score is generated using percentile-based comparison against baseline behavior.

This makes the system:

Explainable
Auditable
Threshold-driven
Suitable for behavioral anomaly detection
🔐 Safety Architecture

Sentinel intentionally avoids uncontrolled automatic blocking.

Safety principles

Bounded actions

Recommendations have predefined scopes and durations.

Human approval

High-impact responses require operator approval.

No automatic blocking

The current system does not directly block payment activity.

This reduces the risk of false-positive operational impact.

🏗️ Project Architecture
card-testing-sentinel/
│
├── dashboard/
│   └── app.py
│
├── data/
│   ├── transactions.csv
│   └── results/
│       ├── detected_windows.csv
│       ├── suspicious_transactions.csv
│       ├── clustered_transactions.csv
│       ├── cluster_summary.csv
│       └── action_recommendations.csv
│
├── notebooks/
│   └── 01_data_exploration.ipynb
│
├── src/
│   ├── data_generator.py
│   ├── detector.py
│   ├── clusterer.py
│   ├── action_engine.py
│   └── sentinel.py
│
├── tests/
│   ├── test_detector.py
│   ├── test_clusterer.py
│   └── test_action_engine.py
│
├── .gitignore
└── README.md
⚙️ Tech Stack
Python
Pandas
NumPy
Scikit-learn
Streamlit
Matplotlib
Git
GitHub
```
