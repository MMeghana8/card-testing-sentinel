import pandas as pd

from src.detector import CardTestingDetector
from src.clusterer import AttackClusterer
from src.action_engine import ActionEngine


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv("data/transactions.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

df["minute"] = df["timestamp"].dt.floor("min")

df["is_failed"] = (
    df["success"] == 0
).astype(int)

df["is_low_value"] = (
    df["amount"] <= 10
).astype(int)


# ============================================================
# CREATE MINUTE WINDOWS
# ============================================================

minute_windows = (
    df.groupby("minute")
    .agg(
        transaction_count=("transaction_id", "count"),
        failed_count=("is_failed", "sum"),
        low_value_count=("is_low_value", "sum"),
        unique_devices=("device_id", "nunique"),
        unique_ips=("ip_address", "nunique"),
        unique_bins=("card_bin", "nunique")
    )
    .reset_index()
)

minute_windows["failure_rate"] = (
    minute_windows["failed_count"]
    / minute_windows["transaction_count"]
)

minute_windows["low_value_rate"] = (
    minute_windows["low_value_count"]
    / minute_windows["transaction_count"]
)


# ============================================================
# TRAINING BASELINE
# ============================================================

training_end = int(
    len(minute_windows) * 0.60
)

baseline = minute_windows.iloc[
    :training_end
].copy()


# ============================================================
# DETECTOR
# ============================================================

detector = CardTestingDetector(
    baseline_data=baseline
)


# ============================================================
# TEST SAMPLE
# ============================================================

sample = df.head(10_000)


# ============================================================
# DETECTION
# ============================================================

detected = detector.detect(sample)

suspicious_windows = detected[
    detected["is_suspicious"]
].copy()


# ============================================================
# CLUSTERING
# ============================================================

clusterer = AttackClusterer(
    min_cluster_size=3,
    time_window_seconds=120
)

suspicious_transactions = (
    clusterer.find_suspicious_transactions(
        sample,
        suspicious_windows["minute"]
    )
)

clustered = clusterer.cluster(
    suspicious_transactions
)

cluster_summary = (
    clusterer.summarize_clusters(
        clustered
    )
)


# ============================================================
# ACTION ENGINE
# ============================================================

action_engine = ActionEngine()

reports = []


# ============================================================
# GENERATE ACTION REPORTS
# ============================================================

if not cluster_summary.empty:

    for _, cluster in cluster_summary.iterrows():

        report = action_engine.generate_report(
            cluster
        )

        reports.append(report)


# ============================================================
# DISPLAY SUMMARY
# ============================================================

print("=" * 70)
print("CARD-TESTING SENTINEL — ACTION ENGINE TEST")
print("=" * 70)

print(
    f"Suspicious windows       : "
    f"{len(suspicious_windows):,}"
)

print(
    f"Suspicious transactions  : "
    f"{len(suspicious_transactions):,}"
)

print(
    f"Clusters discovered      : "
    f"{len(cluster_summary):,}"
)

print(
    f"Action reports generated : "
    f"{len(reports):,}"
)


# ============================================================
# DISPLAY TOP ACTIONS
# ============================================================

print()
print("TOP RECOMMENDED ACTIONS")
print("-" * 70)


if reports:

    reports = sorted(
        reports,
        key=lambda x: x["severity"],
        reverse=True
    )

    for report in reports[:10]:

        print()
        print(
            f"Cluster #{report['cluster_id']}"
        )

        print(
            f"Severity   : "
            f"{report['severity']}"
        )

        print(
            f"Confidence : "
            f"{report['confidence']}"
        )

        print(
            f"Action     : "
            f"{report['recommended_action']}"
        )

        print(
            f"Duration   : "
            f"{report['duration_minutes']} minutes"
        )

        print(
            f"Approval   : "
            f"{report['requires_human_approval']}"
        )

        print(
            f"Auto-block : "
            f"{report['automatic_block']}"
        )

        print("Reasons:")

        if report["reasoning"]:

            for reason in report["reasoning"]:

                print(
                    f"  - {reason}"
                )

        else:

            print(
                "  - No strong attack signals"
            )

else:

    print(
        "No actionable clusters found."
    )


# ============================================================
# SAFETY CHECK
# ============================================================

print()
print("SAFETY CHECK")
print("-" * 70)

auto_block_values = [
    report["automatic_block"]
    for report in reports
]

approval_values = [
    report["requires_human_approval"]
    for report in reports
]


if reports and all(
    value is False
    for value in auto_block_values
):

    print(
        "PASS: No automatic blocking enabled."
    )

else:

    print(
        "WARNING: Automatic blocking detected."
    )


if reports and all(
    value is True
    for value in approval_values
):

    print(
        "PASS: Human approval required."
    )

else:

    print(
        "WARNING: Human approval not required."
    )


print()
print("=" * 70)
print("ACTION ENGINE TEST COMPLETED")
print("=" * 70)