import pandas as pd

from src.detector import CardTestingDetector
from src.clusterer import AttackClusterer


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv("data/transactions.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

df["minute"] = (
    df["timestamp"]
    .dt.floor("min")
)

df["is_failed"] = (
    df["success"] == 0
).astype(int)

df["is_low_value"] = (
    df["amount"] <= 10
).astype(int)


# ============================================================
# CREATE MINUTE-LEVEL BASELINE
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
# CREATE DETECTOR
# ============================================================

detector = CardTestingDetector(
    baseline_data=baseline
)


# ============================================================
# DETECT SUSPICIOUS WINDOWS
# ============================================================

# Use a manageable sample for the first clustering test
sample = df.head(10_000)

detected_windows = detector.detect(
    sample
)

suspicious_windows = detected_windows[
    detected_windows["is_suspicious"]
].copy()


print("=" * 60)
print("CARD-TESTING SENTINEL — CLUSTERING TEST")
print("=" * 60)

print(
    f"Suspicious windows: "
    f"{len(suspicious_windows):,}"
)


# ============================================================
# FIND SUSPICIOUS TRANSACTIONS
# ============================================================

clusterer = AttackClusterer(
    min_cluster_size=3
)

suspicious_transactions = (
    clusterer.find_suspicious_transactions(
        sample,
        suspicious_windows["minute"]
    )
)


print(
    f"Suspicious transactions: "
    f"{len(suspicious_transactions):,}"
)


# ============================================================
# BUILD CLUSTERS
# ============================================================

clustered = clusterer.cluster(
    suspicious_transactions
)


print(
    f"Transactions assigned to clusters: "
    f"{len(clustered):,}"
)


# ============================================================
# SUMMARIZE CLUSTERS
# ============================================================

cluster_summary = (
    clusterer.summarize_clusters(
        clustered
    )
)


print(
    f"Clusters discovered: "
    f"{len(cluster_summary):,}"
)


# ============================================================
# SHOW TOP CLUSTERS
# ============================================================

print()
print("TOP ATTACK CLUSTERS")
print("-" * 60)

if not cluster_summary.empty:

    display_columns = [
        "cluster_id",
        "transaction_count",
        "merchant_count",
        "device_count",
        "ip_count",
        "bin_count",
        "failed_transactions",
        "low_value_transactions",
        "failure_rate",
        "low_value_rate",
        "duration_seconds"
    ]

    print(
        cluster_summary
        .sort_values(
            "transaction_count",
            ascending=False
        )
        .head(10)[display_columns]
        .to_string(index=False)
    )

else:

    print("No clusters found.")


print("=" * 60)
print("CLUSTERING TEST COMPLETED")
print("=" * 60)