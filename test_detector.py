import pandas as pd
from IPython.display import display

from src.detector import CardTestingDetector


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
# CREATE MINUTE-LEVEL BASELINE
# ============================================================

training_windows = (
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


training_windows["failure_rate"] = (
    training_windows["failed_count"]
    / training_windows["transaction_count"]
)


training_windows["low_value_rate"] = (
    training_windows["low_value_count"]
    / training_windows["transaction_count"]
)


# ============================================================
# TRAINING BASELINE
# ============================================================

training_end = int(
    len(training_windows) * 0.60
)

baseline = training_windows.iloc[
    :training_end
].copy()


# ============================================================
# CREATE DETECTOR
# ============================================================

detector = CardTestingDetector(
    baseline_data=baseline
)


# ============================================================
# TEST WITH 10,000 TRANSACTIONS
# ============================================================

sample = df.head(10_000)

result = detector.detect(sample)


# ============================================================
# RESULTS
# ============================================================

print("=" * 60)
print("CARD-TESTING SENTINEL DETECTOR TEST")
print("=" * 60)

print(
    f"Transactions tested : {len(sample):,}"
)

print(
    f"Windows generated   : {len(result):,}"
)

print(
    f"Suspicious windows  : "
    f"{result['is_suspicious'].sum():,}"
)

print(
    f"Maximum risk score  : "
    f"{result['risk_score'].max():.2f}"
)

print(
    f"Minimum risk score  : "
    f"{result['risk_score'].min():.2f}"
)

print()
print("Top suspicious windows:")
print("-" * 60)


display(
    result
    .sort_values(
        "risk_score",
        ascending=False
    )
    .head(10)
)


print("=" * 60)
print("DETECTOR TEST COMPLETED")
print("=" * 60)