import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta


# ============================================================
# CARD-TESTING ATTACK SENTINEL
# Synthetic Payment Transaction Generator
# ============================================================

# -----------------------------
# DATASET SIZE
# -----------------------------
TOTAL_TRANSACTIONS = 500_000

NORMAL_TRANSACTIONS = 450_000
ATTACK_TRANSACTIONS = 50_000

RANDOM_SEED = 42

np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)


# -----------------------------
# TIME CONFIGURATION
# -----------------------------
START_TIME = datetime(2026, 1, 1, 0, 0, 0)

DAYS = 30
SECONDS_IN_DAY = 24 * 60 * 60
TOTAL_SECONDS = DAYS * SECONDS_IN_DAY


# ============================================================
# INFRASTRUCTURE
# ============================================================

MERCHANTS = [
    f"M{i:04d}" for i in range(1, 101)
]

NORMAL_DEVICES = [
    f"DEV_N_{i:05d}" for i in range(1, 20_001)
]

ATTACK_DEVICES = [
    f"DEV_A_{i:05d}" for i in range(1, 501)
]

NORMAL_IPS = [
    f"103.{random.randint(0, 255)}."
    f"{random.randint(0, 255)}."
    f"{random.randint(1, 254)}"
    for _ in range(5_000)
]

ATTACK_IPS = [
    f"185.{random.randint(0, 255)}."
    f"{random.randint(0, 255)}."
    f"{random.randint(1, 254)}"
    for _ in range(200)
]

# Common BINs
NORMAL_BINS = [
    "411111",
    "424242",
    "555555",
    "378282",
    "601111",
    "400000",
    "510510",
    "520082",
    "453201",
    "491748",
    "448407",
    "402400"
]

# BINs used heavily by attack campaigns
ATTACK_BINS = [
    "498765",
    "498766",
    "498767",
    "498768",
    "498769",
    "498770",
    "498771",
    "498772"
]


# ============================================================
# NORMAL TRANSACTIONS
# ============================================================

print("Generating normal transactions...")

normal_timestamps = np.random.randint(
    0,
    TOTAL_SECONDS,
    NORMAL_TRANSACTIONS
)

normal_timestamps = [
    START_TIME + timedelta(seconds=int(x))
    for x in normal_timestamps
]


normal_amounts = []

for _ in range(NORMAL_TRANSACTIONS):

    # Most normal payments are ordinary purchase amounts.
    # Some legitimate payments are intentionally small so
    # the detector cannot simply flag every low-value payment.

    payment_type = random.random()

    if payment_type < 0.08:
        # Legitimate small payment
        amount = round(random.uniform(1, 10), 2)

    elif payment_type < 0.20:
        # Smaller ordinary payment
        amount = round(random.uniform(10, 100), 2)

    else:
        # Normal purchase
        amount = round(
            np.random.lognormal(
                mean=5.5,
                sigma=0.8
            ),
            2
        )

        amount = min(amount, 25_000)

    normal_amounts.append(amount)


normal_success = np.random.choice(
    [0, 1],
    size=NORMAL_TRANSACTIONS,
    p=[0.07, 0.93]
)


normal_data = pd.DataFrame({
    "transaction_id": [
        f"TXN_N_{i:07d}"
        for i in range(NORMAL_TRANSACTIONS)
    ],

    "timestamp": normal_timestamps,

    "merchant_id": np.random.choice(
        MERCHANTS,
        NORMAL_TRANSACTIONS
    ),

    "amount": normal_amounts,

    "device_id": np.random.choice(
        NORMAL_DEVICES,
        NORMAL_TRANSACTIONS
    ),

    "ip_address": np.random.choice(
        NORMAL_IPS,
        NORMAL_TRANSACTIONS
    ),

    "card_bin": np.random.choice(
        NORMAL_BINS,
        NORMAL_TRANSACTIONS
    ),

    "success": normal_success,

    "is_attack": 0
})


# ============================================================
# ATTACK CAMPAIGNS
# ============================================================

print("Generating coordinated card-testing attacks...")

attack_rows = []

NUMBER_OF_CAMPAIGNS = 500

for campaign_id in range(NUMBER_OF_CAMPAIGNS):

    # Each campaign has its own infrastructure.
    attack_device = random.choice(ATTACK_DEVICES)
    attack_ip = random.choice(ATTACK_IPS)

    # Attackers test cards belonging to a small number of BINs.
    campaign_bins = random.sample(
        ATTACK_BINS,
        k=random.randint(2, 4)
    )

    # One or several merchants can be targeted.
    campaign_merchants = random.sample(
        MERCHANTS,
        k=random.randint(1, 4)
    )

    # Campaign duration:
    # 2 minutes to 20 minutes
    campaign_duration = random.randint(
        120,
        1200
    )

    campaign_start = START_TIME + timedelta(
        seconds=random.randint(
            0,
            TOTAL_SECONDS - campaign_duration
        )
    )

    # Number of transactions in this campaign
    transactions_in_campaign = (
        ATTACK_TRANSACTIONS // NUMBER_OF_CAMPAIGNS
    )

    for _ in range(transactions_in_campaign):

        # Rapid-fire transaction timing
        seconds_from_start = random.randint(
            0,
            campaign_duration
        )

        timestamp = campaign_start + timedelta(
            seconds=seconds_from_start
        )

        # Card-testing amount
        amount = round(
            random.uniform(1, 10),
            2
        )

        # High failure rate
        success = np.random.choice(
            [0, 1],
            p=[0.82, 0.18]
        )

        attack_rows.append({
            "transaction_id": (
                f"TXN_A_{len(attack_rows):07d}"
            ),

            "timestamp": timestamp,

            "merchant_id": random.choice(
                campaign_merchants
            ),

            "amount": amount,

            "device_id": attack_device,

            "ip_address": attack_ip,

            "card_bin": random.choice(
                campaign_bins
            ),

            "success": success,

            "is_attack": 1
        })


attack_data = pd.DataFrame(attack_rows)


# ============================================================
# COMBINE DATA
# ============================================================

print("Combining datasets...")

df = pd.concat(
    [
        normal_data,
        attack_data
    ],
    ignore_index=True
)


# ============================================================
# SHUFFLE + SORT
# ============================================================

df = df.sample(
    frac=1,
    random_state=RANDOM_SEED
).reset_index(drop=True)

df = df.sort_values(
    "timestamp"
).reset_index(drop=True)


# ============================================================
# ADD CAMPAIGN-FRIENDLY FEATURES
# ============================================================

df["hour"] = pd.to_datetime(
    df["timestamp"]
).dt.hour

df["day_of_week"] = pd.to_datetime(
    df["timestamp"]
).dt.dayofweek

df["is_low_value"] = (
    df["amount"] <= 10
).astype(int)

df["is_failed"] = (
    df["success"] == 0
).astype(int)


# ============================================================
# SAVE
# ============================================================

OUTPUT_PATH = "data/transactions.csv"

df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ============================================================
# DATASET SUMMARY
# ============================================================

print()
print("=" * 60)
print("CARD-TESTING ATTACK SENTINEL DATASET")
print("=" * 60)

print(f"Total transactions : {len(df):,}")
print(
    f"Normal transactions: "
    f"{(df['is_attack'] == 0).sum():,}"
)
print(
    f"Attack transactions: "
    f"{(df['is_attack'] == 1).sum():,}"
)

print(
    f"Attack percentage  : "
    f"{df['is_attack'].mean() * 100:.2f}%"
)

print()
print("Columns:")
print(list(df.columns))

print()
print("Attack success rate:")
print(
    df[df["is_attack"] == 1]["success"].mean()
)

print()
print("Normal success rate:")
print(
    df[df["is_attack"] == 0]["success"].mean()
)

print()
print("Low-value transactions:")
print(
    f"{df['is_low_value'].sum():,}"
)

print()
print(f"Saved to: {OUTPUT_PATH}")

print("=" * 60)