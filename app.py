import streamlit as st
import pandas as pd
from pathlib import Path


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Card-Testing Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "data" / "results"


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_data():

    detected = pd.read_csv(
        RESULTS_DIR / "detected_windows.csv"
    )

    suspicious = pd.read_csv(
        RESULTS_DIR / "suspicious_transactions.csv"
    )

    clusters = pd.read_csv(
        RESULTS_DIR / "cluster_summary.csv"
    )

    recommendations = pd.read_csv(
        RESULTS_DIR / "action_recommendations.csv"
    )

    return (
        detected,
        suspicious,
        clusters,
        recommendations
    )


detected, suspicious, clusters, recommendations = load_data()


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Card-Testing Sentinel")

st.caption(
    "Behavioral detection and coordinated card-testing "
    "attack response system"
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("Sentinel Controls")

st.sidebar.metric(
    "Production Risk Threshold",
    "79"
)

st.sidebar.divider()

st.sidebar.subheader("Detection Signals")

st.sidebar.write("✓ Transaction velocity")
st.sidebar.write("✓ Payment failure rate")
st.sidebar.write("✓ Low-value concentration")
st.sidebar.write("✓ Device behavior")
st.sidebar.write("✓ IP behavior")
st.sidebar.write("✓ Card BIN behavior")

st.sidebar.divider()

st.sidebar.success(
    "System operational"
)

st.sidebar.info(
    "Automatic blocking is disabled. "
    "Response actions require human approval."
)


# ============================================================
# KPI CALCULATIONS
# ============================================================

TOTAL_TRANSACTIONS = 500_000

total_windows = len(detected)

suspicious_windows = int(
    detected["is_suspicious"].sum()
)

suspicious_transactions = len(
    suspicious
)

attack_clusters = len(
    clusters
)

human_approvals = len(
    recommendations
)

# ============================================================
# SENTINEL DECISION
# ============================================================

st.header("🎯 Sentinel Decision")

if suspicious_windows > 0:

    highest_risk = float(
        detected["risk_score"].max()
    )

    high_risk_count = int(
        (
            detected["risk_score"] >= 90
        ).sum()
    )

    if high_risk_count > 0:

        st.error(
            f"🚨 HIGH RISK ACTIVITY DETECTED — "
            f"{high_risk_count:,} windows have risk scores "
            f"above 90. Highest risk: {highest_risk:.2f}/100."
        )

    else:

        st.warning(
            f"⚠️ SUSPICIOUS ACTIVITY DETECTED — "
            f"{suspicious_windows:,} windows require investigation."
        )

    st.info(
        f"Sentinel identified {suspicious_transactions:,} "
        f"suspicious transactions across "
        f"{attack_clusters:,} coordinated attack clusters. "
        f"Recommended responses require human approval."
    )

else:

    st.success(
        "✅ No significant card-testing activity detected."
    )

# ============================================================
# OVERVIEW
# ============================================================

st.header("📊 Sentinel Overview")

c1, c2, c3, c4, c5 = st.columns(5)

with c1:
    st.metric(
        "Transactions Analyzed",
        f"{TOTAL_TRANSACTIONS:,}"
    )

with c2:
    st.metric(
        "Windows Monitored",
        f"{total_windows:,}"
    )

with c3:
    st.metric(
        "Suspicious Windows",
        f"{suspicious_windows:,}"
    )

with c4:
    st.metric(
        "Suspicious Transactions",
        f"{suspicious_transactions:,}"
    )

with c5:
    st.metric(
        "Attack Clusters",
        f"{attack_clusters:,}"
    )


# ============================================================
# RISK TIMELINE
# ============================================================

st.header("📈 Risk Activity Timeline")

if "risk_score" in detected.columns:

    chart_data = detected[
        ["minute", "risk_score"]
    ].copy()

    chart_data["minute"] = pd.to_datetime(
        chart_data["minute"]
    )

    chart_data = chart_data.sort_values(
        "minute"
    )

    chart_data = chart_data.set_index(
        "minute"
    )

    st.line_chart(
        chart_data,
        height=350
    )


# ============================================================
# HIGH RISK WINDOWS
# ============================================================

st.header("🚨 Highest-Risk Windows")

top_windows = detected[
    detected["is_suspicious"] == True
].copy()

if not top_windows.empty:

    window_columns = [
        "minute",
        "transaction_count",
        "failed_count",
        "low_value_count",
        "failure_rate",
        "low_value_rate",
        "risk_score",
        "strong_signals"
    ]

    window_columns = [
        column
        for column in window_columns
        if column in top_windows.columns
    ]

    st.dataframe(
        top_windows[
            window_columns
        ]
        .sort_values(
            "risk_score",
            ascending=False
        )
        .head(20),
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No suspicious activity detected."
    )


# ============================================================
# ATTACK CLUSTERS
# ============================================================

st.divider()

st.header("🧩 Coordinated Attack Clusters")

if not clusters.empty:

    cluster_columns = [
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

    cluster_columns = [
        column
        for column in cluster_columns
        if column in clusters.columns
    ]

    st.dataframe(
        clusters[
            cluster_columns
        ]
        .sort_values(
            "transaction_count",
            ascending=False
        )
        .head(20),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No coordinated attack clusters found."
    )


# ============================================================
# RESPONSE ACTIONS
# ============================================================

st.divider()

st.header("⚠️ Recommended Response Actions")

if not recommendations.empty:

    st.warning(
        "These are bounded recommendations. "
        "No action is automatically executed."
    )

    action_columns = [
        "cluster_id",
        "severity",
        "confidence",
        "action",
        "duration_minutes",
        "requires_approval",
        "auto_block"
    ]

    action_columns = [
        column
        for column in action_columns
        if column in recommendations.columns
    ]

    st.dataframe(
        recommendations[
            action_columns
        ],
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No response actions recommended."
    )


# ============================================================
# MERCHANT INVESTIGATION
# ============================================================

st.divider()

st.header("🔎 Merchant Investigation")

if not suspicious.empty:

    merchant_summary = (
        suspicious
        .groupby("merchant_id")
        .agg(
            suspicious_transactions=(
                "transaction_id",
                "count"
            ),
            failed_transactions=(
                "is_failed",
                "sum"
            ),
            low_value_transactions=(
                "is_low_value",
                "sum"
            ),
            total_amount=(
                "amount",
                "sum"
            ),
            unique_devices=(
                "device_id",
                "nunique"
            ),
            unique_ips=(
                "ip_address",
                "nunique"
            ),
            unique_bins=(
                "card_bin",
                "nunique"
            )
        )
        .reset_index()
    )

    merchant_summary["failure_rate"] = (
        merchant_summary["failed_transactions"]
        /
        merchant_summary["suspicious_transactions"]
        * 100
    ).round(2)

    merchant_summary["low_value_rate"] = (
        merchant_summary["low_value_transactions"]
        /
        merchant_summary["suspicious_transactions"]
        * 100
    ).round(2)

    # --------------------------------------------------------
    # MERCHANT SELECTOR
    # --------------------------------------------------------

    merchant_list = (
        merchant_summary
        .sort_values(
            "suspicious_transactions",
            ascending=False
        )["merchant_id"]
        .tolist()
    )

    selected_merchant = st.selectbox(
        "Select a merchant to investigate",
        merchant_list
    )

    merchant = merchant_summary[
        merchant_summary["merchant_id"]
        == selected_merchant
    ].iloc[0]

    # --------------------------------------------------------
    # MERCHANT KPI
    # --------------------------------------------------------

    st.subheader(
        f"Merchant: {selected_merchant}"
    )

    m1, m2, m3, m4 = st.columns(4)

    with m1:

        st.metric(
            "Suspicious Transactions",
            f"{int(merchant['suspicious_transactions']):,}"
        )

    with m2:

        st.metric(
            "Failure Rate",
            f"{merchant['failure_rate']:.2f}%"
        )

    with m3:

        st.metric(
            "Low-Value Rate",
            f"{merchant['low_value_rate']:.2f}%"
        )

    with m4:

        st.metric(
            "Suspicious Amount",
            f"₹{merchant['total_amount']:,.2f}"
        )

    # --------------------------------------------------------
    # INFRASTRUCTURE
    # --------------------------------------------------------

    st.subheader(
        "Infrastructure Signals"
    )

    i1, i2, i3 = st.columns(3)

    with i1:

        st.metric(
            "Unique Devices",
            f"{int(merchant['unique_devices']):,}"
        )

    with i2:

        st.metric(
            "Unique IPs",
            f"{int(merchant['unique_ips']):,}"
        )

    with i3:

        st.metric(
            "Card BINs",
            f"{int(merchant['unique_bins']):,}"
        )

    # --------------------------------------------------------
    # MERCHANT TRANSACTIONS
    # --------------------------------------------------------

    merchant_transactions = suspicious[
        suspicious["merchant_id"]
        == selected_merchant
    ].copy()

    merchant_transactions["timestamp"] = pd.to_datetime(
        merchant_transactions["timestamp"]
    )

    # --------------------------------------------------------
    # ACTIVITY TIMELINE
    # --------------------------------------------------------

    st.subheader(
        "Suspicious Transaction Activity"
    )

    timeline = (
        merchant_transactions
        .set_index("timestamp")
        .resample("5min")
        .size()
        .rename("transactions")
    )

    st.bar_chart(
        timeline,
        height=300
    )

    # --------------------------------------------------------
    # TRANSACTION TABLE
    # --------------------------------------------------------

    st.subheader(
        "Recent Suspicious Transactions"
    )

    transaction_columns = [
        "transaction_id",
        "timestamp",
        "amount",
        "device_id",
        "ip_address",
        "card_bin",
        "success",
        "is_attack"
    ]

    transaction_columns = [
        column
        for column in transaction_columns
        if column in merchant_transactions.columns
    ]

    st.dataframe(
        merchant_transactions[
            transaction_columns
        ]
        .sort_values(
            "timestamp",
            ascending=False
        )
        .head(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No suspicious transactions available "
        "for merchant investigation."
    )


# ============================================================
# SAFETY ARCHITECTURE
# ============================================================

st.divider()

st.header("🔐 Safety Architecture")

s1, s2, s3 = st.columns(3)

with s1:

    st.success(
        "✓ Bounded Actions"
    )

    st.caption(
        "Every recommended action has "
        "a predefined duration and scope."
    )

with s2:

    st.success(
        "✓ Human Approval"
    )

    st.caption(
        "High-impact responses require "
        "operator approval."
    )

with s3:

    st.success(
        "✓ Automatic Blocking OFF"
    )

    st.caption(
        "The Sentinel recommends actions "
        "instead of directly blocking payments."
    )

# ============================================================
# ATTACK EXPLANATION
# ============================================================

st.divider()

st.header("🧠 Attack Explanation")

if not clusters.empty:

    cluster_ids = (
        clusters["cluster_id"]
        .dropna()
        .astype(int)
        .tolist()
    )

    selected_cluster = st.selectbox(
        "Select an attack cluster to explain",
        cluster_ids
    )

    selected = clusters[
        clusters["cluster_id"]
        == selected_cluster
    ].iloc[0]

    st.subheader(
        f"Why Cluster #{selected_cluster} is Suspicious"
    )

    # --------------------------------------------------------
    # SIGNAL VALUES
    # --------------------------------------------------------

    transaction_count = int(
        selected.get("transaction_count", 0)
    )

    merchant_count = int(
        selected.get("merchant_count", 0)
    )

    device_count = int(
        selected.get("device_count", 0)
    )

    ip_count = int(
        selected.get("ip_count", 0)
    )

    bin_count = int(
        selected.get("bin_count", 0)
    )

    failed = int(
        selected.get("failed_transactions", 0)
    )

    low_value = int(
        selected.get("low_value_transactions", 0)
    )

    failure_rate = float(
        selected.get("failure_rate", 0)
    )

    low_value_rate = float(
        selected.get("low_value_rate", 0)
    )

    duration = float(
        selected.get("duration_seconds", 0)
    )

    # --------------------------------------------------------
    # CONVERT RATES
    # --------------------------------------------------------

    if failure_rate <= 1:
        failure_percent = failure_rate * 100
    else:
        failure_percent = failure_rate

    if low_value_rate <= 1:
        low_value_percent = low_value_rate * 100
    else:
        low_value_percent = low_value_rate

    # --------------------------------------------------------
    # SIGNAL CARDS
    # --------------------------------------------------------

    e1, e2, e3, e4 = st.columns(4)

    with e1:

        st.metric(
            "Transactions",
            f"{transaction_count:,}"
        )

    with e2:

        st.metric(
            "Failure Rate",
            f"{failure_percent:.1f}%"
        )

    with e3:

        st.metric(
            "Low-Value Rate",
            f"{low_value_percent:.1f}%"
        )

    with e4:

        st.metric(
            "Duration",
            f"{duration / 60:.1f} min"
        )

    # --------------------------------------------------------
    # INFRASTRUCTURE SIGNALS
    # --------------------------------------------------------

    st.subheader(
        "🔗 Shared Infrastructure"
    )

    i1, i2, i3, i4 = st.columns(4)

    with i1:

        st.metric(
            "Merchants",
            merchant_count
        )

    with i2:

        st.metric(
            "Devices",
            device_count
        )

    with i3:

        st.metric(
            "IP Addresses",
            ip_count
        )

    with i4:

        st.metric(
            "Card BINs",
            bin_count
        )

    # --------------------------------------------------------
    # EXPLANATION
    # --------------------------------------------------------

    st.subheader(
        "🚨 Detection Reasoning"
    )

    reasons = []

    if failure_percent >= 70:

        reasons.append(
            f"Payment failure rate is extremely high "
            f"({failure_percent:.1f}%)."
        )

    if low_value_percent >= 80:

        reasons.append(
            f"{low_value_percent:.1f}% of transactions "
            f"are low-value attempts."
        )

    if transaction_count >= 50:

        reasons.append(
            f"High transaction velocity detected "
            f"({transaction_count:,} transactions)."
        )

    if device_count <= 3:

        reasons.append(
            f"Activity is concentrated across only "
            f"{device_count} device(s)."
        )

    if ip_count <= 3:

        reasons.append(
            f"Activity is concentrated across only "
            f"{ip_count} IP address(es)."
        )

    if bin_count <= 5:

        reasons.append(
            f"Multiple attempts target a limited set "
            f"of card BINs ({bin_count})."
        )

    if not reasons:

        reasons.append(
            "Multiple behavioral signals indicate "
            "coordinated suspicious activity."
        )

    for reason in reasons:

        st.warning(
            f"• {reason}"
        )

    # --------------------------------------------------------
    # ATTACK INTERPRETATION
    # --------------------------------------------------------

    st.subheader(
        "🎯 Sentinel Interpretation"
    )

    if (
        failure_percent >= 70
        and low_value_percent >= 80
        and transaction_count >= 50
    ):

        st.error(
            "Likely card-testing behavior: "
            "rapid low-value authorization attempts "
            "with a high payment failure rate."
        )

    elif failure_percent >= 50:

        st.warning(
            "Potential payment abuse pattern detected. "
            "Further investigation is recommended."
        )

    else:

        st.info(
            "Suspicious behavior detected, but the "
            "attack pattern is less conclusive."
        )

else:

    st.info(
        "No attack clusters are currently available."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Card-Testing Sentinel | "
    "Explainable behavioral fraud detection | "
    "500K transaction evaluation"
)