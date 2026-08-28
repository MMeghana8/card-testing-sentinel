import os
import pandas as pd

from src.detector import CardTestingDetector
from src.clusterer import AttackClusterer
from src.action_engine import ActionEngine


class CardTestingSentinel:

    def __init__(
        self,
        data_path="data/transactions.csv"
    ):
        self.data_path = data_path

        self.detector = None
        self.clusterer = AttackClusterer(
            min_cluster_size=3,
            time_window_seconds=120
        )
        self.action_engine = ActionEngine()

    # ========================================================
    # LOAD DATA
    # ========================================================

    def load_data(self):

        df = pd.read_csv(
            self.data_path
        )

        df["timestamp"] = pd.to_datetime(
            df["timestamp"]
        )

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

        return df

    # ========================================================
    # CREATE MINUTE WINDOWS
    # ========================================================

    def create_windows(self, df):

        windows = (
            df.groupby("minute")
            .agg(
                transaction_count=(
                    "transaction_id",
                    "count"
                ),

                failed_count=(
                    "is_failed",
                    "sum"
                ),

                low_value_count=(
                    "is_low_value",
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

        windows["failure_rate"] = (
            windows["failed_count"]
            / windows["transaction_count"]
        )

        windows["low_value_rate"] = (
            windows["low_value_count"]
            / windows["transaction_count"]
        )

        return windows

    # ========================================================
    # DETECTION
    # ========================================================

    def detect_attacks(
        self,
        df,
        windows
    ):

        training_end = int(
            len(windows) * 0.60
        )

        baseline = windows.iloc[
            :training_end
        ].copy()

        self.detector = CardTestingDetector(
            baseline_data=baseline
        )

        detected = self.detector.detect(
            df
        )

        suspicious_windows = detected[
            detected["is_suspicious"]
        ].copy()

        return detected, suspicious_windows

    # ========================================================
    # CLUSTERING
    # ========================================================

    def cluster_attacks(
        self,
        df,
        suspicious_windows
    ):

        suspicious_transactions = (
            self.clusterer
            .find_suspicious_transactions(
                df,
                suspicious_windows["minute"]
            )
        )

        clustered = self.clusterer.cluster(
            suspicious_transactions
        )

        cluster_summary = (
            self.clusterer
            .summarize_clusters(
                clustered
            )
        )

        return (
            suspicious_transactions,
            clustered,
            cluster_summary
        )

    # ========================================================
    # ACTION RECOMMENDATIONS
    # ========================================================

    def generate_actions(
        self,
        cluster_summary
    ):

        reports = []

        for _, cluster in (
            cluster_summary.iterrows()
        ):

            report = (
                self.action_engine
                .generate_report(
                    cluster
                )
            )

            reports.append(
                report
            )

        return reports

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    def save_results(
        self,
        detected,
        suspicious_transactions,
        clustered,
        cluster_summary,
        reports
    ):

        os.makedirs(
            "data/results",
            exist_ok=True
        )

        detected.to_csv(
            "data/results/detected_windows.csv",
            index=False
        )

        suspicious_transactions.to_csv(
            "data/results/suspicious_transactions.csv",
            index=False
        )

        clustered.to_csv(
            "data/results/clustered_transactions.csv",
            index=False
        )

        cluster_summary.to_csv(
            "data/results/cluster_summary.csv",
            index=False
        )

        pd.DataFrame(
            reports
        ).to_csv(
            "data/results/action_recommendations.csv",
            index=False
        )

    # ========================================================
    # RUN COMPLETE PIPELINE
    # ========================================================

    def run(self):

        print("=" * 70)
        print(
            "CARD-TESTING SENTINEL — COMPLETE PIPELINE"
        )
        print("=" * 70)

        # ----------------------------------------------------
        # Load
        # ----------------------------------------------------

        print()
        print("1. Loading transactions...")

        df = self.load_data()

        print(
            f"   Transactions loaded: "
            f"{len(df):,}"
        )

        # ----------------------------------------------------
        # Windows
        # ----------------------------------------------------

        print()
        print("2. Creating time windows...")

        windows = self.create_windows(
            df
        )

        print(
            f"   Windows created: "
            f"{len(windows):,}"
        )

        # ----------------------------------------------------
        # Detection
        # ----------------------------------------------------

        print()
        print("3. Detecting suspicious activity...")

        detected, suspicious_windows = (
            self.detect_attacks(
                df,
                windows
            )
        )

        print(
            f"   Suspicious windows: "
            f"{len(suspicious_windows):,}"
        )

        # ----------------------------------------------------
        # Clustering
        # ----------------------------------------------------

        print()
        print("4. Clustering coordinated attacks...")

        (
            suspicious_transactions,
            clustered,
            cluster_summary
        ) = self.cluster_attacks(
            df,
            suspicious_windows
        )

        print(
            f"   Suspicious transactions: "
            f"{len(suspicious_transactions):,}"
        )

        print(
            f"   Transactions clustered: "
            f"{len(clustered):,}"
        )

        print(
            f"   Attack clusters: "
            f"{len(cluster_summary):,}"
        )

        # ----------------------------------------------------
        # Actions
        # ----------------------------------------------------

        print()
        print(
            "5. Generating bounded recommendations..."
        )

        reports = self.generate_actions(
            cluster_summary
        )

        print(
            f"   Recommendations generated: "
            f"{len(reports):,}"
        )

        # ----------------------------------------------------
        # Safety
        # ----------------------------------------------------

        print()
        print("6. Running safety checks...")

        auto_blocks = sum(
            report["automatic_block"]
            for report in reports
        )

        approvals_required = sum(
            report["requires_human_approval"]
            for report in reports
        )

        print(
            f"   Automatic blocks: "
            f"{auto_blocks}"
        )

        print(
            f"   Human approvals required: "
            f"{approvals_required}"
        )

        # ----------------------------------------------------
        # Save
        # ----------------------------------------------------

        print()
        print("7. Saving results...")

        self.save_results(
            detected,
            suspicious_transactions,
            clustered,
            cluster_summary,
            reports
        )

        print(
            "   Results saved to data/results/"
        )

        # ----------------------------------------------------
        # Final
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 70)

        return {
            "transactions": len(df),
            "windows": len(windows),
            "suspicious_windows": len(
                suspicious_windows
            ),
            "suspicious_transactions": len(
                suspicious_transactions
            ),
            "clustered_transactions": len(
                clustered
            ),
            "clusters": len(
                cluster_summary
            ),
            "recommendations": len(
                reports
            ),
            "automatic_blocks": auto_blocks,
            "human_approvals": approvals_required
        }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    sentinel = CardTestingSentinel()

    sentinel.run()