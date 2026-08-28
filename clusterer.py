import pandas as pd
import numpy as np


class AttackClusterer:
    """
    Scalable, time-aware graph clustering for coordinated
    card-testing attacks.

    Transactions are connected when they share:
        - device_id OR
        - ip_address OR
        - card_bin

    AND occur within the configured time window.

    Uses time buckets + Union-Find instead of comparing
    every transaction pair.
    """

    def __init__(
        self,
        min_cluster_size=3,
        time_window_seconds=120
    ):
        self.min_cluster_size = min_cluster_size
        self.time_window_seconds = time_window_seconds

    # ========================================================
    # PREPARE TRANSACTIONS
    # ========================================================

    def prepare_transactions(self, transactions):

        df = transactions.copy()

        df["timestamp"] = pd.to_datetime(
            df["timestamp"]
        )

        df["is_failed"] = (
            df["success"] == 0
        ).astype(int)

        df["is_low_value"] = (
            df["amount"] <= 10
        ).astype(int)

        df["minute"] = (
            df["timestamp"]
            .dt.floor("min")
        )

        return df

    # ========================================================
    # FIND SUSPICIOUS TRANSACTIONS
    # ========================================================

    def find_suspicious_transactions(
        self,
        transactions,
        suspicious_minutes
    ):

        df = self.prepare_transactions(
            transactions
        )

        suspicious_minutes = pd.to_datetime(
            suspicious_minutes
        )

        suspicious = df[
            df["minute"].isin(
                suspicious_minutes
            )
        ].copy()

        return suspicious

    # ========================================================
    # UNION-FIND
    # ========================================================

    def _find(self, parent, x):

        while parent[x] != x:

            parent[x] = parent[
                parent[x]
            ]

            x = parent[x]

        return x

    def _union(
        self,
        parent,
        rank,
        a,
        b
    ):

        root_a = self._find(
            parent,
            a
        )

        root_b = self._find(
            parent,
            b
        )

        if root_a == root_b:
            return

        if rank[root_a] < rank[root_b]:

            parent[root_a] = root_b

        elif rank[root_a] > rank[root_b]:

            parent[root_b] = root_a

        else:

            parent[root_b] = root_a

            rank[root_a] += 1

    # ========================================================
    # OPTIMIZED GRAPH CLUSTERING
    # ========================================================

    def cluster(
        self,
        suspicious_transactions
    ):

        if suspicious_transactions.empty:

            return suspicious_transactions.copy()

        df = suspicious_transactions.copy()

        # ----------------------------------------------------
        # Reset index so every transaction has a compact ID
        # ----------------------------------------------------

        df = df.reset_index(
            drop=True
        )

        n = len(df)

        parent = np.arange(n)

        rank = np.zeros(
            n,
            dtype=np.int8
        )

        # ----------------------------------------------------
        # Convert timestamps to integer seconds
        # ----------------------------------------------------

        timestamps = (
            df["timestamp"]
            .astype("int64")
            // 1_000_000_000
        )

        df["_timestamp_seconds"] = (
            timestamps
        )

        # ----------------------------------------------------
        # Time bucket size
        # ----------------------------------------------------

        bucket_size = (
            self.time_window_seconds
        )

        df["_time_bucket"] = (
            df["_timestamp_seconds"]
            // bucket_size
        )

        # ----------------------------------------------------
        # Process each infrastructure signal
        # ----------------------------------------------------

        signals = [
            "device_id",
            "ip_address",
            "card_bin"
        ]

        for signal in signals:

            # ------------------------------------------------
            # Ignore missing values
            # ------------------------------------------------

            valid = df[
                df[signal].notna()
            ].copy()

            if valid.empty:
                continue

            # ------------------------------------------------
            # Sort by signal + time
            # ------------------------------------------------

            valid = valid.sort_values(
                [
                    signal,
                    "_timestamp_seconds"
                ]
            )

            # ------------------------------------------------
            # Group by signal
            # ------------------------------------------------

            for _, group in valid.groupby(
                signal,
                sort=False
            ):

                indices = (
                    group.index.to_numpy()
                )

                times = (
                    group[
                        "_timestamp_seconds"
                    ]
                    .to_numpy()
                )

                if len(indices) < 2:
                    continue

                # ------------------------------------------------
                # Only connect transactions within time window.
                #
                # Instead of comparing every pair, each transaction
                # is connected to the previous transaction in the
                # same signal group when they are close enough.
                #
                # This keeps the graph sparse.
                # ------------------------------------------------

                previous_index = indices[0]
                previous_time = times[0]

                for position in range(
                    1,
                    len(indices)
                ):

                    current_index = (
                        indices[position]
                    )

                    current_time = (
                        times[position]
                    )

                    difference = (
                        current_time
                        - previous_time
                    )

                    if (
                        difference
                        <= self.time_window_seconds
                    ):

                        self._union(
                            parent,
                            rank,
                            previous_index,
                            current_index
                        )

                    previous_index = (
                        current_index
                    )

                    previous_time = (
                        current_time
                    )

        # ====================================================
        # BUILD COMPONENTS
        # ====================================================

        roots = np.empty(
            n,
            dtype=np.int64
        )

        for i in range(n):

            roots[i] = self._find(
                parent,
                i
            )

        # ----------------------------------------------------
        # Count component sizes
        # ----------------------------------------------------

        component_sizes = (
            pd.Series(roots)
            .value_counts()
        )

        valid_roots = set(
            component_sizes[
                component_sizes
                >= self.min_cluster_size
            ].index
        )

        # ----------------------------------------------------
        # Assign cluster IDs
        # ----------------------------------------------------

        root_to_cluster = {}

        next_cluster_id = 1

        cluster_ids = []

        for root in roots:

            if root not in valid_roots:

                cluster_ids.append(
                    -1
                )

                continue

            if root not in root_to_cluster:

                root_to_cluster[root] = (
                    next_cluster_id
                )

                next_cluster_id += 1

            cluster_ids.append(
                root_to_cluster[root]
            )

        df["cluster_id"] = (
            cluster_ids
        )

        # ----------------------------------------------------
        # Remove unclustered transactions
        # ----------------------------------------------------

        clustered = df[
            df["cluster_id"] != -1
        ].copy()

        # ----------------------------------------------------
        # Remove helper columns
        # ----------------------------------------------------

        clustered = clustered.drop(
            columns=[
                "_timestamp_seconds",
                "_time_bucket"
            ],
            errors="ignore"
        )

        return clustered

    # ========================================================
    # SUMMARIZE CLUSTERS
    # ========================================================

    def summarize_clusters(
        self,
        clustered
    ):

        if clustered.empty:
            return pd.DataFrame()

        summary = (
            clustered
            .groupby("cluster_id")
            .agg(
                transaction_count=(
                    "transaction_id",
                    "count"
                ),

                merchant_count=(
                    "merchant_id",
                    "nunique"
                ),

                device_count=(
                    "device_id",
                    "nunique"
                ),

                ip_count=(
                    "ip_address",
                    "nunique"
                ),

                bin_count=(
                    "card_bin",
                    "nunique"
                ),

                failed_transactions=(
                    "is_failed",
                    "sum"
                ),

                low_value_transactions=(
                    "is_low_value",
                    "sum"
                ),

                first_seen=(
                    "timestamp",
                    "min"
                ),

                last_seen=(
                    "timestamp",
                    "max"
                )
            )
            .reset_index()
        )

        # ----------------------------------------------------
        # Rates
        # ----------------------------------------------------

        summary["failure_rate"] = (
            summary["failed_transactions"]
            /
            summary["transaction_count"]
        )

        summary["low_value_rate"] = (
            summary["low_value_transactions"]
            /
            summary["transaction_count"]
        )

        # ----------------------------------------------------
        # Duration
        # ----------------------------------------------------

        summary["duration_seconds"] = (
            summary["last_seen"]
            -
            summary["first_seen"]
        ).dt.total_seconds()

        # ----------------------------------------------------
        # Coordination score
        # ----------------------------------------------------

        summary["coordination_score"] = (

            (
                summary["device_count"] > 1
            ).astype(int)

            +

            (
                summary["ip_count"] > 1
            ).astype(int)

            +

            (
                summary["bin_count"] > 1
            ).astype(int)
        )

        # ----------------------------------------------------
        # Volume score
        # ----------------------------------------------------

        max_transactions = (
            summary["transaction_count"]
            .max()
        )

        if max_transactions > 0:

            volume_score = (
                summary["transaction_count"]
                /
                max_transactions
            )

        else:

            volume_score = 0

        # ----------------------------------------------------
        # Cluster risk score
        # ----------------------------------------------------

        summary["cluster_risk_score"] = (

            40
            * summary["failure_rate"]

            +

            30
            * summary["low_value_rate"]

            +

            15
            * volume_score

            +

            15
            * (
                summary[
                    "coordination_score"
                ]
                / 3
            )
        )

        summary["cluster_risk_score"] = (
            summary[
                "cluster_risk_score"
            ]
            .clip(0, 100)
            .round(2)
        )

        return summary

    # ========================================================
    # EXPLAIN CLUSTER
    # ========================================================

    def explain_cluster(
        self,
        cluster_row
    ):

        reasons = []

        if (
            cluster_row[
                "failure_rate"
            ] >= 0.70
        ):

            reasons.append(
                "Very high payment failure rate"
            )

        if (
            cluster_row[
                "low_value_rate"
            ] >= 0.70
        ):

            reasons.append(
                "Strong concentration of low-value transactions"
            )

        if (
            cluster_row[
                "transaction_count"
            ] >= 20
        ):

            reasons.append(
                "Rapid high-volume transaction burst"
            )

        if (
            cluster_row[
                "device_count"
            ] > 1
        ):

            reasons.append(
                "Multiple devices connected to the cluster"
            )

        if (
            cluster_row[
                "ip_count"
            ] > 1
        ):

            reasons.append(
                "Multiple IP addresses connected to the cluster"
            )

        if (
            cluster_row[
                "bin_count"
            ] > 1
        ):

            reasons.append(
                "Multiple card BINs connected to the cluster"
            )

        return reasons