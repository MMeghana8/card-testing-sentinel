import pandas as pd


class ActionEngine:
    """
    Converts an attack cluster into a bounded,
    explainable defensive recommendation.

    IMPORTANT:
    This engine ONLY recommends actions.
    It never automatically blocks transactions.
    """

    def __init__(self):
        pass

    # ========================================================
    # CALCULATE CLUSTER SEVERITY
    # ========================================================

    def calculate_severity(self, cluster):
        """
        Calculate a 0-100 severity score using:
        - failure rate
        - low-value concentration
        - transaction volume
        - coordination
        """

        failure_score = (
            cluster["failure_rate"] * 40
        )

        low_value_score = (
            cluster["low_value_rate"] * 30
        )

        volume_score = min(
            cluster["transaction_count"] / 100,
            1.0
        ) * 15

        coordination_score = (
            min(
                cluster["coordination_score"] / 3,
                1.0
            ) * 15
        )

        severity = (
            failure_score
            + low_value_score
            + volume_score
            + coordination_score
        )

        return round(
            min(severity, 100),
            2
        )

    # ========================================================
    # RECOMMEND ACTION
    # ========================================================

    def recommend_action(self, cluster):
        """
        Generate a bounded defensive recommendation.
        """

        severity = self.calculate_severity(
            cluster
        )

        failure_rate = cluster[
            "failure_rate"
        ]

        low_value_rate = cluster[
            "low_value_rate"
        ]

        transaction_count = cluster[
            "transaction_count"
        ]

        # ----------------------------------------------------
        # HIGH CONFIDENCE ATTACK
        # ----------------------------------------------------

        if (
            severity >= 80
            and failure_rate >= 0.75
            and low_value_rate >= 0.80
        ):

            action = (
                "PAUSE_SUSPECTED_BIN"
            )

            duration = 15

            confidence = "HIGH"

        # ----------------------------------------------------
        # MEDIUM CONFIDENCE
        # ----------------------------------------------------

        elif (
            severity >= 60
            and failure_rate >= 0.60
        ):

            action = (
                "RATE_LIMIT_SUSPECTED_TRAFFIC"
            )

            duration = 10

            confidence = "MEDIUM"

        # ----------------------------------------------------
        # LOW CONFIDENCE
        # ----------------------------------------------------

        elif severity >= 40:

            action = (
                "INCREASE_MONITORING"
            )

            duration = 5

            confidence = "LOW"

        # ----------------------------------------------------
        # NO ACTION
        # ----------------------------------------------------

        else:

            action = (
                "NO_ACTION"
            )

            duration = 0

            confidence = "LOW"

        # ----------------------------------------------------
        # REASONING
        # ----------------------------------------------------

        reasons = []

        if failure_rate >= 0.75:
            reasons.append(
                f"High failure rate "
                f"({failure_rate:.1%})"
            )

        if low_value_rate >= 0.80:
            reasons.append(
                f"High low-value concentration "
                f"({low_value_rate:.1%})"
            )

        if transaction_count >= 50:
            reasons.append(
                f"Rapid transaction volume "
                f"({transaction_count} transactions)"
            )

        if cluster[
            "coordination_score"
        ] >= 2:

            reasons.append(
                "Multiple shared infrastructure signals"
            )

        # ----------------------------------------------------
        # HUMAN APPROVAL
        # ----------------------------------------------------

        requires_approval = True

        auto_block = False

        return {
            "severity": severity,
            "confidence": confidence,
            "recommended_action": action,
            "duration_minutes": duration,
            "reasons": reasons,
            "requires_approval": requires_approval,
            "auto_block": auto_block
        }

    # ========================================================
    # GENERATE ACTION REPORT
    # ========================================================

    def generate_report(self, cluster):
        """
        Generate a complete explainable recommendation.
        """

        recommendation = self.recommend_action(
            cluster
        )

        report = {
            "cluster_id": cluster[
                "cluster_id"
            ],

            "severity": recommendation[
                "severity"
            ],

            "confidence": recommendation[
                "confidence"
            ],

            "recommended_action": recommendation[
                "recommended_action"
            ],

            "duration_minutes": recommendation[
                "duration_minutes"
            ],

            "reasoning": recommendation[
                "reasons"
            ],

            "requires_human_approval": recommendation[
                "requires_approval"
            ],

            "automatic_block": recommendation[
                "auto_block"
            ]
        }

        return report