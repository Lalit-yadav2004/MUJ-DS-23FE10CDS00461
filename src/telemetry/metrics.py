"""
CodePulse AI - Telemetry & Performance Benchmarking Metrics
===========================================================
Calculates statistical metrics for multi-agent triage:
- Precision, Recall, F1
- False Positive Reduction Rate
- Latency per AST Node
- Token Efficiency Ratio
"""

from typing import Any, Dict, List


class TelemetryMetrics:
    """Aggregates and formats operational metrics across scans."""

    @staticmethod
    def calculate_benchmark_metrics(
        ground_truth: List[Dict[str, Any]],
        predictions: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """
        Computes standard information retrieval / classification metrics:
        TP: Ground truth is vulnerable, model confirmed vulnerable
        FP: Ground truth is safe/benign, model confirmed vulnerable
        TN: Ground truth is safe/benign, model rejected/clean
        FN: Ground truth is vulnerable, model marked clean/rejected
        """
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        # Build lookup by file
        pred_map = {p["file_path"]: p for p in predictions}

        for item in ground_truth:
            fpath = item["file_path"]
            is_truly_vulnerable = item.get("is_vulnerable", False)
            pred = pred_map.get(fpath)

            if not pred:
                if is_truly_vulnerable:
                    fn += 1
                else:
                    tn += 1
                continue

            confirmed_count = pred.get("summary_statistics", {}).get("confirmed_vulnerabilities", 0)
            model_says_vulnerable = confirmed_count > 0

            if is_truly_vulnerable and model_says_vulnerable:
                tp += 1
            elif not is_truly_vulnerable and model_says_vulnerable:
                fp += 1
            elif not is_truly_vulnerable and not model_says_vulnerable:
                tn += 1
            elif is_truly_vulnerable and not model_says_vulnerable:
                fn += 1

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = ((tp + tn) / (tp + tn + fp + fn)) if (tp + tn + fp + fn) > 0 else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        return {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "false_positive_rate": round(fpr, 4),
        }
