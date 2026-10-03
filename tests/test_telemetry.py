"""
Unit Tests for Telemetry and Metrics
"""

from src.telemetry.metrics import TelemetryMetrics


def test_metrics_calculation_perfect_run():
    ground_truth = [
        {"file_path": "a.py", "is_vulnerable": True},
        {"file_path": "b.py", "is_vulnerable": False},
    ]
    predictions = [
        {"file_path": "a.py", "summary_statistics": {"confirmed_vulnerabilities": 1}},
        {"file_path": "b.py", "summary_statistics": {"confirmed_vulnerabilities": 0}},
    ]

    metrics = TelemetryMetrics.calculate_benchmark_metrics(ground_truth, predictions)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["false_positive_rate"] == 0.0


def test_metrics_with_false_positive():
    ground_truth = [
        {"file_path": "a.py", "is_vulnerable": False},
    ]
    predictions = [
        {"file_path": "a.py", "summary_statistics": {"confirmed_vulnerabilities": 1}},
    ]

    metrics = TelemetryMetrics.calculate_benchmark_metrics(ground_truth, predictions)
    assert metrics["precision"] == 0.0
    assert metrics["false_positives"] == 1
