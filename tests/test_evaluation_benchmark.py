"""Tests validating the 30-fixture evaluation benchmark suite."""
from benchmark.run_benchmark import execute_full_benchmark


def test_30_fixture_benchmark_execution_and_thresholds():
    summary, report_md = execute_full_benchmark()

    assert summary["total_fixtures"] == 30
    # Security guarantees
    assert summary["zero_leakage_rate"] == 100.0
    assert summary["immutability_rate"] == 100.0
    # Performance metrics
    assert summary["precision"] >= 0.85
    assert summary["recall"] >= 0.85
    assert summary["f1_score"] >= 0.85
    # Markdown report generated
    assert "# SafeDrop — 30-Fixture Evaluation Benchmark Report" in report_md
    assert "Executive Metrics Summary" in report_md
