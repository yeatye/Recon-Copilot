from __future__ import annotations

from recon_copilot.fuzzing.diff import annotate_anomalies, is_anomalous
from recon_copilot.fuzzing.models import BaselineResponse, FuzzHit

BASELINE = BaselineResponse(status_code=404, body_size=100, response_time_ms=50.0)


def test_same_status_and_size_is_not_anomalous():
    assert is_anomalous(404, 100, 55.0, BASELINE) is False


def test_different_status_is_anomalous():
    assert is_anomalous(200, 100, 50.0, BASELINE) is True


def test_much_larger_body_is_anomalous():
    assert is_anomalous(404, 5000, 50.0, BASELINE) is True


def test_slightly_larger_body_within_tolerance_is_not_anomalous():
    assert is_anomalous(404, 105, 50.0, BASELINE) is False  # 5% de variation, tolerance 15%


def test_missing_status_code_is_anomalous():
    assert is_anomalous(None, None, None, BASELINE) is True


def test_much_slower_response_is_anomalous():
    assert is_anomalous(404, 100, 500.0, BASELINE) is True  # 10x plus lent


def test_annotate_anomalies_marks_correct_hits():
    hits = [
        FuzzHit(payload="/a", status_code=404, body_size=100, response_time_ms=51.0, is_anomaly=False),
        FuzzHit(payload="/b", status_code=200, body_size=9000, response_time_ms=51.0, is_anomaly=False),
    ]
    annotated = annotate_anomalies(hits, BASELINE)
    assert annotated[0].is_anomaly is False
    assert annotated[1].is_anomaly is True


def test_zero_size_baseline_nonzero_response_is_anomalous():
    empty_baseline = BaselineResponse(status_code=200, body_size=0, response_time_ms=10.0)
    assert is_anomalous(200, 500, 10.0, empty_baseline) is True


def test_near_zero_baseline_time_does_not_trigger_time_anomaly():
    # Baseline quasi instantanee (ex: service local tres rapide, mock de test) :
    # sans plancher, un ecart de quelques ms exploserait le ratio pour rien.
    fast_baseline = BaselineResponse(status_code=404, body_size=100, response_time_ms=0.2)
    assert is_anomalous(404, 100, 5.0, fast_baseline) is False


def test_time_anomaly_still_detected_above_floor():
    baseline_above_floor = BaselineResponse(status_code=404, body_size=100, response_time_ms=10.0)
    assert is_anomalous(404, 100, 200.0, baseline_above_floor) is True
