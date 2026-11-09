import math

import pytest

from cybershield_ml.evaluation import evaluate_anomaly_scores


def test_evaluate_anomaly_scores_uses_lower_score_as_higher_risk():
    result = evaluate_anomaly_scores(
        [0, 0, 1, 1],
        [0.8, 0.4, -0.2, -0.7],
        threshold=0.0,
    )
    assert result["score_contract"] == "lower_is_more_anomalous"
    assert result["confusion_matrix_0_1"] == [[2, 0], [0, 2]]
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["false_positive_rate"] == 0.0
    assert result["false_negative_rate"] == 0.0
    assert result["alert_count"] == 2
    assert result["alert_rate"] == 0.5
    assert result["roc_auc"] == 1.0


def test_evaluate_anomaly_scores_reports_false_positives_and_misses():
    result = evaluate_anomaly_scores(
        [0, 0, 1, 1],
        [-0.5, 0.5, 0.5, -0.5],
        threshold=0.0,
    )
    assert result["confusion_matrix_0_1"] == [[1, 1], [1, 1]]
    assert result["false_positive_rate"] == 0.5
    assert result["false_negative_rate"] == 0.5
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5


def test_evaluate_anomaly_scores_handles_single_class_without_roc_auc():
    result = evaluate_anomaly_scores([0, 0], [0.1, -0.1], threshold=0.0)
    assert result["roc_auc"] is None
    assert result["false_negative_rate"] is None
    assert result["false_positive_rate"] == 0.5


@pytest.mark.parametrize(
    ("labels", "scores", "threshold"),
    [
        ([], [], 0.0),
        ([0], [], 0.0),
        ([0, 2], [0.1, -0.1], 0.0),
        ([False, 1], [0.1, -0.1], 0.0),
        ([0, 1], [0.1, math.inf], 0.0),
        ([0, 1], [0.1, math.nan], 0.0),
        ([0, 1], [0.1, "bad"], 0.0),
        ([0, 1], [0.1, -0.1], math.inf),
        ([0, 1], [0.1, -0.1], math.nan),
    ],
)
def test_evaluate_anomaly_scores_rejects_invalid_inputs(labels, scores, threshold):
    with pytest.raises((TypeError, ValueError)):
        evaluate_anomaly_scores(labels, scores, threshold)
