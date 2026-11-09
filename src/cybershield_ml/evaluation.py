import math

from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)


def evaluate(y_true: list[int], y_pred: list[int]) -> dict:
    if not y_true or len(y_true) != len(y_pred):
        raise ValueError("labels must have equal non-zero lengths")
    return {
        "report": classification_report(
            y_true, y_pred, labels=[0, 1], output_dict=True, zero_division=0
        ),
        "confusion_matrix_0_1": confusion_matrix(
            y_true, y_pred, labels=[0, 1]
        ).tolist(),
    }


def evaluate_anomaly_scores(
    y_true: list[int],
    decision_scores: list[float],
    threshold: float,
) -> dict:
    """Evaluate IsolationForest-style decision scores on held-out labelled data.

    Label contract: 0 = benign, 1 = malicious/suspicious.
    Score contract: lower decision scores indicate greater anomaly risk.
    A sample is flagged when decision_score < threshold.
    This reports predictive performance, not proof that an event is malicious.
    """
    if not isinstance(y_true, list) or not isinstance(decision_scores, list):
        raise ValueError("y_true and decision_scores must be lists")
    if not y_true or len(y_true) != len(decision_scores):
        raise ValueError("labels and decision scores must have equal non-zero lengths")
    if any(type(label) is not int or label not in (0, 1) for label in y_true):
        raise ValueError("labels must contain only integer values 0 or 1")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("threshold must be a finite number")
    if not math.isfinite(float(threshold)):
        raise ValueError("threshold must be a finite number")
    scores: list[float] = []
    for score in decision_scores:
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ValueError("decision scores must be finite numbers")
        value = float(score)
        if not math.isfinite(value):
            raise ValueError("decision scores must be finite numbers")
        scores.append(value)

    predictions = [int(score < float(threshold)) for score in scores]
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(value) for value in matrix.ravel()
    )
    total = len(y_true)
    positives = sum(y_true)
    negatives = total - positives
    precision = true_positive / (true_positive + false_positive) if (
        true_positive + false_positive
    ) else 0.0
    recall = true_positive / positives if positives else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (
        precision + recall
    ) else 0.0

    result = {
        "label_contract": {"0": "benign", "1": "malicious_or_suspicious"},
        "score_contract": "lower_is_more_anomalous",
        "threshold_operator": "decision_score < threshold",
        "threshold": float(threshold),
        "sample_count": total,
        "positive_count": positives,
        "negative_count": negatives,
        "confusion_matrix_0_1": matrix.tolist(),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": (
            false_positive / negatives if negatives else None
        ),
        "false_negative_rate": (
            false_negative / positives if positives else None
        ),
        "alert_count": sum(predictions),
        "alert_rate": sum(predictions) / total,
        "average_precision": (\n            average_precision_score(y_true, [-s for s in scores]) if positives else None\n        ),
        "roc_auc": roc_auc_score(y_true, [-s for s in scores]) if len(set(y_true)) == 2 else None,
        "interpretation": (
            "Anomaly scores are triage signals; they do not establish malicious activity."
        ),
    }
    return result
