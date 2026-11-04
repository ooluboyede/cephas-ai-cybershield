from sklearn.metrics import classification_report, confusion_matrix

def evaluate(y_true: list[int], y_pred: list[int]) -> dict:
    if not y_true or len(y_true) != len(y_pred):
        raise ValueError("labels must have equal non-zero lengths")
    return {"report": classification_report(y_true, y_pred, labels=[0, 1],
            output_dict=True, zero_division=0),
            "confusion_matrix_0_1": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()}
