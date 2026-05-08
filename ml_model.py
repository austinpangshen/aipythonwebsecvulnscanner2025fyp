import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import matplotlib.pyplot as plt

class train_model:
    # =========================
    # LOAD DATA
    # =========================
    df = pd.read_csv("C:\\Users\\Austin\\FYP New\\dataset.csv")
    print(len(df))

    # =========================
    # FEATURES & LABEL
    # =========================
    features = [
        "payload_length",
        "special_chars",
        "response_length",
        "length_diff",
        "has_script",
        "has_event",
        "has_js_protocol",
        "has_h1",
        "has_basic_html",
        "has_html_tag",
        "error_detected"
    ]

    X = df[features]
    y = df["label"]

    # =========================
    # ENCODE LABELS
    # =========================
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    print("Label Mapping:", dict(zip(le.classes_, le.transform(le.classes_))))

    # =========================
    # TRAIN TEST SPLIT
    # =========================
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # =========================
    # TRAIN MODEL
    # =========================
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)

    # =========================
    # EVALUATE
    # =========================
    y_pred = model.predict(X_test)

    print("\n=== MODEL PERFORMANCE ===")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # =========================
    # FEATURE IMPORTANCE
    # =========================
    importances = model.feature_importances_

    plt.bar(features, importances)
    plt.title("Feature Importance")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # =========================
    # SAVE MODEL
    # =========================
    joblib.dump(model, "model.pkl")
    joblib.dump(le, "label_encoder.pkl")

    print("\n✅ Model saved!")

