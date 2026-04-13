"""
model_train.py — ML model o'qitish (v4 — TO'LIQ TUZATILGAN)

Tuzatishlar:
  1. Class weight (imbalance simulyatsiyasi): BENIGN ko'proq, hujumlar kamroq
     Real trafikda BENIGN ~70-80%, hujumlar 20-30%
  2. Cross-validation qo'shildi (overfitting tekshirish)
  3. Model murakkabligi kamaytirildi: max_depth=6 (8 edi) — overfitting oldini olish
  4. Feature importance chiqariladi — qaysi feature muhimroq ko'rsatadi
  5. Dataset taqsimoti haqiqatga yaqinroq: BENIGN ko'p
  6. Sanity check kengaytirildi
"""
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

MODEL_PATH   = "network_model.pkl"
SCALER_PATH  = "scaler.pkl"
ENCODER_PATH = "label_encoder.pkl"

FEATURES = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_byts_s",
    "flow_pkts_s",
    "pkt_len_mean",
    "fwd_iat_mean",
    "fin_flag_cnt",
]

# Haqiqatga yaqin taqsimlash: BENIGN ko'p, hujumlar kamroq
# Jami ~ 21000 ta yozuv
SAMPLE_COUNTS = {
    "BENIGN":   9000,   # ~43% — real trafikda dominant
    "DNS":      2000,
    "NTP":      2000,
    "SYN":      2000,
    "UDP":      2000,
    "LDAP":     2000,
    "PORTSCAN": 2000,
}


def generate_dataset(seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    records = []

    classes = {
        # Normal HTTP trafik
        "BENIGN": {
            "flow_duration":    (150_000, 50_000),
            "tot_fwd_pkts":     (12,   4),
            "tot_bwd_pkts":     (10,   3),
            "fwd_pkt_len_mean": (600,  200),
            "bwd_pkt_len_mean": (800,  300),
            "flow_byts_s":      (12_000, 4_000),
            "flow_pkts_s":      (18,   6),
            "pkt_len_mean":     (700,  200),
            "fwd_iat_mean":     (80,   25),
            "fin_flag_cnt":     (1,    0.3),
        },
        # DNS amplification DDoS
        "DNS": {
            "flow_duration":    (400,   150),
            "tot_fwd_pkts":     (250,   80),
            "tot_bwd_pkts":     (200,   60),
            "fwd_pkt_len_mean": (75,    15),
            "bwd_pkt_len_mean": (190,   40),
            "flow_byts_s":      (600_000, 80_000),
            "flow_pkts_s":      (400,   80),
            "pkt_len_mean":     (130,   30),
            "fwd_iat_mean":     (1.5,  0.5),
            "fin_flag_cnt":     (0,    0.1),
        },
        # NTP amplification DDoS
        "NTP": {
            "flow_duration":    (600,   200),
            "tot_fwd_pkts":     (120,   40),
            "tot_bwd_pkts":     (450,   100),
            "fwd_pkt_len_mean": (80,    15),
            "bwd_pkt_len_mean": (460,   20),
            "flow_byts_s":      (900_000, 120_000),
            "flow_pkts_s":      (300,   60),
            "pkt_len_mean":     (310,   60),
            "fwd_iat_mean":     (2,    0.8),
            "fin_flag_cnt":     (0,    0.1),
        },
        # SYN flood DDoS
        "SYN": {
            "flow_duration":    (150,   60),
            "tot_fwd_pkts":     (600,   150),
            "tot_bwd_pkts":     (8,    3),
            "fwd_pkt_len_mean": (54,   4),
            "bwd_pkt_len_mean": (58,   4),
            "flow_byts_s":      (1_200_000, 180_000),
            "flow_pkts_s":      (500,   100),
            "pkt_len_mean":     (55,   4),
            "fwd_iat_mean":     (0.8,  0.3),
            "fin_flag_cnt":     (0,    0.1),
        },
        # UDP flood DDoS
        "UDP": {
            "flow_duration":    (250,   80),
            "tot_fwd_pkts":     (500,   100),
            "tot_bwd_pkts":     (4,    2),
            "fwd_pkt_len_mean": (1400, 40),
            "bwd_pkt_len_mean": (80,   20),
            "flow_byts_s":      (1_400_000, 200_000),
            "flow_pkts_s":      (480,   80),
            "pkt_len_mean":     (820,  80),
            "fwd_iat_mean":     (0.9,  0.3),
            "fin_flag_cnt":     (0,    0.1),
        },
        # LDAP amplification DDoS
        "LDAP": {
            "flow_duration":    (900,   300),
            "tot_fwd_pkts":     (280,   80),
            "tot_bwd_pkts":     (550,   120),
            "fwd_pkt_len_mean": (190,   40),
            "bwd_pkt_len_mean": (1150, 180),
            "flow_byts_s":      (750_000, 100_000),
            "flow_pkts_s":      (400,   70),
            "pkt_len_mean":     (870,  120),
            "fwd_iat_mean":     (1.8,  0.7),
            "fin_flag_cnt":     (2,    0.6),
        },
        # PORT SCAN
        "PORTSCAN": {
            "flow_duration":    (2_000,  1_000),
            "tot_fwd_pkts":     (2,      1),
            "tot_bwd_pkts":     (1,      0.8),
            "fwd_pkt_len_mean": (40,     8),
            "bwd_pkt_len_mean": (40,     10),
            "flow_byts_s":      (150_000, 50_000),
            "flow_pkts_s":      (50_000, 15_000),
            "pkt_len_mean":     (40,     8),
            "fwd_iat_mean":     (1.5,    0.8),
            "fin_flag_cnt":     (0,      0.05),
        },
    }

    total = sum(SAMPLE_COUNTS.values())
    for label, params in classes.items():
        n = SAMPLE_COUNTS[label]
        rows = {}
        for feat, (mean, std) in params.items():
            rows[feat] = np.clip(rng.normal(mean, std, n), 0, None)
        rows["label"] = label
        records.append(pd.DataFrame(rows))

    df = (
        pd.concat(records, ignore_index=True)
        .sample(frac=1, random_state=seed)
        .reset_index(drop=True)
    )
    print(f"  Dataset: {len(df)} ta yozuv, {len(classes)} sinf")
    for lbl, cnt in df["label"].value_counts().items():
        pct = cnt / len(df) * 100
        print(f"    {lbl:<12} {cnt:>5} ta  ({pct:.1f}%)")
    return df


def train(df: pd.DataFrame):
    X     = df[FEATURES].values
    y_raw = df["label"].values

    le = LabelEncoder()
    y  = le.fit_transform(y_raw)
    print(f"\n  Sinflar: {dict(zip(le.classes_, range(len(le.classes_))))}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # Klass og'irliklari: BENIGN ko'p bo'lgani uchun weight past, hujumlar uchun yuqori
    # Bu class imbalance ni to'g'rilaydi
    class_counts = np.bincount(y)
    total_samples = len(y)
    n_classes = len(le.classes_)
    class_weights = {i: total_samples / (n_classes * count)
                     for i, count in enumerate(class_counts)}
    sample_weights = np.array([class_weights[yi] for yi in y_train])

    clf = XGBClassifier(
        n_estimators=300,
        max_depth=6,          # 8 edi → overfitting oldini olish uchun 6
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=5,   # 3 edi → underfitting emas, overfitting oldini olish
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    print("\n  O'qitilmoqda...")
    clf.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    y_pred = clf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    print(f"\n  Test aniqlik: {acc * 100:.2f}%")
    print("\n  Sinf bo'yicha hisobot:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Cross-validation (overfitting tekshirish)
    print("  Cross-validation (5-fold) baholanmoqda...")
    X_all_scaled = scaler.transform(X)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_all_scaled, y, cv=cv, scoring="accuracy", n_jobs=-1)
    print(f"  CV scores: {cv_scores.round(4)}")
    print(f"  CV o'rtacha: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    if abs(acc - cv_scores.mean()) > 0.05:
        print("  [OGOHLANTIRISH] Test aniqlik va CV o'rtacha orasida katta farq — overfitting bo'lishi mumkin!")

    # Feature importance
    print("\n  Feature ahamiyati:")
    importances = clf.feature_importances_
    for feat, imp in sorted(zip(FEATURES, importances), key=lambda x: -x[1]):
        bar = "█" * int(imp * 50)
        print(f"    {feat:<22} {imp:.4f}  {bar}")

    joblib.dump(clf,    MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODER_PATH)
    print(f"\n  Model    → {MODEL_PATH}")
    print(f"  Scaler   → {SCALER_PATH}")
    print(f"  Encoder  → {ENCODER_PATH}")

    # Sanity check
    print("\n  [SANITY CHECK] flow_pkts_s qiymatlari:")
    for lbl in ["BENIGN", "SYN", "UDP", "DNS", "PORTSCAN"]:
        mask = df["label"] == lbl
        mean_pkts = df.loc[mask, "flow_pkts_s"].mean()
        print(f"    {lbl:<12} mean flow_pkts_s = {mean_pkts:>10.1f}")

    # Feature range
    print("\n  [DEBUG] Feature range (original scale):")
    print(f"  {'Feature':<22} {'Min':>12} {'Mean':>12} {'Max':>12}")
    for i, feat in enumerate(FEATURES):
        col = X[:, i]
        print(f"  {feat:<22} {col.min():>12.1f} {col.mean():>12.1f} {col.max():>12.1f}")


def main():
    if sys.version_info < (3, 9):
        sys.exit("Python 3.9+ kerak.")

    print("=" * 60)
    print("  IDS/IPS — ML Model O'qitish  (v4 — TO'LIQ TUZATILGAN)")
    print("=" * 60)

    print("\n1/2 — Dataset yaratilmoqda...")
    df = generate_dataset()

    print("\n2/2 — Model o'qitilmoqda...")
    train(df)

    print("\n" + "=" * 60)
    print("  Tayyor! Endi: python main.py")
    print("=" * 60)


if __name__ == "__main__":
    main()