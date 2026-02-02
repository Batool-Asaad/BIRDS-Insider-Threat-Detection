import sqlite3
import pandas as pd
import numpy as np
import joblib
from datetime import datetime

RAW_PATH = "insider_threat_dataset.csv"
PROCESSED_PATH = "insider_threat_dataset_processed.csv"
BUNDLE_PATH = "birds_xgb_bundle.joblib"
DB_PATH = "insider_threat.db"

def create_tables(conn: sqlite3.Connection):
    conn.executescript("""
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS predictions (
      employee_id INTEGER NOT NULL,
      day TEXT NOT NULL,                 -- YYYY-MM-DD
      risk_score REAL NOT NULL,
      risk_level TEXT NOT NULL,          -- LOW/MED/HIGH
      created_at TEXT NOT NULL,
      PRIMARY KEY (employee_id, day)
    );

    CREATE TABLE IF NOT EXISTS alerts (
      employee_id INTEGER NOT NULL,
      day TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'OPEN',
      notes TEXT,
      updated_at TEXT,
      PRIMARY KEY (employee_id, day),
      FOREIGN KEY (employee_id, day) REFERENCES predictions(employee_id, day)
    );

    CREATE INDEX IF NOT EXISTS idx_predictions_day ON predictions(day);
    CREATE INDEX IF NOT EXISTS idx_predictions_risk ON predictions(risk_level, risk_score);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    """)

def risk_level(score: float, high_th: float, med_th: float) -> str:
    if score >= high_th:
        return "HIGH"
    if score >= med_th:
        return "MED"
    return "LOW"

def main():

    # Load bundle (model + scaler + feature order + thresholds)

    bundle = joblib.load(BUNDLE_PATH)
    model = bundle["model"]
    scaler = bundle["scaler"]
    expected = bundle["feature_names"]
    numerical_features = bundle["numerical_features"]
    HIGH_TH = float(bundle.get("high_th", 0.80))
    MED_TH  = float(bundle.get("med_th", 0.50))

    
    # Read raw keys (employee_id + date)
   
    df_raw = pd.read_csv(RAW_PATH)
    if "employee_id" not in df_raw.columns or "date" not in df_raw.columns:
        raise ValueError("RAW file must contain employee_id and date columns.")

    keys = df_raw[["employee_id", "date"]].copy()
    keys["day"] = pd.to_datetime(keys["date"], errors="coerce").dt.strftime("%Y-%m-%d")
    keys = keys.drop(columns=["date"])


    # Read processed features
    
    df_proc = pd.read_csv(PROCESSED_PATH)

    if len(df_proc) != len(keys):
        raise ValueError(
            f"Row count mismatch: processed={len(df_proc)} vs raw_keys={len(keys)}. "
            "This means preprocessing changed rows/order."
        )

    
    # Prepare X
    
    if "is_emp_malicious" in df_proc.columns:
        X = df_proc.drop(columns=["is_emp_malicious"])
    else:
        X = df_proc.copy()

    
    
    for col in expected:
        if col not in X.columns:
            X[col] = 0


    extra = [c for c in X.columns if c not in expected]
    if extra:
        X = X.drop(columns=extra)

    X = X[expected]

    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    
    X[numerical_features] = scaler.transform(X[numerical_features])



    # Predict
    proba = model.predict_proba(X)[:, 1].astype(float)
    levels = np.array([risk_level(s, HIGH_TH, MED_TH) for s in proba], dtype=object)

    
    # results table
    results = keys.copy()
    results["risk_score"] = proba
    results["risk_level"] = levels
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    results["created_at"] = now

    
    #  Insert into SQLite
    conn = sqlite3.connect(DB_PATH)
    try:
        create_tables(conn)
        cur = conn.cursor()

        cur.executemany(
            """
            INSERT OR REPLACE INTO predictions(employee_id, day, risk_score, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            results[["employee_id", "day", "risk_score", "risk_level", "created_at"]].itertuples(index=False, name=None)
        )

        high_rows = results[results["risk_level"] == "HIGH"][["employee_id", "day"]].copy()
        high_rows["updated_at"] = now

        cur.executemany(
            """
            INSERT OR IGNORE INTO alerts(employee_id, day, status, notes, updated_at)
            VALUES (?, ?, 'OPEN', NULL, ?)
            """,
            high_rows[["employee_id", "day", "updated_at"]].itertuples(index=False, name=None)
        )

        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
