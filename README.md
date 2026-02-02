# BIRDS 🛡️
**BIRDS** stands for **Behavioral Insider Risk Detection System**.

This project is a machine learning-based system that detects insider threats by analyzing employee behavior data.
It generates a daily risk score for each employee and shows the results in a simple interactive dashboard.

---

##  Features
- Detects suspicious (malicious) behavior using ML models
- Generates **risk score** and **risk level** (HIGH / MED / LOW)
- Stores results in a **SQLite database**
- Displays everything in a **Streamlit dashboard**
- Includes alerts management (status + notes)

---

##  Project Files
Main files you will find in this repository:
- `app.py` → Streamlit dashboard
- `run_inference_to_db.py` → runs the model and saves predictions into the database
- `models/` → contains the trained model bundle (`.joblib`)

---




## Authors
Batool Asaad
Alaa Al-Quran
Elaf Almomani

## Supervisor
 Prof. Amin Alqudah