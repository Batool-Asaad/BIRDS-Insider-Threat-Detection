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

##  Installation
1) Clone the repository:
```bash
git clone <your-repo-link>
cd BIRDS

2. Install requirements:
    pip install -r requirements.txt


 How to Run
1. Generate predictions and fill the database: 
    python run_inference_to_db.py
2. Run the dashboard:
    streamlit run app.py


Model

The main model used in this project is XGBoost.
The model outputs a probability of malicious behavior, and we use a tuned threshold to classify the final label.


Database

The system uses a local SQLite database:
insider_threat.db

It stores:
predictions (risk score / risk level)
alerts (status / notes)


Authors

Batool Asaad

Alaa Al-Quran

Elaf Almomani

Supervisor: Prof. Amin Alqudah