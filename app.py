# app.py — Streamlit Dashboard (SQLite) for Insider Threat Detection (XGBoost)
# Compatible with DB schema created by run_inference_to_db.py:
#   predictions(employee_id, day, risk_score, risk_level, created_at)
#   alerts(employee_id, day, status, notes, updated_at)

from __future__ import annotations
import os
import sqlite3
from datetime import datetime, timedelta
import pandas as pd
import streamlit as st
import plotly.express as px
import hashlib



# Config

APP_TITLE = "BIRDS"
APP_SUBTITLE = "Behavioral Insider Risk Detection System"

# Robust DB path (same folder as this app.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "insider_threat.db")

DEFAULT_DAYS = 30
RISK_ORDER = ["HIGH", "MED", "LOW"]

def normalize_level(x: str) -> str:
    x = (x or "").strip().upper()
    return x if x in {"HIGH", "MED", "LOW"} else "LOW"



# Streamlit page setup + Styling

st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")

CUSTOM_CSS = """
<style>

.stApp {
  background: radial-gradient(1200px 800px at 20% 0%, rgba(90, 160, 255, 0.10), transparent 50%),
              radial-gradient(1000px 700px at 100% 20%, rgba(255, 70, 120, 0.10), transparent 45%),
              linear-gradient(180deg, #0B1220 0%, #0A0F1C 100%);
  color: #D1D5DB;
}
h1, h2, h3, h4 { letter-spacing: 0.2px; }
.small-muted { color: rgba(230, 238, 249); font-size: 0.95rem; }

.card {
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px;
  padding: 16px 16px 12px 16px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.25);
}
.card-title { color: rgba(230, 238, 249, 0.7); font-size: 0.9rem; margin-bottom: 6px; }
.card-value { font-size: 1.8rem; font-weight: 700; line-height: 1.1; }
.card-sub { color: rgba(230, 238, 249, 0.55); font-size: 0.85rem; margin-top: 8px; }

.pill {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 0.85rem;
  border: 1px solid rgba(255,255,255,0.12);
  background: rgba(255,255,255,0.04);
  margin-right: 6px;
  margin-top: 6px;
}
.pill-high { border-color: rgba(255, 70, 120, 0.45); background: rgba(255, 70, 120, 0.12); }
.pill-med  { border-color: rgba(255, 180, 80, 0.45);  background: rgba(255, 180, 80, 0.12); }
.pill-low  { border-color: rgba(90, 210, 140, 0.45);  background: rgba(90, 210, 140, 0.10); }

section[data-testid="stSidebar"] {
  background: rgba(255,255,255,0.02);
  border-right: 1px solid rgba(255,255,255,0.06);
  color: #E5E7EB !important;
}




/* Radio buttons text */
section[data-testid="stSidebar"] div[role="radiogroup"] label {
  #color: #E5E7EB !important;
  opacity: 1 !important;
  font-weight: 500;
}

/* Slider labels (numbers + text) */
section[data-testid="stSidebar"] .stSlider label,
section[data-testid="stSidebar"] .stSlider span {
  color: #F9FAFB !important;
  opacity: 1 !important;
}

/* Captions under sliders */
section[data-testid="stSidebar"] .stCaption,
section[data-testid="stSidebar"] small {
  color: #D1D5DB !important;
  opacity: 1 !important;
}

/* Checkbox & toggle text */
section[data-testid="stSidebar"] label span {
  color: #F9FAFB !important;
  opacity: 1 !important;
}

/* Dropdown (selectbox) text */
section[data-testid="stSidebar"] div[data-baseweb="select"] * {
  color: #000000 !important;
}



.stForm.st-emotion-cache-1bcyifm.emjbblw1 {
    width: 500px;
}


.st-emotion-cache-1jsf23j p, .st-emotion-cache-1jsf23j ol, .st-emotion-cache-1jsf23j ul, .st-emotion-cache-1jsf23j dl, .st-emotion-cache-1jsf23j li {
    font-size: inherit;
    color: #ffffff;
}

button:not(:disabled), [role="button"]:not(:disabled) {
    cursor: pointer;
    color: black;
}
button.st-emotion-cache-5qfegl.e1q4kxr47:hover {
    background-color: #f0f2f6b0;
}

header.stAppHeader.st-emotion-cache-1v51wz1.e1o8oa9v1 {
    display: none;
}


.st-b8.st-bn.st-bo.st-bp.st-bq.st-br.st-bs.st-bt.st-bu.st-bv.st-bw {
    color: #F9FAFB;
}


label.st-emotion-cache-1s2v671.e1gk92lc0 {
    color: #d1d5db;
}

</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)



# DB helpers

def get_conn() -> sqlite3.Connection:
    # Read-only mode if possible (prevents locking issues); fallback to normal if needed.
    if os.path.exists(DB_PATH):
        try:
            return sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
        except Exception:
            pass
    return sqlite3.connect(DB_PATH, check_same_thread=False)

@st.cache_data(ttl=10)
def read_df(query: str, params: tuple | None = None) -> pd.DataFrame:
    conn = get_conn()
    try:
        return pd.read_sql_query(query, conn, params=params)
    finally:
        conn.close()

def exec_sql(query: str, params: tuple | None = None) -> None:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        cur = conn.cursor()
        cur.execute(query, params or ())
        conn.commit()
    finally:
        conn.close()



# Queries 

def q_latest_day() -> str | None:
    df = read_df("SELECT MAX(day) AS latest_day FROM predictions")
    if df.empty or pd.isna(df.loc[0, "latest_day"]):
        return None
    return str(df.loc[0, "latest_day"])

def q_summary_counts(date_from: str, date_to: str) -> pd.DataFrame:
    return read_df(
        """
        SELECT
          risk_level,
          COUNT(DISTINCT employee_id) AS users_count,
          COUNT(*) AS events_count
        FROM predictions
        WHERE day BETWEEN ? AND ?
        GROUP BY risk_level
        """,
        (date_from, date_to),
    )

def q_daily_trend(date_from: str, date_to: str) -> pd.DataFrame:
    return read_df(
        """
        SELECT
          day,
          COUNT(*) AS total_predictions,
          SUM(CASE WHEN risk_level='HIGH' THEN 1 ELSE 0 END) AS high_events,
          SUM(CASE WHEN risk_level='MED'  THEN 1 ELSE 0 END) AS med_events,
          SUM(CASE WHEN risk_level='LOW'  THEN 1 ELSE 0 END) AS low_events,
          AVG(risk_score) AS avg_risk
        FROM predictions
        WHERE day BETWEEN ? AND ?
        GROUP BY day
        ORDER BY day
        """,
        (date_from, date_to),
    )

def q_top_employees(latest_day: str, limit: int) -> pd.DataFrame:
    return read_df(
        f"""
        SELECT
          employee_id,
          risk_score,
          risk_level
        FROM predictions
        WHERE day = ?
        ORDER BY risk_score DESC
        LIMIT {int(limit)}
        """,
        (latest_day,),
    )

def q_alerts(limit: int, status: str | None = None) -> pd.DataFrame:
    if status:
        return read_df(
            f"""
            SELECT
              a.employee_id,
              a.day,
              a.status,
              a.notes,
              a.updated_at,
              p.risk_score,
              p.risk_level
            FROM alerts a
            JOIN predictions p
              ON p.employee_id = a.employee_id AND p.day = a.day
            WHERE a.status = ?
            ORDER BY a.day DESC, p.risk_score DESC
            LIMIT {int(limit)}
            """,
            (status,),
        )
    return read_df(
        f"""
        SELECT
          a.employee_id,
          a.day,
          a.status,
          a.notes,
          a.updated_at,
          p.risk_score,
          p.risk_level
        FROM alerts a
        JOIN predictions p
          ON p.employee_id = a.employee_id AND p.day = a.day
        ORDER BY a.day DESC, p.risk_score DESC
        LIMIT {int(limit)}
        """
    )

def q_employee_list() -> pd.DataFrame:
    return read_df("SELECT DISTINCT employee_id FROM predictions ORDER BY employee_id")

def q_employee_history(employee_id: int, date_from: str, date_to: str) -> pd.DataFrame:
    return read_df(
        """
        SELECT day, risk_score, risk_level
        FROM predictions
        WHERE employee_id = ? AND day BETWEEN ? AND ?
        ORDER BY day
        """,
        (employee_id, date_from, date_to),
    )

def q_employee_recent(employee_id: int, limit: int = 60) -> pd.DataFrame:
    return read_df(
        f"""
        SELECT day, risk_score, risk_level
        FROM predictions
        WHERE employee_id = ?
        ORDER BY day DESC
        LIMIT {int(limit)}
        """,
        (employee_id,),
    )



# UI helpers

def pill(level: str) -> str:
    lvl = normalize_level(level)
    if lvl == "HIGH":
        return "<span class='pill pill-high'>🔴 HIGH</span>"
    if lvl == "MED":
        return "<span class='pill pill-med'>🟠 MED</span>"
    return "<span class='pill pill-low'>🟢 LOW</span>"

def card(title: str, value: str, sub: str = "", tone: str = "neutral"):
    tone_class = "pill"
    if tone == "high":
        tone_class = "pill pill-high"
    elif tone == "med":
        tone_class = "pill pill-med"
    elif tone == "low":
        tone_class = "pill pill-low"

    st.markdown(
        f"""
        <div class="card">
          <div class="card-title">{title}</div>
          <div class="card-value">{value}</div>
          <div class="card-sub"><span class="{tone_class}">{sub}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

def render_header():
    left, right = st.columns([0.68, 0.32])
    with left:
        st.markdown(f"# 🛡️ {APP_TITLE}")
        st.markdown(f"<div class='small-muted'>{APP_SUBTITLE}</div>", unsafe_allow_html=True)
    


# Pages

def page_overview():
    st.markdown("## Overview")
    st.markdown("<div class='small-muted'>Summary cards, risk distribution, activity trends, top suspicious employees, and recent alerts.</div>", unsafe_allow_html=True)

    latest_day = q_latest_day()
    if not latest_day:
        st.error("No predictions found in the database. Make sure run_inference_to_db.py ran successfully and insider_threat.db exists next to app.py.")
        return

    # Sidebar filters
    with st.sidebar:
        st.markdown("### Filters")
        days = st.slider("Time window (days)", 7, 180, DEFAULT_DAYS, step=1)
        date_to = datetime.strptime(latest_day, "%Y-%m-%d").date()
        date_from = (date_to - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        date_to_str = date_to.strftime("%Y-%m-%d")
        st.caption(f"Range: **{date_from} → {date_to_str}**")
        top_n = st.slider("Top suspicious employees", 5, 30, 10, step=1)

    counts = q_summary_counts(date_from, date_to_str)

    def get_count(level: str, col: str) -> int:
        if counts.empty:
            return 0
        return int(counts.loc[counts["risk_level"].astype(str).str.upper() == level, col].sum())

    users_high = get_count("HIGH", "users_count")
    users_med  = get_count("MED", "users_count")
    users_low  = get_count("LOW", "users_count")
    total_events = int(counts["events_count"].sum()) if not counts.empty else 0

    # Cards row
    c1, c2, c3, c4 = st.columns(4)
    with c1: card("High-risk employees", f"{users_high}", "Immediate review", "high")
    with c2: card("Medium-risk employees", f"{users_med}", "Monitor closely", "med")
    with c3: card("Normal employees", f"{users_low}", "Baseline behavior", "low")
    with c4: card("Total events", f"{total_events:,}", f"Window: {days} days", "neutral")

    st.markdown("")

    # Charts: Pie + Trend
    left, right = st.columns([0.45, 0.55], gap="large")

    with left:
        st.markdown("### Risk Distribution")
        pie_df = counts.copy()
        if pie_df.empty:
            pie_df = pd.DataFrame({"risk_level": ["LOW", "MED", "HIGH"], "users_count": [0, 0, 0]})
        pie_df["risk_level"] = pie_df["risk_level"].astype(str).str.upper()
        pie_df["risk_level"] = pd.Categorical(pie_df["risk_level"], categories=RISK_ORDER, ordered=True)
        pie_df = pie_df.sort_values("risk_level")

        COLOR_MAP = {
            "LOW": "#1E88E5",   
            "MED": "#FB8C00",    
            "HIGH": "#E53935",   
        }

        fig_pie = px.pie(
            pie_df,
            names="risk_level",
            values="users_count",
            hole=0.55,
            color="risk_level",
            color_discrete_map=COLOR_MAP,
        )
        fig_pie.update_layout(
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend_title_text="Risk Level",
            legend=dict(
                font=dict(
                    color="white",
                    size=13
                )
            )
        )

        st.plotly_chart(fig_pie, width="stretch")  # updated

    with right:
        st.markdown("### Suspicious Events Over Time")
        trend = q_daily_trend(date_from, date_to_str)
        if trend.empty:
            st.info("No trend data for selected window.")
        else:
            fig_line = px.line(trend, x="day", y=["high_events", "med_events"], markers=True)
            fig_line.update_layout(
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                legend_title_text="Event Type",
                yaxis_title="Count",
                xaxis_title="Day",
            )
            st.plotly_chart(fig_line, width="stretch")  # updated

    st.markdown("")

    # Top suspicious + Alerts
    bottom_left, bottom_right = st.columns([0.62, 0.38], gap="large")

    with bottom_left:
        st.markdown("### Top Suspicious Employees (Latest Day)")
        top_df = q_top_employees(latest_day, top_n)
        if top_df.empty:
            st.info("No data for latest day.")
        else:
            show = top_df.copy()
            show["risk_level"] = show["risk_level"].astype(str).str.upper().map(normalize_level)
            show["risk_score"] = show["risk_score"].astype(float).round(4)
            show["risk"] = show["risk_level"].apply(lambda x: "🔴 HIGH" if x=="HIGH" else ("🟠 MED" if x=="MED" else "🟢 LOW"))
            show = show[["employee_id", "risk_score", "risk"]]
            show.rename(columns={"employee_id": "employee_id"}, inplace=True)
            st.dataframe(show, width="stretch", hide_index=True)  # updated

    with bottom_right:
        st.markdown("### Recent Alerts")
        only_open = st.toggle("Show OPEN only", value=True)
        alerts_df = q_alerts(limit=12, status="OPEN" if only_open else None)

        if alerts_df.empty:
            st.success("No alerts to display")
        else:
            for _, row in alerts_df.iterrows():
                lvl = normalize_level(str(row["risk_level"]))
                st.markdown(
                    f"""
                    <div class="card">
                      <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                          <div style="font-weight:700;">Employee: {int(row['employee_id'])}</div>
                          <div class="small-muted">Day: {row['day']} • Score: {float(row['risk_score']):.4f}</div>
                        </div>
                        <div>{pill(lvl)}</div>
                      </div>
                      <div class="card-sub">
                        <span class="pill">Status: {row['status']}</span>
                      </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


def page_employee_details():
    st.markdown("## Employee Details")
    st.markdown("<div class='small-muted'>Select an employee_id to inspect risk history and pattern over time.</div>", unsafe_allow_html=True)

    latest_day = q_latest_day()
    if not latest_day:
        st.error("No predictions found in the database.")
        return

    emp_list = q_employee_list()
    if emp_list.empty:
        st.error("No employee_id values found in predictions.")
        return

    with st.sidebar:
        st.markdown("### Employee Filter")
        employee_id = st.selectbox("employee_id", emp_list["employee_id"].astype(int).tolist())

        days = st.slider("History window (days)", 7, 365, DEFAULT_DAYS, step=1, key="emp_days")
        date_to = datetime.strptime(latest_day, "%Y-%m-%d").date()
        date_from = (date_to - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        date_to_str = date_to.strftime("%Y-%m-%d")
        st.caption(f"Range: **{date_from} → {date_to_str}**")

    hist = q_employee_history(int(employee_id), date_from, date_to_str)

    if hist.empty:
        st.info("No history for selected employee in this window.")
        return

    hist["risk_level"] = hist["risk_level"].astype(str).str.upper().map(normalize_level)
    hist["risk_score"] = hist["risk_score"].astype(float)

    last = hist.iloc[-1]
    k1, k2, k3 = st.columns(3)
    with k1:
        card("Latest risk score", f"{float(last['risk_score']):.4f}", f"Day: {last['day']}", "neutral")
    with k2:
        lvl = normalize_level(str(last["risk_level"]))
        card("Latest risk level", f"{lvl}", "Current classification", "high" if lvl=="HIGH" else ("med" if lvl=="MED" else "low"))
    with k3:
        high_days = int((hist["risk_level"] == "HIGH").sum())
        card("High-risk days (window)", f"{high_days}", f"Last {days} days", "high" if high_days else "neutral")

    st.markdown("")

    st.markdown("### Risk Trend")
    fig = px.line(hist, x="day", y="risk_score", markers=True)
    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis_title="Risk Score",
        xaxis_title="Day",
    )
    st.plotly_chart(fig, width="stretch")  # updated

    st.markdown("")

    st.markdown("### Recent Predictions")
    recent = q_employee_recent(int(employee_id), limit=40)
    if not recent.empty:
        recent["risk_level"] = recent["risk_level"].astype(str).str.upper().map(normalize_level)
        recent["risk_score"] = recent["risk_score"].astype(float).round(4)
        recent["risk"] = recent["risk_level"].apply(lambda x: "🔴 HIGH" if x=="HIGH" else ("🟠 MED" if x=="MED" else "🟢 LOW"))
        recent = recent[["day", "risk_score", "risk"]]
        st.dataframe(recent, width="stretch", hide_index=True)  # updated
    else:
        st.info("No recent predictions found.")


def page_alerts():
    st.markdown("## Alerts Management")
    st.markdown("<div class='small-muted'>Review alerts, update status, and add investigation notes.</div>", unsafe_allow_html=True)

    df = q_alerts(limit=500, status=None)
    if df.empty:
        st.success("No alerts available.")
        return

    # Filters
    with st.sidebar:
        st.markdown("### Alert Filters")
        status_filter = st.multiselect("Status", ["OPEN", "INVESTIGATING", "CLOSED"], default=["OPEN", "INVESTIGATING"])
        risk_filter = st.multiselect("Risk Level", ["HIGH", "MED", "LOW"], default=["HIGH", "MED"])
        max_rows = st.slider("Max rows", 20, 300, 120, step=10)

    df["status"] = df["status"].astype(str).str.upper()
    df["risk_level"] = df["risk_level"].astype(str).str.upper().map(normalize_level)

    df = df[df["status"].isin(status_filter) & df["risk_level"].isin(risk_filter)].head(max_rows)

    st.markdown("### Alerts Table")
    show = df.copy()
    show["risk_score"] = show["risk_score"].astype(float).round(4)
    show = show[["employee_id", "day", "risk_score", "risk_level", "status", "notes", "updated_at"]]
    st.dataframe(show, width="stretch", hide_index=True)  # updated

    st.markdown("---")
    st.markdown("### Update an Alert")

    # Select alert key (employee_id, day)
    keys = df[["employee_id", "day"]].drop_duplicates()
    if keys.empty:
        st.info("No alerts match your filters.")
        return

    keys["label"] = keys.apply(lambda r: f"Employee {int(r['employee_id'])} • {r['day']}", axis=1)
    label_to_key = {row["label"]: (int(row["employee_id"]), str(row["day"])) for _, row in keys.iterrows()}

    chosen_label = st.selectbox("Select alert", keys["label"].tolist())
    emp_id, day = label_to_key[chosen_label]

    current = df[(df["employee_id"] == emp_id) & (df["day"] == day)].iloc[0]

    col1, col2 = st.columns([0.36, 0.64])
    with col1:
        st.markdown(
            f"""
            <div class="card">
              <div class="card-title">Selected Alert</div>
              <div style="font-weight:700; font-size:1.05rem;">Employee: {emp_id}</div>
              <div class="small-muted">Day: {day} • Score: {float(current['risk_score']):.4f}</div>
              <div style="margin-top:10px;">{pill(str(current['risk_level']))}</div>
              <div class="card-sub">
                <span class="pill">Status: {str(current['status']).upper()}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        new_status = st.selectbox(
            "New Status",
            ["OPEN", "INVESTIGATING", "CLOSED"],
            index=["OPEN", "INVESTIGATING", "CLOSED"].index(str(current["status"]).upper())
        )
        new_notes = st.text_area("Notes", value="" if pd.isna(current["notes"]) else str(current["notes"]), height=120)

        if st.button("Save Update", type="primary"):
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            exec_sql(
                """
                UPDATE alerts
                SET status = ?, notes = ?, updated_at = ?
                WHERE employee_id = ? AND day = ?
                """,
                (new_status, new_notes, now, emp_id, day),
            )
            st.cache_data.clear()
            st.success("Alert updated successfully")






# App entry


render_header()

if not os.path.exists(DB_PATH):
    st.error(f"Database file not found: {DB_PATH}\n\nPut insider_threat.db in the same folder as app.py.")
    st.stop()


with st.sidebar:
    st.markdown("## Navigation")
    page = st.radio("Go to", ["Overview", "Employee Details", "Alerts"], index=0)
    st.markdown("---")

if page == "Overview":
    page_overview()
elif page == "Employee Details":
    page_employee_details()
else:
    page_alerts()
