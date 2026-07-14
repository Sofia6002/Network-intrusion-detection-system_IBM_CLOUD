"""
NIDS Streamlit Dashboard

Reads nids_log.jsonl (written by flow_aggregator.py) and displays:
  - Live connection table
  - Highlighted anomaly rows
  - Mitigation panel for the most recent alert
  - Session-local history log

Run with:
    streamlit run dashboard.py

Run this ALONGSIDE flow_aggregator.py (separate terminal) -- the
aggregator writes to nids_log.jsonl, this dashboard polls it.
"""

import streamlit as st
import pandas as pd
import json
import os
import time

LOG_FILE_PATH = "nids_log.jsonl"
REFRESH_INTERVAL_SECONDS = 2

st.set_page_config(page_title="NIDS Dashboard", layout="wide")


def load_log_entries():
    """Read all JSON lines from the log file. Tolerates a half-written
    last line (aggregator might be mid-write) by skipping bad lines."""
    if not os.path.exists(LOG_FILE_PATH):
        return []

    entries = []
    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # likely a partially-flushed last line; skip it
    return entries


# ============================================================
# UI
# ============================================================

st.title("🛡️ Network Intrusion Detection System")
st.caption("Live connection feed, powered by IBM Watson Machine Learning")

entries = load_log_entries()

if not entries:
    st.info("No data yet. Make sure flow_aggregator.py is running in a separate terminal.")
    time.sleep(REFRESH_INTERVAL_SECONDS)
    st.rerun()

df = pd.DataFrame(entries)
df["time"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%H:%M:%S")

total = len(df)
anomalies = (df["prediction"] == "anomaly").sum()
normal = (df["prediction"] == "normal").sum()
failed = (df["prediction"] == "unknown").sum()

# ---- Summary metrics ----
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Connections", total)
col2.metric("🚨 Anomalies", int(anomalies))
col3.metric("✓ Normal", int(normal))
col4.metric("⚠️ Scoring Failures", int(failed))

st.divider()

# ---- Most recent alert panel ----
recent_anomalies = df[df["prediction"] == "anomaly"].tail(1)

if not recent_anomalies.empty:
    latest = recent_anomalies.iloc[-1]
    st.error(
        f"**Latest Alert** — {latest['src_ip']}:{latest['src_port']} → "
        f"{latest['dst_ip']}:{latest['dst_port']} ({latest['protocol']})  "
        f"| Confidence: {latest['confidence']:.1%}\n\n"
        f"**Mitigation:** {latest['mitigation']}"
    )
else:
    st.success("No anomalies detected yet.")

st.divider()

# ---- Live connection table ----
st.subheader("Live Connection Feed")

display_df = df[["time", "src_ip", "src_port", "dst_ip", "dst_port",
                  "protocol", "prediction", "confidence"]].tail(50).iloc[::-1]


def highlight_anomaly(row):
    if row["prediction"] == "anomaly":
        return ["background-color: #ffcccc"] * len(row)
    elif row["prediction"] == "unknown":
        return ["background-color: #fff3cd"] * len(row)
    return [""] * len(row)


st.dataframe(
    display_df.style.apply(highlight_anomaly, axis=1),
    use_container_width=True,
    hide_index=True,
)

st.caption(f"Showing last 50 of {total} connections. Auto-refreshes every {REFRESH_INTERVAL_SECONDS}s.")

# ---- Auto-refresh ----
time.sleep(REFRESH_INTERVAL_SECONDS)
st.rerun()
