# Network Intrusion Detection System (NIDS)

Binary ML-based Network Intrusion Detection System (Normal/Anomaly) built on NSL-KDD. Uses IBM Watson Studio AutoAI for model training, Watson Machine Learning for live REST scoring, a custom Scapy-based flow aggregator to reconstruct features from real traffic, and a Streamlit dashboard for live alerts and mitigation guidance.

## Overview

A Network Intrusion Detection System (NIDS) analyzes network traffic to identify malicious activity. This project builds an ML-based NIDS that classifies live-captured network connections as **Normal** or **Anomaly** in real time, using IBM Cloud Lite services end-to-end as required by the assignment (Problem Statement No. 40).

## ⚠️ Important: Scoping Decision 

The original problem statement describes classifying traffic into DoS, Probe, R2L, and U2R attack categories, but links to the Kaggle dataset `sampadab17/network-intrusion-detection`. That dataset's `class` column contains **only `normal`/`anomaly` labels** — the original per-attack-type labels were already collapsed to binary before this CSV was published, so a 4-category classifier cannot be produced from it.

**Decision:** this project follows the dataset as explicitly linked and implements **binary anomaly detection** (Normal vs. Anomaly). This is a deliberate, documented scoping decision — not an oversight — made because the explicitly linked dataset takes precedence over the prose description when the two conflict.

## Architecture
NIC (Wi-Fi/Ethernet)
│
▼
Scapy Sniffer  ──  captures raw packets
│
▼
Flow Aggregator

keys connections by (src_ip, dst_ip, dst_port, protocol)
2-second rolling window (time-based features)
last-100-connections-per-host window (host-based features)
fills 13 Content features with safe defaults
emits a 40-field vector matching the trained model's schema
│
▼  REST call
IBM Watson Machine Learning — live scoring endpoint
│
▼
Static Mitigation Lookup Table  ──  operator-facing recommendation only
│
▼
Streamlit Dashboard  ──  live feed, alert panel, mitigation display

## Tech Stack

**Cloud layer (IBM Cloud Lite — mandatory)**
- Watson Studio — AutoAI (automated pipeline search on `Train_data.csv`)
- Cloud Object Storage (COS) — backing storage for the AutoAI project
- Watson Machine Learning (WML) — live REST scoring endpoint

**Local layer**
- Python 3.11+
- Scapy — raw packet capture (Npcap on Windows)
- Streamlit — live dashboard

## Feature Reconstruction

NSL-KDD has 41 features across 4 groups. This project reconstructs **28 of 41** from live traffic:

| Group | Count | Live-derivable? |
|---|---|---|
| Basic (duration, protocol_type, service, flag, bytes, etc.) | 9 | ✅ Yes |
| Time-based (count, serror_rate, same_srv_rate, etc.) | 9 | ✅ Yes, via flow aggregator |
| Host-based (dst_host_count, dst_host_srv_count, etc.) | 10 | ✅ Yes, via flow aggregator |
| Content (num_failed_logins, root_shell, etc.) | 13 | ❌ No — requires app-layer parsing, out of scope |



The 13 Content features are set to safe defaults (0 / not logged in) at inference time.

## Setup

**Prerequisites**
- Python 3.11+
- [Npcap](https://npcap.com) (Windows only, required for Scapy packet capture — install with "WinPcap API-compatible Mode" enabled)
- An IBM Cloud Lite account with a deployed WML scoring endpoint (see `notebooks/` for the AutoAI pipeline)

**Install**
```bash
git clone https://github.com/Sofia6002/Network-intrusion-detection-system_IBM_CLOUD.git
cd Network-intrusion-detection-system
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

**Set your IBM Cloud API key** (never hardcode it):
```powershell
$env:IBM_CLOUD_API_KEY = "your-api-key-here"
```

## How to Run

Packet capture requires Administrator/root privileges.

**Terminal 1 — start the flow aggregator + live scoring:**
```bash
python flow_aggregator.py
```

**Terminal 2 — start the dashboard (same folder, so they share the log file):**
```bash
streamlit run dashboard.py
```

## Model Details

- Trained via IBM Watson Studio **AutoAI** on `Train_data.csv` (NSL-KDD 20% subset, 25,192 rows)
- Selected pipeline: **Snap Random Forest Classifier (Batched Tree Ensemble)**
- Cross-validated accuracy: **99.6%**
- Deployed to a WML Deployment Space as an online REST scoring endpoint
- See `notebooks/` for the exported AutoAI pipeline notebook

## Known Limitations

- **Content features (13/41) are defaulted** at inference time — anomalies whose signature depends mainly on Content features (e.g. login-abuse patterns) are harder to catch live than timing/volume-based attacks (e.g. flooding, scanning).
- **NSL-KDD is synthetic, 1998-era academic traffic** — a model trained on it won't transfer perfectly to real production networks. This is a known, general limitation of NSL-KDD-based research, not specific to this implementation.
- **`Test_data.csv` has no ground-truth labels** — it can only be used to generate example predictions, not to measure accuracy.
- **Mitigation actions are recommendations for a human operator**, never auto-executed — a deliberate design choice.
- Some NSL-KDD features (`wrong_fragment`, `srv_diff_host_rate`, `dst_host_srv_diff_host_rate`) are simplified/defaulted in the live aggregator due to the additional per-service/cross-host state they'd require to track precisely.
