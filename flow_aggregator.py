"""
NIDS Flow Aggregator — full pipeline

Captures live packets -> tracks connections -> on connection close
(or timeout), emits a 40-field feature vector matching the schema
your WML deployment expects (confirmed working in Watson Studio test).

Feature groups (per your spec, Section 2b):
  - Basic (9):        derived directly per-connection
  - Content (13):     NOT derivable from live traffic -> defaulted
  - Time-based (9):   rolling 2-second window across connections
  - Host-based (10):  rolling last-100-connections-per-host window

Run as Administrator, inside your venv:
    python flow_aggregator.py
"""

import threading
import time
import os
import json
import requests
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ============================================================
# SHARED LOG FILE (for the Streamlit dashboard to read)
# ============================================================

LOG_FILE_PATH = "nids_log.jsonl"
log_file_lock = threading.Lock()


def append_log_entry(canonical_key, prediction, confidence, mitigation):
    """
    Append one classified connection as a JSON line. The Streamlit
    dashboard (a separate process) polls this file -- append-only,
    one JSON object per line, so a reader can safely read up to
    whatever's been flushed without needing a lock on the reader side.
    """
    src_ip, dst_ip, src_port, dst_port, proto = canonical_key
    entry = {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "prediction": prediction if prediction is not None else "unknown",
        "confidence": round(confidence, 4) if confidence is not None else None,
        "mitigation": mitigation,
    }
    with log_file_lock:
        with open(LOG_FILE_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")

# ============================================================
# WML SCORING CONFIG
# ============================================================

# Set this in your terminal before running:
#   PowerShell: $env:IBM_CLOUD_API_KEY = "your-api-key-here"
API_KEY = os.environ.get("IBM_CLOUD_API_KEY")

# From your deployment's API reference tab -- the public/private
# scoring endpoint URL (includes the deployment ID and ?version=...)
WML_SCORING_URL = "https://jp-tok.ml.cloud.ibm.com/ml/v4/deployments/019f59ca-c66a-72d9-a66c-f52b60a0d67d/predictions?version=2021-05-01"

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"

_cached_token = {"value": None, "expires_at": 0}


def get_iam_token():
    """
    IAM bearer tokens last ~1 hour. Cache and reuse instead of
    regenerating on every scoring call -- regenerating per-request
    would be slow and hits IAM rate limits unnecessarily.
    """
    if _cached_token["value"] and time.time() < _cached_token["expires_at"]:
        return _cached_token["value"]

    if not API_KEY:
        raise RuntimeError(
            "IBM_CLOUD_API_KEY environment variable not set. "
            "Set it in your terminal before running this script."
        )

    response = requests.post(
        IAM_TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": API_KEY,
        },
        timeout=10,
    )
    response.raise_for_status()
    token_data = response.json()

    _cached_token["value"] = token_data["access_token"]
    # Refresh 5 minutes early to avoid edge-of-expiry failures
    _cached_token["expires_at"] = time.time() + token_data["expires_in"] - 300

    return _cached_token["value"]


def score_vector(fields, values_row):
    """
    Send one feature vector to the WML endpoint, return
    (prediction, confidence) or (None, None) on failure.
    Network/API failures are caught here and logged, not raised --
    a single failed scoring call should not crash the live capture.
    """
    try:
        token = get_iam_token()
    except Exception as e:
        print(f"  [WML ERROR] Could not get IAM token: {e}")
        return None, None

    payload = {
        "input_data": [
            {"fields": fields, "values": [values_row]}
        ]
    }

    try:
        response = requests.post(
            WML_SCORING_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()

        prediction_row = result["predictions"][0]["values"][0]
        prediction = prediction_row[0]        # e.g. "anomaly" / "normal"
        probabilities = prediction_row[1]      # e.g. [0.97, 0.03]
        confidence = max(probabilities)

        return prediction, confidence

    except requests.exceptions.RequestException as e:
        print(f"  [WML ERROR] Scoring call failed: {e}")
        return None, None
    except (KeyError, IndexError) as e:
        print(f"  [WML ERROR] Unexpected response shape: {e}")
        return None, None


# ============================================================
# MITIGATION LOOKUP (static, per spec Section 6 -- never LLM-generated)
# ============================================================

MITIGATION_TABLE = {
    "anomaly": (
        "FLAG connection for review. Log source/destination IPs, ports, "
        "and byte counts. Escalate to operator for manual triage "
        "(rate-limit, block, or investigate as appropriate)."
    ),
    "normal": "No action.",
}


def display_alert(canonical_key, prediction, confidence):
    src_ip, dst_ip, src_port, dst_port, proto = canonical_key
    mitigation = MITIGATION_TABLE.get(prediction, "Unknown classification -- manual review recommended.")

    if prediction == "anomaly":
        print(f"\n  🚨 ALERT: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})")
        print(f"     Prediction: ANOMALY  (confidence: {confidence:.1%})")
        print(f"     Mitigation: {mitigation}")
    else:
        print(f"  ✓ {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})  "
              f"normal (confidence: {confidence:.1%})")

# ============================================================
# CONFIG
# ============================================================

CONNECTION_TIMEOUT_SECONDS = 5     # idle connection auto-closes after this
TIME_WINDOW_SECONDS = 2            # NSL-KDD's time-based window
HOST_WINDOW_SIZE = 100             # NSL-KDD's host-based window

# Minimal port -> NSL-KDD-style service name mapping.
# NSL-KDD has ~70 service categories; we map the common ones and
# fall back to "other" for anything unmapped. This is a known
# simplification -- worth one sentence in the report's limitations.
PORT_SERVICE_MAP = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp_u", 79: "finger",
    80: "http", 110: "pop_3", 113: "auth", 119: "nntp", 123: "ntp_u",
    143: "imap4", 179: "bgp", 194: "irc", 389: "ldap", 443: "http",
    445: "smtp", 514: "shell", 515: "printer", 543: "klogin",
    544: "kshell", 993: "imap4", 995: "pop_3",
}


def port_to_service(port):
    return PORT_SERVICE_MAP.get(port, "other")


# ============================================================
# GLOBAL STATE
# ============================================================

# Active connections, keyed by canonical 5-tuple:
#   (src_ip, dst_ip, src_port, dst_port, protocol)
connections = {}

# Direction resolution cache (see step 2) -- unordered key -> canonical key.
# IMPORTANT: this is intentionally never cleared on close. If a packet
# trails a connection's close (a delayed ACK, a retransmit, the final
# leg of a FIN/ACK teardown), we still want it recognized as belonging
# to the SAME conversation -- not spawn a reversed-direction "ghost"
# connection. See closed_keys below for how we then drop such packets.
pending_by_unordered_key = {}

# Canonical keys that have already been emitted/closed. Any further
# packet matching one of these is a trailing artifact of a connection
# we already scored -- we deliberately drop it rather than opening a
# new connection, since re-opening would double-count it in the
# rolling history and skew count/serror_rate/etc. for later traffic.
closed_keys = set()

# History of completed connections, for time-based + host-based stats.
# Each entry: dict with keys: end_time, src_ip, dst_ip, dst_port,
#             service, flag, was_error (bool)
completed_history = deque(maxlen=5000)  # generous cap so memory doesn't grow forever

history_lock = threading.Lock()

# ============================================================
# HELPERS: direction + service + flag classification
# ============================================================


def unordered_key(ip_a, port_a, ip_b, port_b, proto):
    if (ip_a, port_a) <= (ip_b, port_b):
        return (ip_a, port_a, ip_b, port_b, proto)
    return (ip_b, port_b, ip_a, port_a, proto)


def extract_fields(pkt):
    if not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst
    pkt_len = len(pkt)

    if pkt.haslayer(TCP):
        proto = "tcp"
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        flags = pkt[TCP].flags
    elif pkt.haslayer(UDP):
        proto = "udp"
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        flags = None
    elif pkt.haslayer(ICMP):
        proto = "icmp"
        src_port, dst_port = 0, 0
        flags = None
    else:
        return None

    return (src_ip, dst_ip, src_port, dst_port, proto, flags, pkt_len)


def classify_nslkdd_flag(conn, proto):
    """
    Approximate NSL-KDD 'flag' values from what we observed.
    NSL-KDD flags: SF, S0, S1, S2, S3, REJ, RSTO, RSTR, RSTOS0, SH, OTH
    This is a simplification of the real TCP-state-machine-derived
    flag NSL-KDD uses -- documented as a known approximation.

    UDP/ICMP have no handshake, so we can't infer state the same way.
    NSL-KDD's real distribution has the vast majority of benign UDP
    traffic labeled SF -- defaulting non-TCP traffic to OTH would bias
    every UDP row toward looking "unusual" to the model, purely as an
    artifact of the aggregator rather than real traffic behavior. So
    for UDP we default to SF (documented limitation -- a real ICMP
    port-unreachable would ideally flip this, but that's not tracked
    in this version).
    """
    if proto != "tcp":
        return "SF"

    if conn["saw_syn"] and conn["saw_synack"] and conn["saw_fin"]:
        return "SF"          # normal full close
    if conn["saw_syn"] and not conn["saw_synack"] and conn["saw_rst"]:
        return "REJ"         # connection refused
    if conn["saw_syn"] and conn["saw_synack"] and conn["saw_rst"]:
        return "RSTO"        # established then reset by originator side
    if conn["saw_syn"] and not conn["saw_synack"] and not conn["saw_fin"]:
        return "S0"          # SYN sent, no reply at all (e.g. filtered/scan)
    return "OTH"


# ============================================================
# STATS: time-based (2-second window) + host-based (last 100)
# ============================================================


def compute_time_based_features(now, dst_ip, service):
    """
    NSL-KDD time-based features, computed over connections to the
    SAME destination host (count/serror_rate/etc.) and same service
    (srv_* variants) within the last TIME_WINDOW_SECONDS.
    """
    with history_lock:
        window = [c for c in completed_history if now - c["end_time"] <= TIME_WINDOW_SECONDS]

    same_host = [c for c in window if c["dst_ip"] == dst_ip]
    same_host_srv = [c for c in same_host if c["service"] == service]

    count = len(same_host)
    srv_count = len(same_host_srv)

    def error_rate(conns):
        if not conns:
            return 0.0
        errors = sum(1 for c in conns if c["was_error"])
        return round(errors / len(conns), 2)

    serror_rate = error_rate(same_host)
    srv_serror_rate = error_rate(same_host_srv)
    rerror_rate = serror_rate   # simplification: we don't distinguish SYN-error vs REJ-error separately
    srv_rerror_rate = srv_serror_rate

    same_srv_rate = round(srv_count / count, 2) if count else 0.0
    diff_srv_rate = round(1 - same_srv_rate, 2) if count else 0.0
    srv_diff_host_rate = 0.0  # requires cross-host same-service tracking; defaulted (documented limitation)

    return {
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
    }


def compute_host_based_features(dst_ip, dst_port, service, src_port):
    """
    NSL-KDD host-based features, computed over the last
    HOST_WINDOW_SIZE connections to the same destination host
    (regardless of when -- this window is count-based, not time-based).
    """
    with history_lock:
        recent = list(completed_history)[-HOST_WINDOW_SIZE:]

    same_host = [c for c in recent if c["dst_ip"] == dst_ip]
    same_host_srv = [c for c in same_host if c["service"] == service]

    dst_host_count = len(same_host)
    dst_host_srv_count = len(same_host_srv)

    dst_host_same_srv_rate = round(dst_host_srv_count / dst_host_count, 2) if dst_host_count else 0.0
    dst_host_diff_srv_rate = round(1 - dst_host_same_srv_rate, 2) if dst_host_count else 0.0

    same_src_port = [c for c in same_host if c.get("src_port") == src_port]
    dst_host_same_src_port_rate = round(len(same_src_port) / dst_host_count, 2) if dst_host_count else 0.0

    dst_host_srv_diff_host_rate = 0.0  # requires per-service cross-host tracking; defaulted (documented limitation)

    def error_rate(conns):
        if not conns:
            return 0.0
        errors = sum(1 for c in conns if c["was_error"])
        return round(errors / len(conns), 2)

    dst_host_serror_rate = error_rate(same_host)
    dst_host_srv_serror_rate = error_rate(same_host_srv)
    dst_host_rerror_rate = dst_host_serror_rate       # same simplification as above
    dst_host_srv_rerror_rate = dst_host_srv_serror_rate

    return {
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
    }


# ============================================================
# CONTENT FEATURES (13) -- always defaulted, per spec Section 2b
# ============================================================

CONTENT_DEFAULTS = {
    "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
    "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0,
}

# ============================================================
# EMIT: build the full 40-field vector, in schema order
# ============================================================

FIELD_ORDER = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


def emit_feature_vector(conn, canonical_key):
    src_ip, dst_ip, src_port, dst_port, proto = canonical_key
    now = time.time()
    duration = round(now - conn["start_time"], 3)
    service = port_to_service(dst_port)
    flag = classify_nslkdd_flag(conn, proto)
    was_error = flag in ("REJ", "RSTO", "S0")

    basic = {
        "duration": duration,
        "protocol_type": proto,
        "service": service,
        "flag": flag,
        "src_bytes": conn["bytes_forward"],
        "dst_bytes": conn["bytes_reverse"],
        "land": 1 if src_ip == dst_ip and src_port == dst_port else 0,
        "wrong_fragment": 0,   # not tracked at this layer; defaulted
        "urgent": conn.get("urgent_count", 0),
    }

    time_feats = compute_time_based_features(now, dst_ip, service)
    host_feats = compute_host_based_features(dst_ip, dst_port, service, src_port)

    record = {**basic, **CONTENT_DEFAULTS, **time_feats, **host_feats}

    # Record this connection into history for future stats BEFORE returning
    with history_lock:
        completed_history.append({
            "end_time": now,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "service": service,
            "was_error": was_error,
        })

    values_row = [record[field] for field in FIELD_ORDER]

    print(f"\n[EMIT] {canonical_key}  flag={flag}  duration={duration}s")

    # Phase 3: send to the live WML endpoint for real-time classification
    prediction, confidence = score_vector(FIELD_ORDER, values_row)
    mitigation = MITIGATION_TABLE.get(prediction, "No prediction available -- scoring call failed.")
    if prediction is not None:
        display_alert(canonical_key, prediction, confidence)
    else:
        print("  [no prediction -- scoring call failed, see error above]")

    append_log_entry(canonical_key, prediction, confidence, mitigation)

    return {"fields": FIELD_ORDER, "values": [values_row]}


# ============================================================
# PACKET HANDLING
# ============================================================


def handle_packet(pkt):
    fields = extract_fields(pkt)
    if fields is None:
        return
    src_ip, dst_ip, src_port, dst_port, proto, flags, pkt_len = fields

    u_key = unordered_key(src_ip, src_port, dst_ip, dst_port, proto)

    if u_key in pending_by_unordered_key:
        canonical_key = pending_by_unordered_key[u_key]
    else:
        canonical_key = (src_ip, dst_ip, src_port, dst_port, proto)
        pending_by_unordered_key[u_key] = canonical_key

    # This conversation was already closed and scored -- any further
    # packet for it is a trailing artifact (delayed ACK, retransmit,
    # etc). Drop it instead of spawning a reversed-direction ghost.
    if canonical_key in closed_keys:
        return

    is_forward = (src_ip, src_port) == (canonical_key[0], canonical_key[2])

    if canonical_key not in connections:
        connections[canonical_key] = {
            "state": "OPEN",
            "start_time": time.time(),
            "last_seen": time.time(),
            "bytes_forward": 0,
            "bytes_reverse": 0,
            "saw_syn": False,
            "saw_synack": False,
            "saw_fin": False,
            "saw_rst": False,
            "urgent_count": 0,
        }

    conn = connections[canonical_key]
    conn["last_seen"] = time.time()

    if is_forward:
        conn["bytes_forward"] += pkt_len
    else:
        conn["bytes_reverse"] += pkt_len

    if flags is not None:
        if "S" in flags and "A" not in flags:
            conn["saw_syn"] = True
        if "S" in flags and "A" in flags:
            conn["saw_synack"] = True
        if "F" in flags:
            conn["saw_fin"] = True
        if "R" in flags:
            conn["saw_rst"] = True
        if "U" in flags:
            conn["urgent_count"] += 1

        if conn["state"] == "OPEN" and ("F" in flags or "R" in flags):
            conn["state"] = "CLOSED"
            emit_feature_vector(conn, canonical_key)
            del connections[canonical_key]
            closed_keys.add(canonical_key)


# ============================================================
# TIMEOUT WATCHER (background thread) -- closes idle connections
# ============================================================


def timeout_watcher():
    while True:
        time.sleep(1)
        now = time.time()
        idle_keys = [
            key for key, conn in list(connections.items())
            if conn["state"] == "OPEN" and (now - conn["last_seen"]) > CONNECTION_TIMEOUT_SECONDS
        ]
        for key in idle_keys:
            conn = connections[key]
            conn["state"] = "CLOSED"
            emit_feature_vector(conn, key)
            del connections[key]
            closed_keys.add(key)


if __name__ == "__main__":
    watcher_thread = threading.Thread(target=timeout_watcher, daemon=True)
    watcher_thread.start()

    print("Sniffing... browse a couple of sites. Ctrl+C to stop.")
    try:
        sniff(prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopped.")