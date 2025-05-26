import time
import numpy as np
from collections import deque, Counter
from math import log2
from scipy.stats import chi2
from scapy.all import IP

WINDOW_SIZE = 50
ENTROPY_THRESHOLD = 2.0
UNIQUE_FRAG_RATIO_THRESHOLD = 0.3
DELAY_STD_THRESHOLD = 0.01

frag_values = deque(maxlen=WINDOW_SIZE)
packet_delays = deque(maxlen=WINDOW_SIZE)
last_packet_time = None
log_entries = []

def shannon_entropy(seq):
    counts = Counter(seq)
    total = len(seq)
    return -sum((c/total) * log2(c/total) for c in counts.values() if c > 0)

def detect_anomaly():
    frag_list = list(frag_values)
    delay_list = list(packet_delays)
    entropy = shannon_entropy(frag_list)
    unique_rate = len(set(frag_list)) / len(frag_list)
    delay_std = np.std(delay_list) if len(delay_list) > 1 else 0.0
    alert = (
        entropy < ENTROPY_THRESHOLD or
        unique_rate < UNIQUE_FRAG_RATIO_THRESHOLD or
        delay_std < DELAY_STD_THRESHOLD
    )
    return alert, entropy, unique_rate, delay_std

def stats_check():
    alert, entropy, unique_rate, delay_std = detect_anomaly()

    frag_list = list(frag_values)
    bins = [f % 16 for f in frag_list]
    counts = Counter(bins)
    observed = np.array([counts[i] for i in range(16)])
    expected = len(bins) / 16
    chi2_stat = ((observed - expected)**2 / expected).sum()
    p_val = 1 - chi2.cdf(chi2_stat, df=15)
    if p_val < 0.01:
        alert = True
        print(f"[DETECTED] χ² non-uniform distribution (p={p_val:.3f})")

    entry = {
        "alert": alert,
        "entropy": round(entropy, 3),
        "unique_ratio": round(unique_rate, 3),
        "delay_std": round(delay_std, 4),
        "chi2_p": round(p_val, 4)
    }
    log_entries.append(entry)
    tag = "[DETECTED]" if alert else "[OK]"
    print(f"{tag} ent={entropy:.2f}, uniq={unique_rate:.2f}, std={delay_std:.4f}, p={p_val:.4f}")

def process_frag_for_detection(frag_val):
    global last_packet_time
    now = time.time()
    frag_values.append(frag_val)
    if last_packet_time is not None:
        packet_delays.append(now - last_packet_time)
    last_packet_time = now

    if len(frag_values) == WINDOW_SIZE:
        stats_check()