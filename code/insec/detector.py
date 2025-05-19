import time
import numpy as np
from collections import deque, Counter
from math import log2

WINDOW_SIZE = 50
ENTROPY_THRESHOLD = 2.0
UNIQUE_FRAG_RATIO_THRESHOLD = 0.3
DELAY_STD_THRESHOLD = 0.01

frag_values     = deque(maxlen=WINDOW_SIZE)
packet_delays   = deque(maxlen=WINDOW_SIZE)
last_packet_time= None
log_entries     = []

def shannon_entropy(seq):
    counts = Counter(seq)
    total = len(seq)
    return -sum((c/total)*log2(c/total) for c in counts.values() if c>0)

def detect_anomaly():
    frag_list  = list(frag_values)
    delay_list = list(packet_delays)
    entropy     = shannon_entropy(frag_list)
    unique_rate = len(set(frag_list)) / len(frag_list)
    delay_std   = np.std(delay_list) if len(delay_list)>1 else 0.0

    alert = (
      entropy < ENTROPY_THRESHOLD or
      unique_rate < UNIQUE_FRAG_RATIO_THRESHOLD or
      delay_std < DELAY_STD_THRESHOLD
    )
    return alert, entropy, unique_rate, delay_std

def process_frag_for_detection(frag_val):

    global last_packet_time

    now = time.time()
    frag_values.append(frag_val)
    if last_packet_time is not None:
        packet_delays.append(now - last_packet_time)
    last_packet_time = now

    if len(frag_values) == WINDOW_SIZE:
        alert, ent, uniq, std = detect_anomaly()
        entry = {
            "alert": alert,
            "entropy": round(ent,3),
            "unique_ratio": round(uniq,3),
            "delay_std": round(std,4)
        }
        log_entries.append(entry)
        tag = "[DETECTED]" if alert else "[OK]"
        print(f"{tag} ent={ent:.2f}, uniq={uniq:.2f}, std={std:.4f}")
