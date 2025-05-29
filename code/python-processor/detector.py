import time
import numpy as np
from collections import deque, Counter
from math import log2
from scipy.stats import chi2, kstest
from scapy.all import IP

# Configuration
MIN_WINDOW_SIZE = 20
MAX_WINDOW_SIZE = 100
WINDOW_SIZE = 50
WINDOW_ADAPTATION_RATE = 0.2
BASELINE_WINDOWS = 5
ADAPTATION_INTERVAL = 20
COOLDOWN_PERIOD = 10  # seconds to reset after an alert

# Thresholds
ENTROPY_THRESHOLD = 1.5
FRAGMENT_SIZE = 1480  # expected payload length per fragment (bytes)

# Data buffers
frag_values = deque(maxlen=WINDOW_SIZE)
frag_diffs = deque(maxlen=WINDOW_SIZE - 1)
lsb_flags = deque(maxlen=WINDOW_SIZE)

# State vars
last_frag_value = None
last_alert_time = 0

# Logs and counters
log_entries = []
alert_history = deque(maxlen=10)
packets_since_adaptation = 0

# Baseline data
baseline_entropy = []
in_baseline_mode = True
baseline_windows_collected = 0


def shannon_entropy(seq):
    if not seq:
        return 0
    counts = Counter(seq)
    total = len(seq)
    return -sum((c / total) * log2(c / total) for c in counts.values() if c > 0)


def reset_buffers():
    global frag_values, frag_diffs, lsb_flags, last_frag_value
    frag_values.clear()
    frag_diffs.clear()
    lsb_flags.clear()
    last_frag_value = None
    print("[DETECTOR] Buffers reset after cooldown period.")


def detect_anomaly(use_adaptive=True):
    frag_list = list(frag_values)
    diff_list = list(frag_diffs)
    lsb_list = list(lsb_flags)

    entropy = shannon_entropy(frag_list)
    if use_adaptive and baseline_entropy:
        e_threshold = np.mean(baseline_entropy) * 0.6
    else:
        e_threshold = ENTROPY_THRESHOLD

    alert = False
    extra_alerts = {}

    #Entropy-based check
    if entropy < e_threshold * 0.5:
        alert = True
        extra_alerts['entropy'] = f'Low entropy: {entropy:.2f}'

    #Fragment size alignment check
    raw_offsets = [f * 8 for f in frag_list]
    violations = sum(1 for ro in raw_offsets if ro != 0 and ro % FRAGMENT_SIZE != 0)
    if violations > 0:
        alert = True
        extra_alerts['fragsize_align'] = f'{violations}/{len(raw_offsets)} misaligned'

    #Diff pattern check
    if len(diff_list) >= 10:
        diff_entropy = shannon_entropy(diff_list)
        if diff_entropy < e_threshold * 0.5:
            alert = True
            extra_alerts['diff_pattern'] = f'Entropy={diff_entropy:.2f}'

    #LSB entropy check
    if len(lsb_list) >= 20:
        lsb_entropy = shannon_entropy(lsb_list)
        if lsb_entropy > 0.9:
            alert = True
            extra_alerts['offset_lsb'] = f'High LSB entropy: {lsb_entropy:.2f}'

    return alert, entropy, extra_alerts


def check_distribution_uniformity(frag_list):
    bins = [f % 16 for f in frag_list]
    counts = Counter(bins)
    observed = np.array([counts.get(i, 0) for i in range(16)])
    expected = len(bins) / 16
    if expected > 0:
        chi2_stat = ((observed - expected) ** 2 / expected).sum()
        p_val = 1 - chi2.cdf(chi2_stat, df=15)
    else:
        p_val = 1.0
    if frag_list:
        max_val = max(max(frag_list), 1)
        scaled_frags = [f / max_val for f in frag_list]
        _, ks_p_val = kstest(scaled_frags, 'uniform')
    else:
        ks_p_val = 1.0
    return p_val < 0.01 or ks_p_val < 0.01, p_val, ks_p_val


def adjust_window_size():
    global WINDOW_SIZE, frag_values, frag_diffs, lsb_flags, packets_since_adaptation
    alert_ratio = sum(alert_history) / len(alert_history) if alert_history else 0
    new_size = WINDOW_SIZE
    if alert_ratio > 0.4:
        new_size = max(MIN_WINDOW_SIZE, int(WINDOW_SIZE * 0.8))
    if abs(new_size - WINDOW_SIZE) >= 5:
        frag_values = deque(list(frag_values)[-new_size:], maxlen=new_size)
        frag_diffs = deque(list(frag_diffs)[-(new_size - 1):], maxlen=new_size - 1)
        lsb_flags = deque(list(lsb_flags)[-new_size:], maxlen=new_size)
        WINDOW_SIZE = new_size
        packets_since_adaptation = 0


def stats_check():
    global baseline_windows_collected, in_baseline_mode, packets_since_adaptation, last_alert_time
    now = time.time()
    use_adaptive = baseline_windows_collected >= BASELINE_WINDOWS

    alert, entropy, extras = detect_anomaly(use_adaptive)
    alert_history.append(alert)
    entry = {'alert': alert, 'entropy': round(entropy, 3), 'extra_alerts': extras, 'window_size': WINDOW_SIZE}
    log_entries.append(entry)

    dist_alert, chi2_p, ks_p = check_distribution_uniformity(list(frag_values))
    if dist_alert:
        entry['extra_alerts']['distribution_test'] = f'Chi2={chi2_p:.3f}, KS={ks_p:.3f}'

    if in_baseline_mode and not alert:
        baseline_entropy.append(entropy)
        baseline_windows_collected += 1
        if baseline_windows_collected >= BASELINE_WINDOWS:
            in_baseline_mode = False

    if alert and now - last_alert_time >= COOLDOWN_PERIOD:
        reset_buffers()
        last_alert_time = now

    if packets_since_adaptation >= ADAPTATION_INTERVAL:
        adjust_window_size()


def process_frag_for_detection(frag_val):
    global last_frag_value, packets_since_adaptation
    frag_values.append(frag_val)
    lsb_flags.append(frag_val & 1)
    if last_frag_value is not None:
        frag_diffs.append(frag_val - last_frag_value)
    last_frag_value = frag_val
    packets_since_adaptation += 1
    if len(frag_values) >= WINDOW_SIZE and packets_since_adaptation % 5 == 0:
        stats_check()
