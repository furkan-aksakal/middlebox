import time
import numpy as np
from collections import deque, Counter
from math import log2
from scipy.stats import chi2, kstest
from scapy.all import IP

# Configuration
MIN_WINDOW_SIZE = 20
MAX_WINDOW_SIZE = 100
WINDOW_SIZE = 50  # Initial window size
WINDOW_ADAPTATION_RATE = 0.2
BASELINE_WINDOWS = 5
ENTROPY_THRESHOLD = 2.0
UNIQUE_FRAG_RATIO_THRESHOLD = 0.3
DELAY_STD_THRESHOLD = 0.01
ADAPTATION_INTERVAL = 20

# Data collection
frag_values = deque(maxlen=WINDOW_SIZE)
frag_diffs = deque(maxlen=WINDOW_SIZE-1)
packet_delays = deque(maxlen=WINDOW_SIZE)
last_packet_time = None
last_frag_value = None
log_entries = []
packets_since_adaptation = 0
alert_history = deque(maxlen=10)
packet_count = 0
packet_rate = 0
last_rate_check = time.time()

# Traffic statistics
traffic_volume = deque(maxlen=30)

# Baseline collection
baseline_entropy = []
baseline_unique_ratio = []
baseline_delay_std = []
in_baseline_mode = True
baseline_windows_collected = 0

def shannon_entropy(seq):
    if not seq:
        return 0
    counts = Counter(seq)
    total = len(seq)
    return -sum((c/total) * log2(c/total) for c in counts.values() if c > 0)

def detect_anomaly(use_adaptive=True):
    frag_list = list(frag_values)
    delay_list = list(packet_delays)
    diff_list = list(frag_diffs)
    
    # Basic statistics
    entropy = shannon_entropy(frag_list)
    unique_rate = len(set(frag_list)) / len(frag_list) if frag_list else 0
    delay_std = np.std(delay_list) if len(delay_list) > 1 else 0.0
    
    # Get thresholds (adaptive if baseline established)
    e_threshold = np.mean(baseline_entropy) * 0.8 if use_adaptive and baseline_entropy else ENTROPY_THRESHOLD
    u_threshold = np.mean(baseline_unique_ratio) * 0.8 if use_adaptive and baseline_unique_ratio else UNIQUE_FRAG_RATIO_THRESHOLD
    d_threshold = np.mean(baseline_delay_std) * 0.8 if use_adaptive and baseline_delay_std else DELAY_STD_THRESHOLD
    
    # Basic alerts
    alert = (
        entropy < e_threshold or
        unique_rate < u_threshold or
        delay_std < d_threshold
    )
    
    extra_alerts = {}
    
    if len(diff_list) >= 10:
        diff_entropy = shannon_entropy(diff_list)
        diff_unique = len(set(diff_list)) / len(diff_list)
        
        if diff_entropy < e_threshold or diff_unique < u_threshold:
            alert = True
            extra_alerts["diff_pattern"] = f"Entropy={diff_entropy:.2f}, Unique={diff_unique:.2f}"
            
        zero_ratio = diff_list.count(0) / len(diff_list)
        if zero_ratio > 0.2:
            alert = True
            extra_alerts["repeats"] = f"{zero_ratio:.2%} repeated values"

    if len(frag_list) >= 20:
        median = np.median(frag_list)
        runs = sum(1 for i in range(1, len(frag_list)) if 
                 (frag_list[i] > median and frag_list[i-1] <= median) or
                 (frag_list[i] <= median and frag_list[i-1] > median)) + 1
        
        expected_runs = (2 * len(frag_list) - 1) / 3
        runs_ratio = runs / expected_runs
        
        if runs_ratio < 0.7 or runs_ratio > 1.3:
            alert = True
            extra_alerts["runs_test"] = f"Ratio={runs_ratio:.2f}"
    
    # Check for periodicity using autocorrelation
    if len(frag_list) >= 30:
        frag_array = np.array(frag_list)
        frag_array = frag_array - np.mean(frag_array)  # Center the data
        
        # Calculate autocorrelation for lags 1 to 10
        autocorr = []
        for lag in range(1, min(11, len(frag_array) // 3)):
            correlation = np.corrcoef(frag_array[:-lag], frag_array[lag:])[0, 1]
            autocorr.append(abs(correlation))
        
        # High autocorrelation at any lag suggests periodicity
        if max(autocorr) > 0.5:
            alert = True
            max_corr_lag = np.argmax(autocorr) + 1
            extra_alerts["periodicity"] = f"Lag={max_corr_lag}, Corr={max(autocorr):.2f}"
    
    return alert, entropy, unique_rate, delay_std, extra_alerts

def check_distribution_uniformity(frag_list):
    # Chi-square test for uniform distribution
    bins = [f % 16 for f in frag_list]
    counts = Counter(bins)
    observed = np.array([counts.get(i, 0) for i in range(16)])
    expected = len(bins) / 16
    
    if expected > 0:
        chi2_stat = ((observed - expected)**2 / expected).sum()
        p_val = 1 - chi2.cdf(chi2_stat, df=15)
    else:
        p_val = 1.0
    
    # Kolmogorov-Smirnov test for uniformity over full range
    if frag_list:
        # Scale to 0-1 range for K-S test
        max_val = max(max(frag_list), 1)
        scaled_frags = [f / max_val for f in frag_list]
        ks_stat, ks_p_val = kstest(scaled_frags, 'uniform')
    else:
        ks_p_val = 1.0
    
    return p_val < 0.05 or ks_p_val < 0.05, p_val, ks_p_val

def adjust_window_size():
    global WINDOW_SIZE, frag_values, frag_diffs, packet_delays
    
    alert_ratio = sum(1 for entry in alert_history if entry) / len(alert_history) if alert_history else 0
    
    new_size = WINDOW_SIZE

    if packet_rate > 100:
        new_size = min(MAX_WINDOW_SIZE, int(WINDOW_SIZE * (1 + WINDOW_ADAPTATION_RATE)))
    elif packet_rate < 20:
        new_size = max(MIN_WINDOW_SIZE, int(WINDOW_SIZE * (1 - WINDOW_ADAPTATION_RATE)))

    if alert_ratio > 0.3:
        new_size = max(MIN_WINDOW_SIZE, int(new_size * 0.8))

    if abs(new_size - WINDOW_SIZE) >= 5:
        print(f"[DETECTOR] Adjusting window size from {WINDOW_SIZE} to {new_size}")
        print(f"[DETECTOR] Alert ratio: {alert_ratio:.2f}, Traffic rate: {packet_rate:.1f} pps")
        
        temp_frag_values = list(frag_values)
        temp_frag_diffs = list(frag_diffs)
        temp_packet_delays = list(packet_delays)
        
        frag_values = deque(temp_frag_values[-new_size:], maxlen=new_size)
        frag_diffs = deque(temp_frag_diffs[-(new_size-1):], maxlen=new_size-1)
        packet_delays = deque(temp_packet_delays[-new_size:], maxlen=new_size)
        
        WINDOW_SIZE = new_size

def stats_check():
    global baseline_windows_collected, in_baseline_mode
    
    use_adaptive = baseline_windows_collected >= BASELINE_WINDOWS
    
    alert, entropy, unique_rate, delay_std, extra_alerts = detect_anomaly(use_adaptive)
    alert_history.append(alert)

    frag_list = list(frag_values)
    dist_alert, chi2_p_val, ks_p_val = check_distribution_uniformity(frag_list)
    
    if dist_alert:
        alert = True
        print(f"[DETECTED] Non-uniform distribution (χ²={chi2_p_val:.3f}, KS={ks_p_val:.3f})")

    entry = {
        "alert": alert,
        "entropy": round(entropy, 3),
        "unique_ratio": round(unique_rate, 3),
        "delay_std": round(delay_std, 4),
        "chi2_p": round(chi2_p_val, 4),
        "ks_p": round(ks_p_val, 4),
        "extra_alerts": extra_alerts,
        "window_size": WINDOW_SIZE
    }
    log_entries.append(entry)
    
    if in_baseline_mode:
        if not alert:
            baseline_entropy.append(entropy)
            baseline_unique_ratio.append(unique_rate)
            baseline_delay_std.append(delay_std)
            baseline_windows_collected += 1
            print(f"[BASELINE] Added window {baseline_windows_collected}/{BASELINE_WINDOWS}")
        
        if baseline_windows_collected >= BASELINE_WINDOWS:
            in_baseline_mode = False
            print(f"[BASELINE] Complete - Adaptive thresholds enabled")
            print(f"[BASELINE] Entropy: {np.mean(baseline_entropy):.2f}, "
                  f"Unique: {np.mean(baseline_unique_ratio):.2f}, "
                  f"Delay: {np.mean(baseline_delay_std):.4f}")
    
    tag = "[DETECTED]" if alert else "[OK]"
    print(f"{tag} ent={entropy:.2f}, uniq={unique_rate:.2f}, std={delay_std:.4f}, p={chi2_p_val:.4f}, win={WINDOW_SIZE}")
    
    if extra_alerts:
        for alert_type, details in extra_alerts.items():
            print(f"  ├─ {alert_type}: {details}")
    
    global packets_since_adaptation
    if packets_since_adaptation >= ADAPTATION_INTERVAL:
        adjust_window_size()
        packets_since_adaptation = 0

def update_traffic_rate():
    global packet_count, packet_rate, last_rate_check
    
    current_time = time.time()
    elapsed = current_time - last_rate_check
    
    if elapsed >= 1.0:
        packet_rate = packet_count / elapsed
        traffic_volume.append(packet_rate)
        packet_count = 0
        last_rate_check = current_time

def process_frag_for_detection(frag_val):
    global last_packet_time, last_frag_value, packet_count, packets_since_adaptation
    
    now = time.time()
    frag_values.append(frag_val)
    
    packet_count += 1
    packets_since_adaptation += 1
    update_traffic_rate()

    if last_packet_time is not None:
        packet_delays.append(now - last_packet_time)
    last_packet_time = now
    
    if last_frag_value is not None:
        frag_diffs.append(frag_val - last_frag_value)
    last_frag_value = frag_val

    if len(frag_values) >= WINDOW_SIZE:
        stats_check()
        frag_values.popleft()