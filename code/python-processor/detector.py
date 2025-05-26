import time
import numpy as np
from collections import deque, Counter
from math import log2
from scipy.stats import chi2, kstest
from scapy.all import IP

# Configuration
WINDOW_SIZE = 50
BASELINE_WINDOWS = 3
ENTROPY_THRESHOLD = 2.0
UNIQUE_FRAG_RATIO_THRESHOLD = 0.3
DELAY_STD_THRESHOLD = 0.01

# Data collection
frag_values = deque(maxlen=WINDOW_SIZE)
frag_diffs = deque(maxlen=WINDOW_SIZE-1)
packet_delays = deque(maxlen=WINDOW_SIZE)
last_packet_time = None
last_frag_value = None
log_entries = []

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
            
        # Check for too many zeros in differences (indicates repeating values)
        zero_ratio = diff_list.count(0) / len(diff_list)
        if zero_ratio > 0.2:  # More than 20% are repeated values
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
    
    # 3. Check for periodicity using autocorrelation
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
    bins = [f % 16 for f in frag_list]  # Modulo 16 bins for fragment values
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

def stats_check():
    global baseline_windows_collected, in_baseline_mode
    
    # Use adaptive thresholds once baseline is established
    use_adaptive = baseline_windows_collected >= BASELINE_WINDOWS
    
    # Run detection
    alert, entropy, unique_rate, delay_std, extra_alerts = detect_anomaly(use_adaptive)
    
    # Check distribution uniformity
    frag_list = list(frag_values)
    dist_alert, chi2_p_val, ks_p_val = check_distribution_uniformity(frag_list)
    
    if dist_alert:
        alert = True
        print(f"[DETECTED] Non-uniform distribution (χ²={chi2_p_val:.3f}, KS={ks_p_val:.3f})")
    
    # Log results
    entry = {
        "alert": alert,
        "entropy": round(entropy, 3),
        "unique_ratio": round(unique_rate, 3),
        "delay_std": round(delay_std, 4),
        "chi2_p": round(chi2_p_val, 4),
        "ks_p": round(ks_p_val, 4),
        "extra_alerts": extra_alerts
    }
    log_entries.append(entry)
    
    # If in baseline mode, collect baseline data
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
    print(f"{tag} ent={entropy:.2f}, uniq={unique_rate:.2f}, std={delay_std:.4f}, p={chi2_p_val:.4f}")
    
    if extra_alerts:
        for alert_type, details in extra_alerts.items():
            print(f"  ├─ {alert_type}: {details}")

def process_frag_for_detection(frag_val):
    """Process a fragment value for detection."""
    global last_packet_time, last_frag_value
    
    now = time.time()
    frag_values.append(frag_val)
    
    # Store time difference for packet delay analysis
    if last_packet_time is not None:
        packet_delays.append(now - last_packet_time)
    last_packet_time = now
    
    # Store value differences for pattern analysis
    if last_frag_value is not None:
        frag_diffs.append(frag_val - last_frag_value)
    last_frag_value = frag_val

    # Run analysis when we have enough data
    if len(frag_values) == WINDOW_SIZE:
        stats_check()