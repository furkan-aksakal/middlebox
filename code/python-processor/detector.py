from scapy.all import IP
import time
from math import log2

frag_timeout = 60
MIN_FRAG_SIZE = 32
MAX_FRAG_COUNT = 24
HIGH_ENTROPY_THRESHOLD = 7.5

frag_buffer = {}
log_entries = []

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)
    return entropy

def process_frag_for_detection(packet):
    global log_entries
    if IP not in packet:
        return
    ip = packet[IP]
    
    if (ip.flags & 0x1) == 0 and ip.frag == 0:
        return
    
    datagram_key = (ip.src, ip.dst, ip.proto, ip.id)
    
    current_time = time.time()
    for key, info in list(frag_buffer.items()):
        if current_time - info['last_seen'] > frag_timeout:
            print(f"[Timeout] Incomplete datagram {key} discarded after {frag_timeout}s")
            frag_buffer.pop(key, None)
    
    if datagram_key not in frag_buffer:
        frag_buffer[datagram_key] = {
            'fragments': [],
            'last_frag_seen': False,
            'expected_length': None,
            'last_seen': current_time
        }
    else:
        frag_buffer[datagram_key]['last_seen'] = current_time
    
    frag_offset = ip.frag * 8
    ip_header_len = ip.ihl * 4
    frag_payload_len = ip.len - ip_header_len
    
    overlap_detected = False
    for frag in frag_buffer[datagram_key]['fragments']:
        existing_offset = frag['offset']
        existing_end = frag['offset'] + frag['length']
        new_end = frag_offset + frag_payload_len
        if not (frag_offset >= existing_end or existing_offset >= new_end):
            overlap_detected = True
            print(f"[Overlap] Detected overlapping fragment (datagram {datagram_key}, offset {frag_offset} overlaps earlier fragment)")
            break
    
    misalign_detected = False
    if (ip.flags & 0x1) != 0:
        if frag_payload_len % 8 != 0:
            misalign_detected = True
            print(f"[Misalign] Fragment length {frag_payload_len} is not 8-byte aligned (datagram {datagram_key})")
    
    small_fragment_detected = False
    if frag_payload_len < MIN_FRAG_SIZE:
        small_fragment_detected = True
        print(f"[Size Anomaly] Fragment payload size {frag_payload_len} bytes is below {MIN_FRAG_SIZE} (datagram {datagram_key})")
    
    fragment_data = bytes(ip.payload)
    frag_buffer[datagram_key]['fragments'].append({
        'offset': frag_offset,
        'length': frag_payload_len,
        'data': fragment_data
    })
    
    too_many_frags_detected = False
    fragment_count = len(frag_buffer[datagram_key]['fragments'])
    if fragment_count > MAX_FRAG_COUNT:
        too_many_frags_detected = True
        print(f"[Fragmentation] Datagram {datagram_key} has {fragment_count} fragments (exceeds threshold {MAX_FRAG_COUNT})")
    
    if (ip.flags & 0x1) == 0:
        frag_buffer[datagram_key]['last_frag_seen'] = True
        frag_buffer[datagram_key]['expected_length'] = frag_offset + frag_payload_len
    
    high_entropy_detected = False
    if frag_buffer[datagram_key]['last_frag_seen']:
        expected_len = frag_buffer[datagram_key]['expected_length']
        fragments = sorted(frag_buffer[datagram_key]['fragments'], key=lambda x: x['offset'])
        reassembly_complete = True
        if fragments[0]['offset'] != 0:
            reassembly_complete = False
        else:
            prev_end = 0
            for frag in fragments:
                if frag['offset'] != prev_end:
                    reassembly_complete = False
                    break
                prev_end = frag['offset'] + frag['length']
            if expected_len is not None and prev_end != expected_len:
                reassembly_complete = False
        
        if reassembly_complete and not overlap_detected:
            reassembled_data = b''.join(frag['data'] for frag in fragments)
            entropy = calculate_entropy(reassembled_data)
            if entropy > HIGH_ENTROPY_THRESHOLD:
                high_entropy_detected = True
                print(f"[Entropy] High payload entropy ({entropy:.2f} bits/byte) detected for datagram {datagram_key}")
        else:
            if not reassembly_complete:
                print(f"[Incomplete] Datagram {datagram_key} could not be fully reassembled (missing fragments or gaps)")
            if overlap_detected:
                print(f"[Overlap] Datagram {datagram_key} has overlapping fragments - entropy check skipped")
        
        frag_buffer.pop(datagram_key, None)
    
    if overlap_detected or misalign_detected or small_fragment_detected or too_many_frags_detected or high_entropy_detected:
        anomalies = []
        if overlap_detected:      anomalies.append("overlap")
        if misalign_detected:     anomalies.append("misaligned_offset")
        if small_fragment_detected: anomalies.append("small_fragment")
        if too_many_frags_detected: anomalies.append("excessive_fragments")
        if high_entropy_detected: anomalies.append("high_entropy_payload")
        print(f"[Alert] Anomalies detected for {datagram_key}: " + ", ".join(anomalies))
        log_entry = {
            "timestamp": time.time(),
            "datagram_key": datagram_key,
            "anomalies": anomalies,
            "alert": True
        }
        log_entries.append(log_entry)
    else:
        log_entry = {
            "timestamp": time.time(),
            "datagram_key": datagram_key,
            "anomalies": [],
            "alert": False
        }
        log_entries.append(log_entry)