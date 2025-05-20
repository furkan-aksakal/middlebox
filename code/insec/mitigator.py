import time, random
import numpy as np
from scapy.all import IP
from detector import process_frag_for_detection, log_entries

WINDOW_SIZE       = 50
MITIGATION_WINDOW = 20

mitigation_active = False
mitigation_count  = 0

def mitigate_packet(pkt):

    global mitigation_active, mitigation_count

    if IP not in pkt:
        return pkt

    frag = pkt[IP].frag

    process_frag_for_detection(frag)

    if log_entries and log_entries[-1]["alert"]:
        mitigation_active = True
        mitigation_count = MITIGATION_WINDOW

        log_entries[-1]["alert"] = False
        print("[MITIGATOR] Mitigation phase engaged")

    if mitigation_active:
        mitigation_count -= 1
        if mitigation_count <= 0:
            mitigation_active = False
            print("[MITIGATOR] Mitigation phase ended")
        else:
            pkt[IP].frag = 0
            print(f"[MITIGATOR] Cleaned pkt frag={frag}, {mitigation_count} left")
            return None

    pkt[IP].id  = random.randint(0, 0xFFFF)
    pkt[IP].ttl = random.randint(30, 64)
    return pkt
