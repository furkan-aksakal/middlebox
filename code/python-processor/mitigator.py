import time
import random
import numpy as np
from scapy.all import IP
from detector import process_frag_for_detection, log_entries

WINDOW_SIZE = 50
MITIGATION_WINDOW = 20

normal_fragments = []
MAX_NORMAL_SAMPLES = 100

mitigation_active = False
mitigation_count = 0
covert = []
not_covert = []
counter = 0
def mitigate_packet(pkt):
    global mitigation_active, mitigation_count, normal_fragments, counter, covert, not_covert

    if IP not in pkt:
        return pkt

    ip_layer = pkt[IP]
    frag = ip_layer.frag

    if not mitigation_active and frag > 0:
        if len(normal_fragments) < MAX_NORMAL_SAMPLES:
            normal_fragments.append(frag)
        elif random.random() < 0.1:
            idx = random.randint(0, MAX_NORMAL_SAMPLES - 1)
            normal_fragments[idx] = frag

    process_frag_for_detection(pkt)

    if log_entries and log_entries[-1].get("alert", False):
        covert.append(counter)
        counter += 1
        mitigation_active = True
        mitigation_count = MITIGATION_WINDOW
        log_entries[-1]["alert"] = False
        print("[MITIGATOR] Mitigation phase engaged")
    else:
        not_covert.append(counter)
        counter += 1
    
    print("covert:", covert)
    print("not_covert:", not_covert)

    if mitigation_active:
        mitigation_count -= 1
        if mitigation_count <= 0:
            mitigation_active = False
            print("[MITIGATOR] Mitigation phase ended")
        else:
            if frag > 0:
                if normal_fragments:
                    new_frag = random.choice(normal_fragments)
                else:
                    new_frag = random.randint(1, 20) * 185

                print(f"[MITIGATOR] Randomized pkt frag={frag} → {new_frag}, {mitigation_count} steps remaining")
                pkt[IP].frag = new_frag

                if random.random() < 0.7:
                    pkt[IP].flags = random.choice([0, 1])

                if random.random() < 0.5:
                    print("[MITIGATOR] Packet dropped during mitigation")
                    return None

    pkt[IP].id = random.randint(0, 0xFFFF)
    pkt[IP].ttl = random.randint(30, 64)

    return pkt