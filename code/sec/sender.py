import os
import time
import random
import argparse
import string
import hashlib
from scapy.all import IP, UDP, send

def create_prng(key, chunk_index):
    if isinstance(key, int):
        key_bytes = str(key).encode('utf-8')
    else:
        key_bytes = key.encode('utf-8')

    hash_input = key_bytes + str(chunk_index).encode('utf-8')
    hash_val = hashlib.md5(hash_input).digest()
    seed = int.from_bytes(hash_val[:4], byteorder='little')
    return random.Random(seed)

def encode_and_mask(chunk_bits, prng):
    raw_val = int(chunk_bits, 2)
    
    mask1 = prng.getrandbits(len(chunk_bits))
    masked_val = raw_val ^ mask1
    
    mask2 = (mask1 ^ 0xA5) & ((1 << len(chunk_bits)) - 1)
    masked_val = (masked_val ^ mask2)
    
    return masked_val & 0x1FFF

def generate_realistic_fragmentation(idx, total_chunks, base_prng):
    is_first = (idx % 5 == 0)

    is_last = (idx % 5 == 4)
    
    if is_first:
        frag_offset = 0
    else:
        frag_offset = ((idx % 5) * 185) & 0x1FFF

    if is_last:
        flags = 0
    else:
        flags = "MF"
        
    return flags, frag_offset

def generate_realistic_network_behavior(idx, base_prng):
    ttl = base_prng.choice([32, 48, 56, 60, 64, 128])

    ip_id = base_prng.randint(1000, 65535)

    if base_prng.random() < 0.8:
        flags = 0
    else:
        flags = "MF"
    
    return ttl, ip_id, flags

def generate_realistic_timing(base_delay, idx, base_prng):
    if idx > 0 and idx % base_prng.randint(8, 16) == 0:
        return base_delay * base_prng.uniform(2.0, 5.0)

    if idx > 2 and idx % 7 == 0 and base_prng.random() < 0.3:
        return base_delay * 0.4

    jitter = base_prng.gauss(0, 0.3) * base_delay
    return max(0.001, base_delay + jitter)

def send_covert_data(dest_ip, dest_port, message, delay, key,
                     bits_per_packet, payload_min, payload_max):

    base_prng = random.Random(key)
    data_bits = bits_per_packet
    
    bitstream = ''.join(format(ord(c), '08b') for c in message)
    pad_len = (data_bits - len(bitstream) % data_bits) % data_bits
    bitstream += '0' * pad_len
    
    chunks = [bitstream[i:i+data_bits] for i in range(0, len(bitstream), data_bits)]
    bit_buffer = ""
    
    total_chunks = len(chunks)
    print(f"[Sender] Starting transmission of {len(message)} chars ({total_chunks} packets)")
    print(f"[Sender] Using key: {key}")

    packet_times = []
    ip_id_values = []
    fragment_values = []

    for idx, chunk in enumerate(chunks):
        chunk_prng = create_prng(key, idx)

        packet_delay = generate_realistic_timing(delay, idx, base_prng)
        time.sleep(packet_delay)
        packet_times.append(time.time())

        frag_value = encode_and_mask(chunk, chunk_prng)
        fragment_values.append(frag_value)

        flags, frag_offset = generate_realistic_fragmentation(idx, total_chunks, base_prng)

        ttl, ip_id, flags_behavior = generate_realistic_network_behavior(idx, base_prng)
        ip_id_values.append(ip_id)
        
        actual_flags = flags
        
        if idx % 3 == 0 and frag_value == 0:
            actual_flags = "MF"

        if idx % 5 == 4:
            payload_size = base_prng.randint(payload_min, max(payload_min+4, payload_max//2))
        else:
            payload_size = base_prng.randint(payload_min, payload_max)

        pkt = IP(
            dst=dest_ip, 
            flags=actual_flags, 
            frag=frag_value,
            id=ip_id,
            ttl=ttl
        ) / UDP(
            sport=base_prng.randint(49152, 65535),
            dport=dest_port
        ) / os.urandom(payload_size)
        
        send(pkt, verbose=0)
        
        flags_text = "MF" if actual_flags == 1 or actual_flags == "MF" else "none"
        print(f"[Sender] Sent chunk {idx}/{total_chunks-1}: bits={chunk}, masked={frag_value}, frag={frag_value}, flags={flags_text}, delay={packet_delay:.3f}s")
        
        bit_buffer += chunk
        while len(bit_buffer) >= 8:
            byte_str = bit_buffer[:8]
            bit_buffer = bit_buffer[8:]
            ch = chr(int(byte_str, 2))
            if ch == "\x04":
                print("[Sender] EOF detected, transmission complete")

                if len(packet_times) > 1:
                    delays = [packet_times[i] - packet_times[i-1] for i in range(1, len(packet_times))]
                    avg_delay = sum(delays) / len(delays)
                    jitter = sum(abs(d - avg_delay) for d in delays) / len(delays)
                    print(f"[Sender] Average delay: {avg_delay:.3f}s, jitter: {jitter:.3f}s")
                
                for i in range(3):
                    time.sleep(delay * base_prng.uniform(0.5, 1.5))
                    trailing_offset = i * 185
                    trailing_flags = "MF" if i < 2 else 0
                    
                    trailer = IP(
                        dst=dest_ip, 
                        flags=trailing_flags,
                        frag=trailing_offset,
                        id=base_prng.randint(1000, 65535),
                        ttl=base_prng.choice([32, 48, 56, 60, 64, 128])
                    ) / UDP(
                        sport=base_prng.randint(49152, 65535),
                        dport=dest_port
                    ) / os.urandom(base_prng.randint(payload_min, payload_max))
                    
                    send(trailer, verbose=0)
                    print(f"[Sender] Sent trailing packet {i+1}/3: frag={trailing_offset}, flags={trailing_flags}")
                    
                return
            print(f"[Sender] → Assembled char: {ch!r} from {byte_str}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--ip", default="10.0.0.21", help="Destination IP")
    p.add_argument("--port", type=int, default=8888)
    p.add_argument("--message", default="Hello Insecurenet. I am Furkan. I am a student at METU CENG Department.\x04")
    p.add_argument("--delay", type=float, default=0.1)
    p.add_argument("--key", type=int, default=42)
    p.add_argument("--bits", type=int, default=4, help="Number of data bits per packet")
    p.add_argument("--payload-min", type=int, default=4)
    p.add_argument("--payload-max", type=int, default=16)
    args = p.parse_args()
    
    if args.bits < 1:
        p.error("--bits must be ≥1")
        
    send_covert_data(args.ip, args.port, args.message, args.delay, args.key,
                     args.bits, args.payload_min, args.payload_max)