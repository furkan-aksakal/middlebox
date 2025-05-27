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

    normal_packet_interval = max(5, total_chunks // 10)

    for idx, chunk in enumerate(chunks):
        chunk_prng = create_prng(key, idx)

        packet_delay = delay
        if idx > 0 and idx % 10 == 0:
            packet_delay = delay * base_prng.uniform(2, 5)
            
        time.sleep(packet_delay + random.uniform(-packet_delay/3, packet_delay/3))

        masked = encode_and_mask(chunk, chunk_prng)

        flags, frag_offset = generate_realistic_fragmentation(idx, total_chunks, base_prng)

        is_decoy = (idx % normal_packet_interval == normal_packet_interval - 1)
        
        if is_decoy:
            frag_value = masked
            print(f"[Sender] Sending decoy packet (still carries data)")
        else:
            frag_value = masked

        pkt = IP(
            dst=dest_ip, 
            flags=flags, 
            frag=frag_value,
            id=base_prng.randint(1000, 65535)
        ) / UDP(
            sport=base_prng.randint(49152, 65535),
            dport=dest_port
        ) / os.urandom(base_prng.randint(payload_min, payload_max))
        
        send(pkt, verbose=0)
        flags_text = "MF" if flags == 1 else "none"
        print(f"[Sender] Sent chunk {idx}/{total_chunks-1}: bits={chunk}, masked={frag_value}, flags={flags_text}")
        
        bit_buffer += chunk
        while len(bit_buffer) >= 8:
            byte_str = bit_buffer[:8]
            bit_buffer = bit_buffer[8:]
            ch = chr(int(byte_str, 2))
            if ch == "\x04":
                print("[Sender] EOF detected, transmission complete")

                for i in range(3):
                    time.sleep(delay * base_prng.uniform(0.5, 1.5))
                    trailer = IP(dst=dest_ip, flags=0) / UDP(sport=base_prng.randint(49152, 65535), dport=dest_port) / os.urandom(payload_min)
                    send(trailer, verbose=0)
                    print("[Sender] Sent trailing packet")
                    
                return
            print(f"[Sender] → Assembled char: {ch!r} from {byte_str}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--ip", default="10.0.0.21", help="Destination IP")
    p.add_argument("--port", type=int, default=8888)
    p.add_argument("--message", default="Hello Insecurenet. I am furkan. I am ceng student at METU. this is information hiding\x04")
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