import os
import time
import argparse
from scapy.all import IP, UDP, send

def encode_bits_in_frag(bits_str, key, bits_per_packet):
    return (int(bits_str, 2) + key) % (2 ** bits_per_packet)

def send_covert_data(dest_ip, dest_port, message, delay, key, bits_per_packet):
    print(f"[Sender] Sending to {dest_ip}:{dest_port} with delay={delay}, bits={bits_per_packet}")
    for char in message:
        bits = format(ord(char), '08b')
        chunks = [bits[i:i+bits_per_packet] for i in range(0, len(bits), bits_per_packet)]
        for chunk in chunks:
            if len(chunk) < bits_per_packet:
                chunk = chunk.ljust(bits_per_packet, '0')
            frag_val = encode_bits_in_frag(chunk, key, bits_per_packet)
            packet = IP(dst=dest_ip, flags="MF", frag=frag_val) / UDP(sport=4444, dport=dest_port) / b'A'
            send(packet, verbose=0)
            time.sleep(delay)
        print(f"[Sender] Sent: {repr(char)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default=os.getenv("INSECURENET_HOST_IP"))
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--message", default="Hello InSecureNet" + "\x04")
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--key", type=int, default=2, help="Key for encoding (between 0 and 3)")
    parser.add_argument("--bits", type=int, default=2, help="Bits per packet (between 1 and 13)")

    args = parser.parse_args()
    if not args.ip:
        print("INSECURENET_HOST_IP is not set in environment.")
    else:
        send_covert_data(args.ip, args.port, args.message, args.delay, args.key, args.bits)
