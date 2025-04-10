import os
import time
import argparse
from scapy.all import IP, UDP, send

def encode_bit_in_frag(bit):
    return 1 if bit == '1' else 0

def send_covert_data(dest_ip, dest_port, message, delay):
    print(f"[Sender] Sending to {dest_ip}:{dest_port} with delay={delay}")
    for char in message:
        bits = format(ord(char), '08b')
        for bit in bits:
            frag_val = encode_bit_in_frag(bit)
            packet = IP(dst=dest_ip, flags="MF", frag=frag_val) / UDP(sport=4444, dport=dest_port) / b'A'
            send(packet, verbose=0)
            time.sleep(delay)
        print(f"[Sender] Sent: {char}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default=os.getenv("INSECURENET_HOST_IP"))
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--message", default="Hello InSecureNet" + "\x04")
    parser.add_argument("--delay", type=float, default=0.5)

    args = parser.parse_args()
    if not args.ip:
        print("INSECURENET_HOST_IP is not set in environment.")
    else:
        send_covert_data(args.ip, args.port, args.message, args.delay)
