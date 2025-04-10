import os
import time
import random
import argparse
import string
from scapy.all import IP, UDP, send

def encode_bits_in_frag(bits_str, key, bits_per_packet):
    return (int(bits_str, 2) + key) % (2 ** bits_per_packet)

def send_covert_data(dest_ip, dest_port, message, delay, key, bits_per_packet):
    print(f"[Sender] Sending to {dest_ip}:{dest_port} with delay={delay}, bits={bits_per_packet}")

    bitstream = ''.join(format(ord(c), '08b') for c in message)

    pad_len = (bits_per_packet - (len(bitstream) % bits_per_packet)) % bits_per_packet
    if pad_len > 0:
        bitstream += '0' * pad_len
    
    chunks = [bitstream[i:i+bits_per_packet] for i in range(0, len(bitstream), bits_per_packet)]

    for i, chunk in enumerate(chunks):
        frag_val = encode_bits_in_frag(chunk, key, bits_per_packet)
        payload_len = random.randint(4, 16)
        payload = os.urandom(payload_len)
        packet = IP(dst=dest_ip, flags="MF", frag=frag_val) / UDP(sport=4444, dport=dest_port) / payload
        send(packet, verbose=0)
        time.sleep(delay)

        if i % (8 // bits_per_packet) == 0:
            char_index = i // (8 // bits_per_packet)
            if char_index < len(message):
                print(f"[Sender] Sent: {repr(message[char_index])}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default=os.getenv("INSECURENET_HOST_IP"))
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--message", default="Hello InSecureNet" + "\x04")
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--key", type=int, default=2, help="Key for encoding (between 1 and 3)")
    parser.add_argument("--bits", type=int, default=2, help="Bits per packet (between 1 and 8)")
    parser.add_argument("--message-length", type=int, help="Length of random message (optional)")

    args = parser.parse_args()
    if not args.ip:
        print("INSECURENET_HOST_IP is not set in environment.")
    else:
        if args.message_length:
            random_message = ''.join(random.choices(string.ascii_letters + string.digits, k=args.message_length))
            send_covert_data(args.ip, args.port, random_message + "\x04", args.delay, args.key, args.bits)
        else:
            send_covert_data(args.ip, args.port, args.message, args.delay, args.key, args.bits)
