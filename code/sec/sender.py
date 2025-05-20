import string
import os
import time
import random
import argparse
import string
from scapy.all import IP, UDP, send

def encode_and_mask(chunk_bits, prng):
    raw_val = int(chunk_bits, 2)
    mask    = prng.getrandbits(len(chunk_bits))
    return raw_val ^ mask

def send_covert_data(dest_ip, dest_port, message, delay, key,
                     bits_per_packet, payload_min, payload_max):
    prng      = random.Random(key)
    data_bits = bits_per_packet

    bitstream = ''.join(format(ord(c), '08b') for c in message)
    pad_len   = (data_bits - len(bitstream) % data_bits) % data_bits
    bitstream += '0' * pad_len

    chunks = [bitstream[i:i+data_bits]
              for i in range(0, len(bitstream), data_bits)]
    bit_buffer = ""

    for idx, chunk in enumerate(chunks):
        time.sleep(delay + random.uniform(-delay/2, delay/2))

        masked   = encode_and_mask(chunk, prng)
        pkt = IP(dst=dest_ip, flags="MF", frag=masked) \
              / UDP(sport=4444, dport=dest_port) \
              / os.urandom(random.randint(payload_min, payload_max))
        send(pkt, verbose=0)
        print(f"[Sender] Sent chunk {idx}: bits={chunk}")

        bit_buffer += chunk
        while len(bit_buffer) >= 8:
            byte_str   = bit_buffer[:8]
            bit_buffer = bit_buffer[8:]
            ch         = chr(int(byte_str, 2))
            if ch == "\x04":
                print("[Sender] EOF; done")
                return
            print(f"[Sender] → Assembled char: {ch!r} from {byte_str}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--ip", default="10.0.0.21", help="Destination IP")
    p.add_argument("--port",        type=int, default=8888)
    p.add_argument("--message",     default="Hello InS\x04")
    p.add_argument("--delay",       type=float, default=0.01)
    p.add_argument("--key",         type=int, default=42)
    p.add_argument("--bits",        type=int, default=4,
                   help="Number of data bits per packet")
    p.add_argument("--payload-min", type=int, default=4)
    p.add_argument("--payload-max", type=int, default=16)
    p.add_argument("--message-length", type=int,
                   help="If set, send random message of this length")
    args = p.parse_args()

    if args.bits < 1:
        p.error("--bits must be ≥1")

    if args.message_length:
        msg = ''.join(random.choices(string.ascii_letters + string.digits,
                                     k=args.message_length)) + "\x04"
    else:
        msg = args.message

    send_covert_data(args.ip, args.port, msg, args.delay, args.key,
                     args.bits, args.payload_min, args.payload_max)
