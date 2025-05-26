import time
import random
import argparse
import asyncio
import hashlib
from scapy.all import IP, AsyncSniffer
from nats.aio.client import Client as NATS

def create_prng(key, chunk_index):
    if isinstance(key, int):
        key_bytes = str(key).encode('utf-8')
    else:
        key_bytes = key.encode('utf-8')

    hash_input = key_bytes + str(chunk_index).encode('utf-8')
    hash_val = hashlib.md5(hash_input).digest()
    seed = int.from_bytes(hash_val[:4], byteorder='little')
    return random.Random(seed)

def decode_and_unmask(frag, prng, bits_per_packet):
    frag = frag & 0x1FFF
    
    mask1 = prng.getrandbits(bits_per_packet)
    mask2 = (mask1 ^ 0xA5) & ((1 << bits_per_packet) - 1)

    intermediate = frag ^ mask2

    raw_val = intermediate ^ mask1

    raw_val = raw_val & ((1 << bits_per_packet) - 1)

    return format(raw_val, f'0{bits_per_packet}b')

async def start_receiver(iface, nc, key, bits_per_packet):
    base_prng = random.Random(key)
    bit_buffer = ""
    message = ""
    start_time = None
    loop = asyncio.get_running_loop()
    packet_count = 0
    
    print(f"[Receiver] Starting with key: {key}")
    
    async def handle(pkt):
        nonlocal bit_buffer, message, start_time, packet_count

        if IP not in pkt:
            return

        frag = pkt[IP].frag
        flags = pkt[IP].flags

        if flags != 1:
            return

        chunk_prng = create_prng(key, packet_count)

        bits = decode_and_unmask(frag, chunk_prng, bits_per_packet)
        
        packet_count += 1
        
        if bits is None:
            print(f"[Receiver] Failed to decode packet {packet_count}")
            return

        print(f"[Receiver] Packet {packet_count}: frag={frag}, decoded={bits}")

        if start_time is None:
            start_time = time.time()
            print("[Receiver] First packet received, starting message assembly")

        bit_buffer += bits

        while len(bit_buffer) >= 8:
            b = bit_buffer[:8]
            bit_buffer = bit_buffer[8:]
            ch = chr(int(b, 2))
            
            if ch == "\x04":
                duration = time.time() - start_time
                print("[Receiver] EOF; message:", message)
                print(f"[Receiver] 🕒 Time: {duration:.3f}s")
                await nc.close()
                sniffer.stop()
                return

            message += ch
            print(f"[Receiver] Got char: {ch!r}")
        
        await nc.publish("outpktinsec", bytes(pkt[IP]))

    def cb(pkt):
        asyncio.run_coroutine_threadsafe(handle(pkt), loop)
        return None

    sniffer = AsyncSniffer(
        iface=iface,
        filter="ip and udp",
        prn=cb,
        store=False
    )
    sniffer.start()
    print(f"[Receiver] Hardened receiver on {iface}, bits={bits_per_packet}")

    try:
        while sniffer.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
        await nc.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default="eth0")
    p.add_argument("--key", type=int, default=42)
    p.add_argument("--bits", type=int, default=4)
    p.add_argument("--nats", default="nats://admin:admin@nats:4222")
    args = p.parse_args()

    nc = NATS()
    async def main():
        await nc.connect(servers=[args.nats])
        await start_receiver(args.iface, nc, args.key, args.bits)
    asyncio.run(main())