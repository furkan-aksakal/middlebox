import time
import random
import argparse
import asyncio
from scapy.all import IP, AsyncSniffer
from nats.aio.client import Client as NATS

def decode_and_unmask(frag, prng, bits_per_packet):
    data_bits = bits_per_packet
    mask   = prng.getrandbits(data_bits)
    raw    = frag ^ mask
    return format(raw, f'0{data_bits}b')

async def start_receiver(iface, nc, key, bits_per_packet):
    prng       = random.Random(key)
    bit_buffer = ""
    message    = ""
    start_time = None
    loop       = asyncio.get_running_loop()

    async def handle(pkt):
        nonlocal bit_buffer, message, start_time
        if IP not in pkt:
            return
        frag = pkt[IP].frag
        bits = decode_and_unmask(frag, prng, bits_per_packet)
        if bits is None:
            return

        if start_time is None:
            start_time = time.time()
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
    p.add_argument("--key",   type=int, default=42)
    p.add_argument("--bits",  type=int, default=4)
    p.add_argument("--nats",  default="nats://admin:admin@nats:4222")
    args = p.parse_args()

    nc = NATS()
    async def main():
        await nc.connect(servers=[args.nats])
        await start_receiver(args.iface, nc, args.key, args.bits)
    asyncio.run(main())
