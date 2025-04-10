import argparse
import asyncio
import os
import time
from dotenv import load_dotenv
from scapy.all import IP, AsyncSniffer
from nats.aio.client import Client as NATS

load_dotenv()

def decode_bits_from_frag(frag, key, bits_per_packet):
    val = (frag - key) % (2 ** bits_per_packet)
    return format(val, f'0{bits_per_packet}b')

async def start_receiver(iface, nc, key, bits_per_packet):
    bit_buffer = ""
    char_buffer = ""
    start_time = None
    loop = asyncio.get_running_loop()

    async def handle_packet(packet):
        nonlocal bit_buffer, char_buffer, start_time
        if IP in packet:
            frag = packet[IP].frag
            bits = decode_bits_from_frag(frag, key, bits_per_packet)
            bit_buffer += bits

            if start_time is None:
                start_time = time.time()
            
            while len(bit_buffer) >= 8:
                char = chr(int(bit_buffer[:8], 2))
                char_buffer += char
                bit_buffer = bit_buffer[8:]

                if char == "\x04":
                    end_time = time.time()
                    duration = end_time - start_time
                    print("[Receiver] EOF received. Full message:", char_buffer[:-1])
                    print(f"[Receiver] 🕒 Message received in {duration:.3f} seconds")
                    await nc.close()
                    sniffer.stop()
                    return
                else:
                    print(f"[Receiver] Got char: {repr(char)}")

            await nc.publish("outpktinsec", bytes(packet[IP]))

    def packet_callback(pkt):
        asyncio.run_coroutine_threadsafe(handle_packet(pkt), loop)

    sniffer = AsyncSniffer(
        iface=iface,
        filter="ip and udp",
        prn=packet_callback
    )
    sniffer.start()
    print(f"[Receiver] Listening on {iface} with bits={bits_per_packet} and key={key}")

    try:
        while sniffer.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
        await nc.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--key", type=int, default=2, help="Key for decoding (between 1 and 3)")
    parser.add_argument("--bits", type=int, default=2, help="Bits per packet (between 1 and 8)")
    parser.add_argument(
        "--nats",
        default=os.getenv("NATS_SURVEYOR_SERVERS", "nats://admin:admin@nats:4222"),
        help="NATS server URL"
    )

    args = parser.parse_args()
    nc = NATS()

    async def main():
        print(f"[Receiver] Connecting to NATS at {args.nats}")
        await nc.connect(servers=[args.nats])
        await start_receiver(args.iface, nc, args.key, args.bits)

    asyncio.run(main())
