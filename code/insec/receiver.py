import argparse
import asyncio
import os
from dotenv import load_dotenv
from scapy.all import IP, AsyncSniffer
from nats.aio.client import Client as NATS

load_dotenv()

def decode_bit_from_frag(frag):
    return '1' if (frag & 1) else '0'

async def start_receiver(iface, nc):
    bit_buffer = ""
    char_buffer = ""
    loop = asyncio.get_running_loop()

    async def handle_packet(packet):
        nonlocal bit_buffer, char_buffer
        if IP in packet:
            frag = packet[IP].frag
            bit = decode_bit_from_frag(frag)
            bit_buffer += bit
            if len(bit_buffer) >= 8:
                char = chr(int(bit_buffer[:8], 2))
                
                char_buffer += char
                bit_buffer = bit_buffer[8:]

                if char == "\x04":
                    print("[Receiver] EOF received. Full message:", char_buffer[:-1])
                    await nc.close()
                    sniffer.stop()
                else:
                    print(f"[Receiver] Got char: {char}")
            
            await nc.publish("outpktinsec", bytes(packet[IP]))

    def packet_callback(pkt):
        asyncio.run_coroutine_threadsafe(handle_packet(pkt), loop)

    sniffer = AsyncSniffer(
        iface=iface,
        filter="ip and udp",
        prn=packet_callback
    )
    sniffer.start()
    print("[Receiver] Listening for covert data...")

    try:
        while sniffer.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
        await nc.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="eth0")
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
        await start_receiver(args.iface, nc)

    asyncio.run(main())
