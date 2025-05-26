import asyncio
from nats.aio.client import Client as NATS
import os
from scapy.all import Ether, raw
from mitigator import mitigate_packet

async def run():
    nc = NATS()
    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        subject = msg.subject
        data = msg.data 
        pkt = Ether(data)

        print("[RECEIVED PACKET]")
        pkt.show()

        mitigated_pkt = mitigate_packet(pkt)

        if mitigated_pkt is not None:
            out_data = raw(mitigated_pkt)
            if subject == "inpktsec":
                await nc.publish("outpktinsec", out_data)
            else:
                await nc.publish("outpktsec", out_data)
        else:
            print("[MITIGATOR] Dropped a suspicious packet.")

    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print("Subscribed to inpktsec and inpktinsec topics")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    asyncio.run(run())
