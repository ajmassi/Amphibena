import json
import logging
import multiprocessing

import netfilterqueue
import scapy.layers.tls.handshake
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS

log = logging.getLogger(__name__)


class PacketProcessor:
    def __init__(self, config_file_path):
        self._config_data = {}
        try:
            with open(config_file_path, "r") as f:
                self._config_data = json.load(f)
        except FileNotFoundError():
            print("File not found")

        self._current_step = 1
        self._step_count = len(self._config_data)
        self.proc = None

    def start(self):
        self.proc = multiprocessing.Process(target=self.examine_packets)
        self.proc.start()
        return self.proc

    def stop(self):
        # TODO: This works but is sketchy, should consider better means of controlling the process
        if self.proc._closed is False:
            self.proc.terminate()
            self.proc.join()
            self.proc.close()

    def pre_process(self, pkt):
        if self._current_step > self._step_count:
            log.error("No packet operations left!")
            return

        operation = self._config_data.get(str(self._current_step))

        # Parse packet
        # TODO using 'Ether' should work for initial use cases and testing, but may need to work out better future solution
        scapy_packet = Ether(pkt)

        try:
            if operation["Operation"] == "Drop":
                self.drop_packet(pkt, scapy_packet, operation)
            elif operation["Operation"] == "Edit":
                self.edit_packet(pkt, scapy_packet, operation)
            else:
                log.error(f"Unknown packet operation {operation.get('Operation')}")
        except KeyError():
            log.error("Packet operation [Drop, Edit] not defined.")

    def drop_packet(self, pkt, scapy_packet, operation):
        if scapy_packet.haslayer(operation.get("Layer")):
            pkt.drop()

    def edit_packet(self, pkt, scapy_packet, operation):
        # Basic PoC processing attempt
        if (
            scapy_packet.haslayer(TLS)
            and type(scapy_packet.getlayer(TLS).msg[0])
            is scapy.layers.tls.handshake.TLSClientHello
        ):
            scapy_packet.getlayer(TLS).version = 0x0304

        scapy_packet.set_payload(scapy_packet.build())
        self.post_process(pkt)

    def post_process(self, pkt, scapy_packet):
        pkt.set_payload(scapy_packet.build())
        self.finalize(pkt)
        self._current_step += 1

    @staticmethod
    def finalize(pkt):
        # Wrapped for mocking during tests - cdef functions are un-mockable
        pkt.accept()

    def examine_packets(self):
        nfqueue = netfilterqueue.NetfilterQueue()
        nfqueue.bind(1, self.pre_process)
        try:
            print("starting nfqueue")
            log.info("starting nfqueue")
            nfqueue.run()
        except KeyboardInterrupt:
            print("shutting down nfqueue")

        nfqueue.unbind()
