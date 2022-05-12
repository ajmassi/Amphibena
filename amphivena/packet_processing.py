import logging
import multiprocessing

import netfilterqueue
import scapy.layers.tls.handshake
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS

log = logging.getLogger(__name__)


class PacketProcessor:
    def __init__(self, config):
        self._config = config
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

    @staticmethod
    def finalize(pkt):
        # Wrapped for mocking during tests - cdef functions are un-mockable
        pkt.accept()

    def manipulate(self, pkt):
        scapy_packet = Ether(bytes(pkt.get_payload()))

        # Basic PoC processing attempt
        if (
            scapy_packet.haslayer(TLS)
            and type(scapy_packet.getlayer(TLS).msg[0])
            is scapy.layers.tls.handshake.TLSClientHello
        ):
            scapy_packet.getlayer(TLS).version = 0x0304

        pkt.set_payload(scapy_packet.build())
        self.finalize(pkt)

    def examine_packets(self):
        nfqueue = netfilterqueue.NetfilterQueue()
        nfqueue.bind(1, self.manipulate)
        try:
            print("starting nfqueue")
            log.info("starting nfqueue")
            nfqueue.run()
        except KeyboardInterrupt:
            print("shutting down nfqueue")

        nfqueue.unbind()
