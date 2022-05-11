import logging
import multiprocessing

import netfilterqueue
import scapy.layers.tls.handshake
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS

log = logging.getLogger(__name__)


def proc_start():
    p = multiprocessing.Process(target=run)
    p.start()
    return p


def proc_stop(p):
    # TODO: This works but is sketchy, should consider better means of controlling the process
    if p._closed is False:
        p.terminate()
        p.join()
        p.close()


def accept(pkt):
    # Wrapped for mocking during tests - cdef functions are un-mockable
    pkt.accept()


def print_and_accept(pkt):
    scapy_packet = Ether(bytes(pkt.get_payload()))

    # Basic PoC processing attempt
    if (
        scapy_packet.haslayer(TLS)
        and type(scapy_packet.getlayer(TLS).msg[0])
        is scapy.layers.tls.handshake.TLSClientHello
    ):
        scapy_packet.getlayer(TLS).version = 0x0304

    pkt.set_payload(scapy_packet.build())
    accept(pkt)


def run():
    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        print("starting nfqueue")
        log.info("starting nfqueue")
        nfqueue.run()
    except KeyboardInterrupt:
        print("shutting down nfqueue")

    nfqueue.unbind()
