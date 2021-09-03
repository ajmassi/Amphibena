import logging
import multiprocessing

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

log = logging.getLogger(__name__)


def proc_start():
    p = multiprocessing.Process(target=run)
    p.start()
    return p


def proc_stop(p):
    if p._closed is False:
        p.terminate()
        p.join()
        p.close()


def print_and_accept(pkt):
    print(IP(pkt.get_payload()).show())
    pkt.accept()


def run():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        print("starting nfqueue")
        log.info("starting nfqueue")
        nfqueue.run()
    except KeyboardInterrupt:
        print("shutting down nfqueue")

    nfqueue.unbind()
