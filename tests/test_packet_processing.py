import time
from unittest import mock

from netfilterqueue import Packet as test_packet
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS

client_hello = Ether(
    bytes.fromhex(
        "0000000000000000000000000800450000ac1c184000400620327f0000017f000001973a01bb787c608f78bc736680187ffffea000000101080a1f537c981f537c9816030000730100006f03000034011e673afaced951bae4fc64950382630fe3396bc7bd2be5513723485bfb20a3caad46955d64bb33ecb5129121a350d2c0c5f667c3cc9ec04a711b92dc585500280039003800350033003200040005002f00160013feff000a00150012fefe000900640062000300060100"
    )
)


def test_tls_version_change(packet_processor):
    with mock.patch(
        "amphivena.packet_processing.PacketProcessor.finalize"
    ) as mock_accept:
        pkt = test_packet()

        assert client_hello.haslayer(TLS)
        assert hex(client_hello.getlayer(TLS).msg[0].msgtype) == hex(1)
        assert hex(client_hello.getlayer(TLS).version) == hex(768)
        # TODO need to understand how to rebuild scapy when modifying the TLS message itself - for some reason it
        #   will not automatically rebuild as expected
        #   ex. client_hello.getlayer(TLS).msg[0].version

        pkt.set_payload(client_hello.__bytes__())
        packet_processor.manipulate(pkt)

        assert hex(
            Ether(mock_accept.call_args[0][0].get_payload()).getlayer(TLS).version
        ) == hex(772)


def test_run(packet_processor):
    pkt = test_packet()
    pkt.set_payload(client_hello.__bytes__())

    packet_processor.pre_process(pkt)
    assert False
