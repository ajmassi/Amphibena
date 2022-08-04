from unittest import mock

import pytest
from netfilterqueue import Packet as test_packet
from scapy.layers.inet import IP, TCP


def test_tcp_mods(new_packet_processor, new_tls_client_hello):
    # Change TCP.sport from 38713 to 12345
    with mock.patch(
        "amphivena.packet_processor.PacketProcessor._finalize"
    ) as mock_accept:
        packet_processor = new_packet_processor.get(
            "demo.json"
        )

        pkt = test_packet()
        pkt.set_payload(new_tls_client_hello.__bytes__())

        assert new_tls_client_hello.getlayer(TCP).sport == 38713
        packet_processor._process(pkt)

        assert (
            IP(mock_accept.call_args[0][0].get_payload()).getlayer(TCP).sport == 12345
        )
