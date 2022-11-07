from unittest import mock

from netfilterqueue import Packet as nfqPacket
from scapy.layers.inet import IP, TCP
from scapy.compat import bytes_hex


@mock.patch("amphivena.packet_processor.PacketProcessor._finalize")
def test_ordered_edit_tcp_consecutive_packets(mock_accept, new_packet_processor, new_tls_client_hello, new_tls_server_hello):
    """
    Change first packet TCP source port from 38713 to 12345.
    Change second packet TCP destination port from 38713 to 12345.
    """
    packet_processor = new_packet_processor.get("packet_processing/ordered_edit_tcp_consecutive_packets.json")

    pkt = nfqPacket()
    pkt.set_payload(new_tls_client_hello.__bytes__())

    assert new_tls_client_hello.getlayer(TCP).sport == 38713
    packet_processor._process(pkt)

    assert (
        IP(mock_accept.call_args[0][0].get_payload()).getlayer(TCP).sport == 12345
    )

    pkt = nfqPacket()
    pkt.set_payload(new_tls_server_hello.__bytes__())
    assert new_tls_server_hello.getlayer(TCP).dport == 38713

    packet_processor._process(pkt)
    assert (
            IP(mock_accept.call_args[0][0].get_payload()).getlayer(TCP).dport == 12345
    )


@mock.patch("amphivena.packet_processor.PacketProcessor._drop")
def test_ordered_drop_tcp(mock_drop, new_packet_processor, new_tls_client_hello, new_tls_server_hello):
    """Drop TCP packet with source port 443."""
    packet_processor = new_packet_processor.get("packet_processing/ordered_drop_tcp.json")

    # Drop the server hello
    pkt = nfqPacket()
    pkt.set_payload(new_tls_server_hello.__bytes__())
    assert new_tls_server_hello.getlayer(TCP).sport == 443
    packet_processor._process(pkt)

    mock_drop.assert_called_once()


@mock.patch("amphivena.packet_processor.PacketProcessor._drop")
@mock.patch("amphivena.packet_processor.PacketProcessor._finalize")
def test_ordered_drop_tcp_later_packet(mock_accept, mock_drop, new_packet_processor, new_tls_client_hello, new_tls_server_hello):
    """
    Does packet processor skip non-matching packets?
    1. Send non-matching packet
    2. Verify packet was accepted
    3. Send matching packet
    4. Verify packet was dropped
    """
    packet_processor = new_packet_processor.get("packet_processing/ordered_drop_tcp.json")

    # Send client hello first
    pkt = nfqPacket()
    pkt.set_payload(new_tls_client_hello.__bytes__())
    assert new_tls_client_hello.getlayer(TCP).sport == 38713
    packet_processor._process(pkt)
    mock_accept.assert_called_once()

    # Drop the server hello
    pkt = nfqPacket()
    pkt.set_payload(new_tls_server_hello.__bytes__())
    assert new_tls_server_hello.getlayer(TCP).sport == 443
    packet_processor._process(pkt)

    mock_drop.assert_called_once()


@mock.patch("amphivena.packet_processor.PacketProcessor._finalize")
def test_ordered_edit_tcp_multiple_steps_same_packet(mock_accept, new_packet_processor, new_tls_client_hello):
    """
    Multiple instructions match the provided packet.
    Verify the applicable changes were made, but not the unmatched ones.
    """
    packet_processor = new_packet_processor.get("packet_processing/ordered_edit_tcp_multiple_steps_same_packet.json")

    pkt = nfqPacket()
    pkt.set_payload(new_tls_client_hello.__bytes__())

    assert new_tls_client_hello.getlayer(TCP).sport == 38713
    assert new_tls_client_hello.getlayer(IP).ttl == 64
    packet_processor._process(pkt)

    assert (
        IP(mock_accept.call_args[0][0].get_payload()).getlayer(TCP).sport == 12345
    )
    assert (
        IP(mock_accept.call_args[0][0].get_payload()).getlayer(IP).ttl == 255
    )

    # _finalize only called once for both instructions
    mock_accept.assert_called_once()
