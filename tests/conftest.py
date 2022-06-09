import pytest

from amphivena.packet_processor import PacketProcessor


@pytest.fixture()
def packet_processor():
    config_file_path = "/home/alex/PycharmProjects/Amphivena/tests/demo.json"

    yield PacketProcessor(config_file_path)
