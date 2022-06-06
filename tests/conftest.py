import pytest

from amphivena.packet_processing import PacketProcessor


@pytest.fixture()
def packet_processor():
    config_file_path = "tests/demo.json"

    yield PacketProcessor(config_file_path)
