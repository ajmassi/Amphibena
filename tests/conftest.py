import json
from unittest import mock

import pytest

from amphivena.packet_processing import PacketProcessor


@pytest.fixture()
def packet_processor():
    with open("tests/demo.json", "r") as js_conf:
        data = js_conf.read()

    obj = json.loads(data)

    # with mock.patch("netfilterqueue.NetfilterQueue"):
    yield PacketProcessor(obj)
