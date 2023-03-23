import re
from unittest import mock

import pytest

from amphivena.playbook_utils import PlaybookValidationError


def test_file_not_found(new_packet_processor):
    """Playbook does not exist."""
    with pytest.raises(PlaybookValidationError, match="^Playbook not found: "):
        new_packet_processor.get("foo/bar.json")


def test_json_error(new_packet_processor):
    """Playbook with invalid json."""
    playbook_json = """
    {"is_ordered: true}
    """
    with pytest.raises(
        PlaybookValidationError,
        match="^Playbook json invalid: Invalid control character",
    ):
        # Cleaner to mock file contents than make lots of small files
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_json)):
            new_packet_processor.get("mocked.json")


def test_required_fields_root(new_packet_processor):
    """Playbook missing required root field."""
    playbook_json = "{}"
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape("Playbook schema invalid:\n('is_ordered',): field required"),
    ):
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_json)):
            new_packet_processor.get("mocked.json")


def test_optional_fields_root(new_packet_processor):
    """Test default values for root field."""
    playbook_assignments = """{"is_ordered":true,"loop_when_complete":true,"remove_spent_instructions":false}"""
    playbook_no_assignments = """{"is_ordered":true}"""

    with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_assignments)):
        packet_processor = new_packet_processor.get("mocked.json")
        assert packet_processor._loop_when_complete is False
        assert packet_processor._remove_spent_instructions is True

    with mock.patch("builtins.open", mock.mock_open(read_data=playbook_assignments)):
        packet_processor = new_packet_processor.get("mocked.json")
        assert packet_processor._loop_when_complete is True
        assert packet_processor._remove_spent_instructions is False


def test_required_fields_instruction(new_packet_processor):
    """Playbook missing required instruction field(s)."""
    playbook_no_operation = """{"is_ordered":true,"instructions":{"1":{}}}"""

    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'operation'): field required"
        ),
    ):
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=playbook_no_operation)
        ):
            new_packet_processor.get("mocked.json")


def test_required_fields_condition(new_packet_processor):
    """Playbook missing condition fields."""
    playbook_no_layer = """{"is_ordered":true,"instructions":{"1":{"operation":"edit","conditions":[{"field":"sport","comparator":"is","value":38713}]}}}"""
    playbook_no_field = """{"is_ordered":true,"instructions":{"1":{"operation":"edit","conditions":[{"layer":"TCP","comparator":"is","value":38713}]}}}"""
    playbook_no_comparator = """{"is_ordered":true,"instructions":{"1":{"operation":"edit","conditions":[{"layer":"TCP","field":"sport","value":38713}]}}}"""
    playbook_no_value = """{"is_ordered":false,"instructions":{"1":{"operation":"edit","conditions":[{"layer":"TCP","field":"sport","comparator":"is"}]}}}"""

    # Required step condition field "layer"
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'conditions', 0, 'layer'): field required"
        ),
    ):
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_layer)):
            new_packet_processor.get("mocked.json")

    # Required step condition field "field"
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'conditions', 0, 'field'): field required"
        ),
    ):
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_field)):
            new_packet_processor.get("mocked.json")

    # Required step condition field "comparator"
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'conditions', 0, 'comparator'): field required"
        ),
    ):
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=playbook_no_comparator)
        ):
            new_packet_processor.get("mocked.json")

    # Optional step condition field "value"
    with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_value)):
        packet_processor = new_packet_processor.get("mocked.json")
        assert packet_processor is not None
        assert packet_processor._playbook_is_ordered is False


def test_required_fields_action(new_packet_processor):
    """Playbook missing required action fields."""
    playbook_no_type = """{"is_ordered":true,"instructions":{"1":{"operation":"edit","actions":[{"layer":"TCP","field":"sport","value":"0x3039"}]}}}"""
    playbook_no_field = """{"is_ordered":true,"instructions":{"1":{"operation":"edit","actions":[{"layer":"TCP","type":"modify","value":"0x3039"}]}}}"""
    playbook_no_value = """{"is_ordered":false,"instructions":{"1":{"operation":"edit","actions":[{"layer":"TCP","type":"modify","field":"sport"}]}}}"""

    # Required step action field "type"
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'actions', 0, 'type'): field required"
        ),
    ):
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_type)):
            new_packet_processor.get("mocked.json")

    # Required step action field "field"
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'actions', 0, 'field'): field required"
        ),
    ):
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_field)):
            new_packet_processor.get("mocked.json")

    # Optional step action field "value"
    with mock.patch("builtins.open", mock.mock_open(read_data=playbook_no_value)):
        packet_processor = new_packet_processor.get("mocked.json")
        assert packet_processor is not None
        assert packet_processor._playbook_is_ordered is False


def test_invalid_operation(new_packet_processor):
    """Playbook with invalid instruction.operation value."""
    playbook_json = """{"is_ordered":true,"instructions":{"1":{"operation":"TRASH"}}}"""
    with pytest.raises(
        PlaybookValidationError,
        match=re.escape(
            "Playbook schema invalid:\n('instructions', '1', 'operation'): value is not a valid enumeration member; permitted: 'edit', 'drop'"
        ),
    ):
        with mock.patch("builtins.open", mock.mock_open(read_data=playbook_json)):
            new_packet_processor.get("mocked.json")
