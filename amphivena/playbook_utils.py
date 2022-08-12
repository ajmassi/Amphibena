import json
import logging

import jsonschema

log = logging.getLogger(__name__)

schema = {
    "type": "object",
    "properties": {
        "isOrdered": {"type": "boolean"},
        "instructions": {
            "type": "object",
            "patternProperties": {
                "^[0-9]+$": {
                    "properties": {
                        "operation": {"type": "string", "enum": ["edit", "drop"]},
                        "layerGroup": {"type": "string"},
                        "layer": {"type": "string"},
                        "conditions": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "field": {
                                        "type": "string",
                                    },
                                    "comparator": {
                                        "type": "string",
                                    },
                                    "value": {
                                        "type": ["string", "integer"],
                                    },
                                },
                                "required": ["field", "comparator"],
                            },
                        },
                        "actions": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "enum": ["modify", "insert"],
                                    },
                                    "field": {
                                        "type": "string",
                                    },
                                    "value": {
                                        "type": ["string", "integer"],
                                    },
                                },
                                "required": ["type", "field"],
                            },
                        },
                    },
                    "required": ["operation", "layerGroup", "layer"],
                }
            },
            "additionalProperties": False,
        },
    },
    "required": ["isOrdered"],
}


class PlaybookValidationError(Exception):
    """
    Catch-all for errors that can occur during validation of playbook.

    :return: PlaybookValidationError
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def load(playbook_file_path):
    """
    Load playbook file and validate against schema.

    :param playbook_file_path: string representation of playbook file path.
    :return: dict
    :raise PlaybookValidationError: Can expect JSONDecodeError, ValidationError, and FileNotFoundError.
    """
    try:
        with open(playbook_file_path, "r") as f:
            playbook_obj = json.load(f)

        jsonschema.validate(playbook_obj, schema)

        log.info("Playbook validation successful.")
        return playbook_obj
    except json.decoder.JSONDecodeError as e:
        raise PlaybookValidationError(f"Playbook json invalid: {e}")
    except jsonschema.exceptions.ValidationError as e:
        raise PlaybookValidationError(f"Playbook schema invalid: {e.message}")
    except FileNotFoundError as e:
        raise PlaybookValidationError(f"Playbook not found: '{e.filename}'")
