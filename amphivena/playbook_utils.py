import json

import jsonschema

schema = {
    "type": "object",
    "properties": {
        "isOrdered": {"type": "boolean"},
        "instructions": {
            "type": "object",
            "patternProperties": {
                "^[0-9]+$": {
                    "properties": {
                        "operation": {"type": "string"},
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
                                    },
                                    "field": {
                                        "type": "string",
                                    },
                                    "value": {
                                        "type": ["string", "integer"],
                                    },
                                },
                                "required": ["type", "field", "value"],
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


def load(config_file_path):
    try:
        with open(config_file_path, "r") as f:
            playbook_obj = json.load(f)

        validate(playbook_obj)

        return playbook_obj
    except json.decoder.JSONDecodeError as e:
        print("Config file json invalid:", e)
    except FileNotFoundError as e:
        print(e)

    return {}


def validate(playbook_obj):
    try:
        jsonschema.validate(playbook_obj, schema)
    except jsonschema.exceptions.ValidationError as e:
        print("Config file schema invalid:", e)
