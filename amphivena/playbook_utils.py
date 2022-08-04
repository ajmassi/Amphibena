import json
import jsonschema

schema = {
    "type": "object",
    "properties": {
        "isOrdered": {
            "type": "boolean"
        },
        "instructions": {
            "type": "object",
            "patternProperties": {
                "^.*$": {
                    "operation": "string"
                }
            }
        }
    },
    "required": ["isOrdered"]
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
