import json
import logging
from enum import Enum
from json.decoder import JSONDecodeError
from typing import Dict, List, Optional

import pydantic.error_wrappers
from pydantic import BaseModel

log = logging.getLogger(__name__)


class Condition(BaseModel):
    layer: str
    field: str
    comparator: str  # TODO Enum
    value: Optional[str | int] = None


class Action(BaseModel):
    class Type(str, Enum):
        modify = "modify"
        insert = "insert"

    layer: str
    type: Type
    field: str
    value: Optional[str | int] = None


class Instruction(BaseModel):
    class Operation(str, Enum):
        edit = "edit"
        drop = "drop"

    operation: Operation
    conditions: Optional[List[Condition]] = None
    actions: Optional[List[Action]] = None


class PlaybookMetadata(BaseModel):
    is_ordered: bool
    loop_when_complete: Optional[bool] = False
    remove_spent_instructions: Optional[bool] = True
    instructions: Optional[Dict[int, Instruction]] = None


class PlaybookValidationError(Exception):
    """Base class for exceptions raised during validation of a playbook."""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def load(playbook_file_path):
    """
    Load playbook file and validate against schema.

    :param playbook_file_path: string representation of playbook file path.
    :return: dict
    :raise PlaybookValidationError: Wraps JSONDecodeError, ValidationError, and FileNotFoundError.
    """
    try:
        with open(playbook_file_path, "r") as f:
            playbook_obj = json.load(f)

        playbook_obj = PlaybookMetadata.model_validate(playbook_obj)

        log.info("Playbook validation successful.")
        return playbook_obj
    except JSONDecodeError as e:
        raise PlaybookValidationError(f"Playbook json invalid: {e}") from e
    except pydantic.error_wrappers.ValidationError as e:
        message = "Playbook schema invalid:"
        for err in e.errors():
            message += f"\n{err.get('loc')}: {err.get('msg')}"
        raise PlaybookValidationError(message) from e
    except FileNotFoundError as e:
        raise PlaybookValidationError(f"Playbook not found: '{e.filename}'") from e
