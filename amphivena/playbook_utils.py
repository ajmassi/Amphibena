import logging
from enum import Enum
from json.decoder import JSONDecodeError
from pathlib import Path

import pydantic.error_wrappers
from pydantic import BaseModel, constr
from pydantic.typing import Dict, List, Optional

log = logging.getLogger(__name__)


class Condition(BaseModel):
    layer: str
    field: str
    comparator: str #TODO probs should be enum
    value: Optional[str] #TODO should be int/str/hex, see stack overflow post in bookmarks that is about this


class Action(BaseModel):
    class Type(str, Enum):
        modify = "modify"
        insert = "insert"

    layer: str
    type: Type
    field: str
    value: Optional[str] #TODO sake int/str/hex as above


class Instruction(BaseModel):
    class Operation(str, Enum):
        edit = "edit"
        drop = "drop"

    operation: Operation
    conditions: Optional[List[Condition]]
    actions: Optional[List[Action]]


class PlaybookMetadata(BaseModel):
    is_ordered: bool
    loop_when_complete: Optional[bool] = None
    remove_spent_instructions: Optional[bool] = None
    instructions: Dict[constr(regex=r'^\d+$'), Instruction]


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
        playbook_obj = PlaybookMetadata.parse_file(Path(playbook_file_path), content_type="json")

        log.info("Playbook validation successful.")
        return playbook_obj
    except JSONDecodeError as e:
        raise PlaybookValidationError(f"Playbook json invalid: {e}") from e
    except pydantic.error_wrappers.ValidationError as e:
        raise PlaybookValidationError(f"Playbook schema invalid: {e.errors()}") from e
    except FileNotFoundError as e:
        raise PlaybookValidationError(f"Playbook not found: '{e.filename}'") from e
