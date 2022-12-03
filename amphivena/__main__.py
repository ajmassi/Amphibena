import argparse
import json
import logging.config
import pathlib
import sys

import tomli

from amphivena.gui import main_window

# Configure logger
config_directory = pathlib.Path(__file__).parent.absolute()
with open(config_directory.joinpath("logger.conf")) as logger_conf:
    logging.config.dictConfig(json.load(logger_conf))

with open(config_directory.parent.joinpath("pyproject.toml"), "rb") as pyproject:
    try:
        data = tomli.load(pyproject)
    except tomli.TOMLDecodeError as e:
        raise e

parser = argparse.ArgumentParser(
    prog=data.get("tool")["poetry"]["name"],
    description=data.get("tool")["poetry"]["description"],
)
parser.add_argument(
    "--no-gui",
    required=False,
    action="store_true",
    dest="no_gui",
    help="start execution without the gui",
)
parser.add_argument(
    "--playbook",
    required="--no-gui" in sys.argv,
    help="directory path to playbook; only required if '--no-gui' flag is set",
)
args = parser.parse_args()

if args.no_gui:
    # TODO start mitm and processing with passed playbook
    pass
else:
    # TODO add initial playbook passthrough on init
    main_window.initialize()
