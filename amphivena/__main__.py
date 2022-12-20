import argparse
import asyncio
import json
import logging.config
import pathlib
import sys

import tomli

from amphivena import controller
from amphivena.gui import main_window

# Configure logger
config_directory = pathlib.Path(__file__).parent.absolute()
with open(config_directory.joinpath("logger.conf")) as logger_conf:
    logging.config.dictConfig(json.load(logger_conf))

if __name__ == "__main__":
    # Parse pyproject for application metadata
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
        dest="playbook",
        help="directory path to playbook; only required if '--no-gui' flag is set",
        default="<no playbook file set>"
    )
    args = parser.parse_args()

    print(args)
    try:
        # TODO this does not feel well designed, but I'm a bit tired to figure out
        #   why + how to resolve, so figure out better way to organize functionality
        if args.no_gui:
            asyncio.run(controller.engage("eth0", "eth1", args.playbook))
        else:
            main_window.initialize("eth0", "eth1", args.playbook)
    except KeyboardInterrupt:
        pass
