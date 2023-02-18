import argparse
import asyncio
import json
import logging.config
import pathlib
import sys
import tomllib

from amphivena import controller
from amphivena.gui import main_window

# Configure logger
config_directory = pathlib.Path(__file__).parent.absolute()
with open(config_directory.joinpath("logger.conf")) as logger_conf:
    logging.config.dictConfig(json.load(logger_conf))

log = logging.getLogger(__name__)

if __name__ == "__main__":
    # Parse pyproject for application metadata
    with open(config_directory.parent.joinpath("pyproject.toml"), "rb") as pyproject:
        try:
            data = tomllib.load(pyproject)
        except tomllib.TOMLDecodeError as e:
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
        help="directory path to playbook; required if '--no-gui' flag set",
        default="<no playbook file set>",
    )
    parser.add_argument(
        "-i",
        required="--no-gui" in sys.argv,
        dest="iface1",
        help="primary network interface for MitM, default 'eth0'; required if '--no-gui' flag set",
        default="eth0",
    )
    parser.add_argument(
        "-b",
        required=False,
        dest="iface2",
        help="secondary network interface for network bridge/tap. Typically faces target client.",
    )
    args = parser.parse_args()

    log.debug(args)
    try:
        if args.no_gui:
            c = controller.Controller(args.iface1, args.iface2, args.playbook)
            asyncio.run(c._engage())
        else:
            main_window.initialize(args.iface1, args.iface2, args.playbook)
    except KeyboardInterrupt:
        pass
