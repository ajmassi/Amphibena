import argparse
import asyncio
import json
import logging.config
import pathlib
import sys

import tomllib

from amphivena import controller
from amphivena.gui import main_window

config_directory = pathlib.Path(__file__).parent.absolute()
with pathlib.Path(config_directory.joinpath("logger.conf")).open() as logger_conf:
    logging.config.dictConfig(json.load(logger_conf))

log = logging.getLogger(__name__)

if __name__ == "__main__":
    # Retrieve application metadata
    with pathlib.Path(config_directory.parent.joinpath("pyproject.toml")).open(
        "rb"
    ) as pyproject:
        data = tomllib.load(pyproject)

    parser = argparse.ArgumentParser(
        prog=data.get("project").get("name"),
        description=data.get("project").get("description"),
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
            no_gui_controller = controller.Controller(
                args.iface1,
                args.iface2,
                args.playbook,
            )
            asyncio.run(no_gui_controller.start())
        else:
            main_window.initialize(args.iface1, args.iface2, args.playbook)
    except KeyboardInterrupt:
        pass
