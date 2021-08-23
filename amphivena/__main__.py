import json
import logging.config
import pathlib

from amphivena.gui import main_window

# Configure logger
config_directory = pathlib.Path(__file__).parent.absolute()
with open(config_directory.joinpath("logger.conf")) as logger_conf:
    logging.config.dictConfig(json.load(logger_conf))

main_window.initialize()
