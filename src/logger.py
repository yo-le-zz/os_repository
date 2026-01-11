import logging
from config import *

color_debug = None

def init_logger(name: str, level: int = logging.INFO, color=None) -> logging.Logger:
    """
    Sets up a logger with the specified name and logging level.

    Args:
        name (str): The name of the logger.
        level (int): The logging level (e.g., logging.DEBUG, logging.INFO).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.hasHandlers():
        ch = logging.StreamHandler()
        ch.setLevel(level)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        logger.addHandler(ch)
    global color_debug
    color_debug = color if color else ('', '', '', '', '', '', '')
    return logger

def log(message: str, level: int = logging.INFO):
    if color_debug is None:
        return
    
    r, g, b, y, w, c, m = color_debug

    if debug:
        logger = logging.getLogger('logger')
        if level == logging.DEBUG:
            logger.debug(f"{b}{message}")
        elif level == logging.INFO:
            logger.info(f"{c}{message}")
        elif level == logging.WARNING:
            logger.warning(f"{y}{message}")
        elif level == logging.ERROR:
            logger.error(f"{r}{message}")
        elif level == logging.CRITICAL:
            logger.critical(f"{m}{message}")