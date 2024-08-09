import logging
import sys
from logging.handlers import TimedRotatingFileHandler

def setup_logger(logconf):
    # create logger with 'app_log'
    logger = logging.getLogger(logconf['name'])
    logger.setLevel(logging.DEBUG)

    # create stdout handler with a higher log level
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG)
    log_path = logconf["folder"] + '/'

    # create stdout_file handler which logs even debug messages
    sfh = TimedRotatingFileHandler(
        log_path + logconf['stdout']['name'],
        when="W0",
        interval=1,
        backupCount=5)
    sfh.setLevel(logging.DEBUG)

    # create file handler with a higher log level
    efh = TimedRotatingFileHandler(
        log_path + logconf['error']['name'],
        when="W0",
        interval=1,
        backupCount=5)
    efh.setLevel(logging.ERROR)

    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    sh.setFormatter(formatter)
    sfh.setFormatter(formatter)
    efh.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(sh)
    logger.addHandler(sfh)
    logger.addHandler(efh)

    return logger