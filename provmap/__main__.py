import logging
import logging.config
import time


LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "standard": {
            "format": "[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "verbose": {
            "format": "[%(asctime)s][%(created).0f][%(name)s]"
            "[%(filename)s:%(lineno)d][%(levelname)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
        "file": {
            "class": "logging.FileHandler",
            "formatter": "verbose",
            "level": "DEBUG",
            "filename": f"logs/{int(time.time())}.log",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "DEBUG",
    },
}

logging.config.dictConfig(LOGGING_CONFIG)

from provmap.main import main

if __name__ == "__main__":
    main()
