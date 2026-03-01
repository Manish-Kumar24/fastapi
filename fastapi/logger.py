import logging

def get_logger(name: str):
    return logging.getLogger(name)

logger = get_logger("fastapi")
