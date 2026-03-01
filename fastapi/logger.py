import logging
import json
import re

def get_logger(name: str, level: int = 20):
    return logging.getLogger(name)

logger = get_logger("fastapi")
