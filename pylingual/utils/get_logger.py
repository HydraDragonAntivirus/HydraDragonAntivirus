import datetime
import logging
import os


def get_logger(name: str) -> logging.Logger:
    # Create a logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # Create a file handler
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if not os.path.exists("logs"):  # create a logging directory if not exists
        os.makedirs("logs")
    file_handler = logging.FileHandler(f"logs/{name}_{current_datetime}.log", mode="w")
    file_handler.setLevel(logging.DEBUG)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create a formatter and add it to the handlers
    formatter = logging.Formatter("%(asctime)s- %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
