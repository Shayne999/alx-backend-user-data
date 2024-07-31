#!/usr/bin/env python3
"""
Filter Logger
"""


import re
import logging
import os
import mysql.connector
from mysql.connector import connection


# Define a tuple containing sensitive fields
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields, redaction, message, separator):
    """returns the log message obfuscated"""
    pattern = r'({})=([^{}]*)'.format(
        '|'.join(map(re.escape, fields)), re.escape(separator))
    return re.sub(pattern, r'\1=' + redaction, message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: list):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filter values in incoming log records"""
        original_msg = super(RedactingFormatter, self).format(record)
        redacting_msg = filter_datum(
            self.fields, self.REDACTION, original_msg, self.SEPARATOR)
        return redacting_msg


def get_logger() -> logging.Logger:
    """returns a logger object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_db() -> connection.MySQLConnection:
    """connects to the Holberton database"""
    username = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME', '')
    return mysql.connector.connect(user=username, password=password,
                                   host=host, database=db_name)


def main():
    """main function"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name, email, phone, ssn, password, ip, last_login, user_agent FROM users;")
    logger = get_logger()

    for row in cursor:
        message = (
            f"name={row[0]}; email={row[1]}; phone={row[2]}; ssn={row[3]}; "
            f"password={row[4]}; ip={row[5]}; last_login={row[6]}; user_agent={row[7]};"
        )
        logger.info(message)
    cursor.close()
    db.close()
