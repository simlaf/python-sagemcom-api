"""Enums for the Sagemcom F@st client."""

from enum import Enum


class EncryptionMethod(Enum):
    """Encryption method defining the password hash."""

    MD5 = "MD5"
    SHA512 = "SHA512"

class Weekday(Enum):
    """Week_Days in Sagemcom API"""

    Monday = 1
    Tuesday = 2
    Wednesday = 4
    Thursday = 8
    Friday = 16
    Saturday = 32
    Sunday = 64

class ActionMethod(Enum):
    """Action Method for API calls"""

    GETVALUE = "getValue"
    SETVALUE = "setValue"
    ADDCHILD = "addChild"
    DELETECHILD = "deleteChild"
