#!/usr/bin/env python3
"""
Module for password encryption and validation.
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
     Hash a password using bcrypt with automatic salt generation.
     Args:
        password (str): The plain text password to be hashed.
    Returns:
        bytes: A salted, hashed password as a byte string.
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
     Validate if a password matches the hashed password using bcrypt.
     Args:
        hashed_password (bytes): The hashed password.
        password (str): The plain text password to be validated.
    Returns:
        bool: True if the password matches the hashed password, False otherwise
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
