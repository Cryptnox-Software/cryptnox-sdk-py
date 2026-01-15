# -*- coding: utf-8 -*-
"""
Utility module for handling binary data
"""

import re
from typing import List


def list_to_hexadecimal(data: List[int], sep: str = "") -> str:
    """
    Convert list of integers into hexadecimal representation

    :param List[int] data: List of integer to return in hexadecimal string form
    :param str sep: (optional) Separator to use to join the hexadecimal numbers

    :return: list
    :rtype: str
    """
    return sep.join([f"{x:02x}" for x in data])


def hexadecimal_to_list(value: str) -> List[int]:
    """
    Convert given string containing hexadecimal representation of numbers into
    list of integers

    :param string value: String containing hexadecimal numbers
    :return: List of hexadecimal values in integer form
    :rtype: List[int]
    """
    groups = re.findall("..", value)

    return [int(x, 16) for x in groups]


def path_to_bytes(path_str: str) -> bytes:
    """
    Convert given path for format that the card uses

    :param str path_str: path to convert
    :return: path formatted for use with the card.
    :rtype: bytes
    """
    def read_path_unit(path):
        if path[-1] == "'":
            out = int(path[:-1]) + 2147483648
        else:
            out = int(path)
        return out.to_bytes(4, byteorder='big')

    assert path_str[:2] == "m/"

    return b''.join(map(read_path_unit, path_str.split("/")[1:]))


def binary_to_list(data: bytes) -> List[int]:
    """
    Convert given binary data to it's representation as a list of hexadecimal
    values.

    :param bytes data: Binary data to convert to
    :return: List containing data in hexadecimal numbers in integer format
    :rtype: List[int]
    """
    return hexadecimal_to_list(data.hex())


def pad_data(data: bytes) -> bytes:
    """
    Pad data with 0s to be length of 128.

    :param data: Data to be padded.
    :return: Data padded with 0s with length 128.
    :rtype: bytes
    """
    data_array = bytearray(data)
    data_array.append(128)
    while len(data_array) % 16 > 0:
        data_array.append(0)
    return bytes(data_array)


def remove_padding(data: bytes) -> bytes:
    """
    Remove padding from the data

    :param bytes data: Data from which to remove padding
    :return: Data without the padding
    :rtype: bytes
    """
    i = len(data) - 1
    while data[i] == 0:
        i -= 1

    if data[i] != 0x80:
        raise ValueError("Bad padding in received data")

    return data[:i]
