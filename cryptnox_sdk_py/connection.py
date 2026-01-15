# -*- coding: utf-8 -*-
"""
Module for keeping the connection to the reader.

Sending and receiving information from the card through the reader.
"""

import hashlib
import pickle
import secrets
from contextlib import ContextDecorator
from time import time, sleep
from typing import (
    List,
    Tuple,
    Union
)
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import exceptions
from . import reader
from .binary_utils import (
    binary_to_list,
    list_to_hexadecimal,
    pad_data,
    remove_padding
)
from .crypto_utils import aes_decrypt, aes_encrypt


class Connection(ContextDecorator):
    """
    Connection to the reader.

    Sends and receives messages from the card using the reader.

    :param int index: Index of the reader to initialize the connection with
    :param bool debug: Show debug information during requests
    :param List conn: List of sockets to use for remote connections
    :param bool remote: Use remote sockets for communications with the cards

    :var Card self.card: Information about the card.
    """

    def __init__(self, index: int = 0, debug: bool = False, conn: List = None, remote: bool = False):
        self.conn = conn[index] if conn and (len(conn) > index) else None
        self.debug: bool = debug
        self.index: int = index
        self.remote: bool = remote

        self.session_public_key: str = ""
        self.algorithm = ec.SECP256R1
        self.pairing_secret: str = ""

        self._reader = None
        self._aes_key: bytes = b""
        self._iv: bytes = b""
        self._mac_iv: bytes = b""
        self._mac_key: bytes = b""
        self._init_reader(index, remote)

    def _init_reader(self, index: int, remote: bool) -> None:
        retry = 0
        if remote:
            if not self.conn:
                raise exceptions.ReaderException("Can't find any reader connected.")
            return

        try:
            self._reader = reader.get(index)
        except reader.ReaderException as error:
            raise exceptions.ReaderException("Can't find any reader connected.") from error

        max_retries = 3
        for retry in range(max_retries):
            try:
                self._reader.connect()
                break
            except reader.CardException as error:
                if retry == max_retries - 1:
                    raise exceptions.CardException("The reader has no card inserted") from error
                sleep(0.2)

    def __del__(self):
        if self._reader:
            del self._reader

    def disconnect(self) -> None:
        """
        Disconnect from the card reader and clean up the connection.

        This method properly closes the connection to the card reader without
        deleting the Connection object itself.
        """
        if self._reader:
            try:
                self._reader.disconnect()
            except (AttributeError, reader.ConnectionException):
                # Ignore disconnect errors: disconnect is best-effort and should not raise.
                logging.debug("Failed to disconnect from reader", exc_info=True)

    def send_apdu(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        """
        Send data to the card in plain format

        :param int apdu: list of the APDU header
        :return bytes: Result of the query that was sent to the card
        :rtype: bytes

        :raises ConnectionException: Issue in the connection
        """
        t_env = 0
        if self.debug:
            print(f"--> sending : {len(apdu) - 5} bytes data ")
            print(list_to_hexadecimal(apdu))
            t_env = time()

        if self.remote:
            data, status1, status2 = self.remote_read(apdu)
        else:
            try:
                data, status1, status2 = self._reader.send(apdu)
            except reader.ConnectionException as error:
                raise exceptions.ConnectionException("Connection issue") from error

        if self.debug:
            t_ans = int((time() - t_env) * 10000) / 10.0
            print(f"<-- received : {status1:02x}{status2:02x} : {len(data)} bytes data  --  time : {t_ans:.1f} ms")
            print(list_to_hexadecimal(data))

        self._check_response_code(status1, status2)

        return data, status1, status2

    def send_encrypted(self, apdu: List[int], data: bytes, receive_long: bool = False) -> bytes:
        """
        Send data to the card in encrypted format

        :param int apdu: list of the APDU header
        :param data: bytes of the data payload (in clear, will be encrypted)
        :param bool receive_long:
        :return bytes: Result of the query that was sent to the card
        :rtype: bytes

        :raises CryptnoxException: General exceptions
        """

        self._open_secure_channel()

        if self.debug:
            data_length = len(data)
            print(f"--> sending (SCP) : {len(data)} bytes data ")
            if receive_long or data_length >= 256:
                send_data = [0, data_length >> 8, data_length & 255]
            else:
                send_data = [data_length]
            print(list_to_hexadecimal(apdu + send_data + binary_to_list(data)))

        rep_list, mac_value = self._encrypt(apdu, data, receive_long)

        rep = bytes(rep_list)

        data_decoded = self._decode(rep, mac_value)

        status = data_decoded[-2:]
        received = data_decoded[:-2]
        self._iv = rep[:16]
        if self.debug:
            print(f"<-- received (SCP) : {status.hex()} : {len(received)} bytes data ")
            print(received.hex())

        self._check_response_code(status[0], status[1])
        if status[0] != 0x90 or status[1] != 0x00:
            raise exceptions.GenericException(status)

        return received

    @staticmethod
    def _check_response_code(code1: int, code2: int) -> None:
        if code1 == 0x69 and code2 == 0x82:
            raise exceptions.ConnectionException("Error in secure channel communication. "
                                                 "Check pairing_key.")

        if (code1 == 0x6A and code2 == 0x80) or (code1 == 0x67 and code2 == 0x00):
            raise exceptions.DataValidationException("Data is not valid. Also check the numbers "
                                                     "you entered.")

        if code1 == 0x6A and code2 == 0x82:
            raise exceptions.FirmwareException("Error firmware not found. Check if Cryptnox is "
                                               "connected")

        if code1 == 0x63 and code2 & 0xF0 == 0xC0:
            raise exceptions.PinException(number_of_retries=code2 - 0xC0)

        if code1 == 0x98 and code2 & 0xF0 == 0x40:
            raise exceptions.PukException(number_of_retries=code2 - 0x40)

        if code1 == 0x69 and code2 == 0x85:
            raise exceptions.PinAuthenticationException("PIN code wasn't authorized")

    def _decode(self, rep: bytes, mac_value: bytes) -> bytes:
        rep_data = rep[16:]
        rep_mac = rep[:16]
        data_rec_length = len(rep)
        # Check MAC
        if data_rec_length >= 256:
            data_mac_list = [0, data_rec_length >> 8, data_rec_length & 255] + \
                            [0] * 13
        else:
            data_mac_list = [data_rec_length & 0xFF] + [0] * 15
        mac_datar = bytes(data_mac_list) + rep_data
        mac_valr = aes_encrypt(self._mac_key, self._mac_iv, mac_datar)[-16:]
        if mac_valr != rep_mac:
            raise exceptions.CryptnoxException("Error (SCP) : Bad MAC received")

        try:
            data_decoded = remove_padding(aes_decrypt(self._aes_key,
                                                      mac_value, rep_data))
        except Exception as error:
            raise exceptions.CryptnoxException("Error (SCP) : Error during decryption (bad padding,"
                                               " wrong key)") from error

        return data_decoded

    def _encrypt(self, apdu: List[int], data: bytes,
                 receive_long: bool) -> Tuple[List[int], Union[int, bytes]]:
        padded = pad_data(data)
        data_enc = aes_encrypt(self._aes_key, self._iv, padded)
        data_length = len(padded) + 16

        if receive_long or data_length >= 256:
            cmdh = apdu + [0, data_length >> 8, data_length & 0xFF]
            data_mac_list = cmdh + [0] * 9
        else:
            cmdh = apdu + [data_length]
            data_mac_list = cmdh + [0] * 11
        mac_data = bytes(data_mac_list) + data_enc
        mac_value = aes_encrypt(self._mac_key, self._mac_iv, mac_data)[-16:]

        data_apdu = mac_value + data_enc
        rep_list = self.send_apdu(cmdh + binary_to_list(data_apdu))[0]

        return rep_list, mac_value

    def _open_secure_channel(self, pairing_secret: bytes = b"", pairing_key_index: int = 0) -> None:
        pairing_secret = pairing_secret or self.pairing_secret
        if self._aes_key:
            return

        session_private_key = ec.generate_private_key(self.algorithm())

        session_public_key = session_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)
        data = bytes.fromhex(f"{len(session_public_key):x}" +
                             session_public_key.hex())
        apdu_osc = [0x80, 0x10, pairing_key_index, 0x00] + binary_to_list(data)
        rep = self.send_apdu(apdu_osc)[0]

        if len(rep) != 32:
            raise exceptions.CryptnoxException("Bad data during secure channel opening")

        # compute session keys
        sess_salt = bytes(rep[:32])
        self._iv = bytes([1] * 16)

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self.algorithm(), bytes.fromhex(self.session_public_key))
        dh_secret = session_private_key.exchange(ec.ECDH(), public_key)

        secret = dh_secret + pairing_secret + sess_salt
        session_secrets = hashlib.sha512(secret).digest()
        self._aes_key = session_secrets[:32]
        self._mac_key = session_secrets[32:]
        self._mac_iv = bytes([0] * 16)

        data = secrets.token_bytes(nbytes=32)
        cmd = [0x80, 0x11, 0, 0]
        resp = self.send_encrypted(cmd, data)

        if len(resp) != 32:
            raise exceptions.CryptnoxException("Bad data during secure channel testing")

    def remote_read(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        if not self.conn:
            raise ConnectionError('Calling remote read without connection')

        message = pickle.dumps(apdu)
        msg_length = len(message)
        send_length = str(msg_length).encode('utf-8')
        send_length += (" " * (64 - len(send_length))).encode('utf-8')
        self.conn.send(send_length + message)

        while True:
            message = self.conn.recv(64)
            if not message:
                continue

            try:
                message_length = int(message.decode('utf-8'))
            except ValueError as error:
                raise ConnectionError('Error in remote connection') from error

            received_message = self.conn.recv(message_length)
            if not received_message:
                continue

            try:
                response = pickle.loads(received_message)
            except pickle.UnpicklingError as error:
                raise ConnectionError('Error in remote connection') from error

            data, status1, status2 = response
            break

        return data, status1, status2
