# -*- coding: utf-8 -*-
"""
Module that handles different card reader types and their drivers.
"""

import abc

from typing import List, Tuple

NFC_AVAILABLE = True
SMARTCARD_AVAILABLE = True

try:
    # Requires xantares/nfc-binding
    import nfc
except ImportError:
    NFC_AVAILABLE = False

try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    import smartcard
except ImportError:
    SMARTCARD_AVAILABLE = False


class ReaderException(Exception):
    """
    Reader hasn't been found or other reader related issues
    """


class CardException(Exception):
    """
    The reader is present but there is an issue in connecting to the card
    """


class ConnectionException(Exception):
    """
    An issue has occurred in the communication with the card.
    """


class Reader(metaclass=abc.ABCMeta):
    """
    Abstract class describing methods to be implemented. Holds the connection.
    """

    def __init__(self):
        self._connection = None

    def __del__(self):
        if self._connection:
            del self._connection

    @abc.abstractmethod
    def connect(self) -> None:
        """
        Connect to the card found in the selected reader.

        :return: None
        """

    @abc.abstractmethod
    def send(self, apdu: List[int]) -> Tuple[List[str], int, int]:
        """
        Send APDU to the reader and card and retrieve the result with status
        codes.

        :param List[int] apdu: Command to be sent
        :return: Return the result of the query and two status codes
        :rtype: Tuple[List[str], int, int]
        """

    def bool(self) -> bool:
        """
        Is there an active connection

        :rtype: Is there an active connection
        :return: bool
        """
        return self._connection is not None

    def disconnect(self) -> None:
        """
        Disconnect from the card.

        :return: None
        """
        if self._connection:
            self._connection = None

    @classmethod
    def __subclasshook__(cls, c):
        if cls is Reader:
            attrs = set(dir(c))

            if set(cls.__abstractmethods__) <= attrs:
                return True

        return NotImplemented


class NfcReader(Reader):
    """
    Specialized reader using xantares/nfc-binding
    """

    def __init__(self):
        super().__init__()

        nfc_context = nfc.init()
        self._connection = nfc.open(nfc_context)

        if not self._connection:
            raise ReaderException("Card reader not found.")

    def connect(self):
        nfc.initiator_init(self._connection)
        link_mode = nfc.modulation()
        link_mode.nmt = nfc.NMT_ISO14443A
        link_mode.nbr = nfc.NBR_106
        target = nfc.target()
        nfc.initiator_select_passive_target(self._connection, link_mode, 0, 0,
                                            target)

    def send(self, apdu: List[int]) -> Tuple[List[str], int, int]:
        message_ba = bytearray(apdu)
        ret = nfc.initiator_transceive_bytes(self._connection, message_ba,
                                             len(message_ba), 256, 0)

        if ret[0] < 0:
            print("ERROR RFID", ret[0])
            return [], 0x99, 0x99

        length = ret[0]
        return list(ret[1][:length - 2]), int(ret[1][length - 2]), \
            int(ret[1][length - 1])


class SmartCard(Reader):
    """
    Generic smart card reader class

    :param int index: Index of the reader to initialize.
    """

    def __init__(self, index: int = 0):
        super().__init__()

        try:
            found_readers = list(filter(lambda x: not str(x).startswith("Yubico"), readers()))
        except smartcard.pcsc.PCSCExceptions.EstablishContextException as error:
            raise ReaderException("Readers not detected on the system") \
                from error

        try:
            found_reader = found_readers[index]
            self._connection = found_reader.createConnection()
        except IndexError as error:
            raise ReaderException(f"Reader with index {index} not found.") \
                from error

    def connect(self) -> None:
        try:
            self._connection.connect(CardConnection.T1_protocol)
        except smartcard.Exceptions.NoCardException as error:
            raise CardException("The reader has no card inserted") from error
        except smartcard.Exceptions.CardConnectionException as error:
            raise CardException("The reader has no card inserted") from error

    def send(self, apdu: List[int]) -> Tuple[List[str], int, int]:
        try:
            return self._connection.transmit(apdu)
        except smartcard.Exceptions.CardConnectionException as error:
            raise ConnectionException("Connection issue") from error

    def disconnect(self) -> None:
        if self._connection:
            try:
                self._connection.disconnect()
            except smartcard.Exceptions.CardConnectionException:
                # Ignore disconnect errors: connection is being torn down anyway.
                self._connection = None
            else:
                self._connection = None


def get(index: int = 0) -> Reader:
    """
    Get the reader that can be found on the given position.

    :param int index: Index of reader to be initialized and used
    :return: Reader object that can be used.
    :rtype: Reader
    """
    if SMARTCARD_AVAILABLE:
        return SmartCard(index)
    if NFC_AVAILABLE:
        return NfcReader()

    raise ReaderException("No readers available")
