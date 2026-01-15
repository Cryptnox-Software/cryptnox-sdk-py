# -*- coding: utf-8 -*-
"""
Module for keeping information about the card attached to the reader
"""
import abc
import collections
import secrets
from typing import (
    Any,
    Dict,
    NamedTuple,
    Tuple
)
from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import authenticity
from .custom_bits import CustomBitsBase
from .user_data import UserDataBase
from .. import exceptions
from ..binary_utils import binary_to_list, pad_data
from ..connection import Connection
from ..crypto_utils import aes_encrypt
from ..enums import (
    AuthType,
    Derivation,
    KeyType,
    Origin,
    SeedSource,
    SlotIndex
)
from ..exceptions import InitializationException

User = collections.namedtuple("User", ["name", "email"])
SignatureCheckResult = collections.namedtuple("SignatureCheckResult", ["message", "signature"])

BASIC_PAIRING_SECRET = b'Cryptnox Basic CommonPairingData'


class Base(metaclass=abc.ABCMeta):
    """
    Object that contains information about the card that is in the reader.

    :param Connection connection: Connection to use for card initialization
    :param bool debug: Show debug information to the user.

    :var List[int] applet_version: Version of the applet on the card.
    :var int serial_number: Serial number of card.
    :var str session_public_key: Public key of the session.
    :var bool initialized: The card has been initialized with secrets.

    :raises CardTypeException: The card in the reader is not a Cryptnox card
    """

    _ALGORITHM = ec.SECP256R1
    PUK_LENGTH = 15

    pin_rule = "4-9 digits"
    type = ord("B")
    _type = "Basic"

    user_data = UserDataBase()
    custom_bits = CustomBitsBase()

    def __init__(self, connection: Connection, serial: int, applet_version: List[int],
                 data: List[int] = None, debug: bool = False):
        self.connection = connection
        self.connection.pairing_secret = BASIC_PAIRING_SECRET
        self.connection.algorithm = self._ALGORITHM

        self.debug = debug

        self.applet_version: List[int] = applet_version
        self.serial_number: int = serial
        self.auth_type: AuthType = AuthType.NO_AUTH

        self._data = data
        self._user: User = None
        self._origin: Origin = Origin.UNKNOWN

    @staticmethod
    @property
    @abc.abstractmethod
    def select_apdu() -> List[int]:
        """
        :return: Value to add to select command to select the applet on the card
        :rtype: List[int]
        """

    @staticmethod
    @property
    @abc.abstractmethod
    def puk_rule() -> str:
        """
        Human readable PUK code rule

        :return: Human readable PUK code rule
        :rtype: str
        """

    @property
    def alive(self) -> bool:
        """
        :return: The connection to the card is established and the card hasn't been changed
        :rtype: bool
        """
        try:
            certificate = authenticity.manufacturer_certificate(self.connection, self.debug)
        except (exceptions.CardException, exceptions.ConnectionException,
                exceptions.ReaderException):
            return False

        certificate_parts = certificate.split("0302010202")
        if len(certificate_parts) <= 1:
            return False

        if certificate_parts[1][1] == "8":
            data = certificate_parts[1][2:18]
        elif certificate_parts[1][1] == "9":
            data = certificate_parts[1][4:20]
        else:
            return False

        return int(data, 16) == self.serial_number

    @abc.abstractmethod
    def change_pairing_key(self, index: int, pairing_key: bytes, puk: str = "") -> None:
        """
        Set the pairing key of the card

        :param int index: Index of the pairing key
        :param bytes pairing_key: Pairing key to set for the card
        :param str puk: PUK code of the card

        :raises DataValidationException: input data is not valid
        :raises SecureChannelException: operation not allowed
        :raises PukException: PUK code is not valid
        """

    def change_pin(self, new_pin: str) -> None:
        """
        Change the current pin code of the card to a new pin code.

        The method will set the given pin code as the pin code of the card.
        For it to work the card first must be opened with the current pin code.

        :requires:
            - PIN code or challenge-response validated

        :param str new_pin: The desired PIN code to be set for the card
                            (4-9 digits).
        """
        new_pin = self.valid_pin(new_pin, pin_name="new pin")
        self._change_secret(0, new_pin)
        if not self.open:
            self.auth_type = AuthType.PIN

    def change_puk(self, current_puk: str, new_puk: str) -> None:
        """
        Change the current pin code of the card to a new pin code.

        The method will set the given pin code as the pin code of the card.
        For it to work the card first must be opened with the current pin code.

        :param str current_puk: The current PUK code of the card
        :param str new_puk: The desired PUK code to be set for the card
        """
        current_puk = self.valid_puk(current_puk, "current puk")
        new_puk = self.valid_puk(new_puk, "new puk")
        self._change_secret(1, new_puk + current_puk)
        if not self.open:
            self.auth_type = AuthType.PIN

    def check_init(self) -> None:
        """
        Check if the initialization has been done on the card.

        It can be useful to check if the card is initialized before doing
        anything else, like asking for pin code from the user.

        :raises InitializationException: The card is not initialized
        """

        if not self.initialized:
            raise InitializationException("Card is not initialized")

    @abc.abstractmethod
    def derive(self, key_type: KeyType = KeyType.K1, path: str = ""):
        """
        Derive key on path and make it the current key in the card

        :requires:
            - PIN code or challenge-response validated
            - Seed must exist

        :param KeyType key_type: Key type to do derive on
        :param str path: Path on which to do derivation
        """

    @abc.abstractmethod
    def dual_seed_public_key(self, pin: str = "") -> bytes:
        """
        Get the public key from the card for dual initialization of the cards

        :requires:
            - PIN code or challenge-response validated

        :param str pin: PIN code of card if it was opened with a PIN check

        :return: Public key and signature that can be sent into the other card
        :rtype: bytes

        :raises DataException: The received data is invalid
        """

    @abc.abstractmethod
    def dual_seed_load(self, data: bytes, pin: str = "") -> None:
        """
        Load public key and signature from the other card into the card to generate same seed.

        :requires:
            - PIN code or challenge-response validated

        :param str pin: PIN code of card if it was opened with a PIN check
        :param bytes data: Public key and signature of public key from the other card
        """

    @property
    @abc.abstractmethod
    def extended_public_key(self) -> bool:
        """
        :return: Extended public key turned on
        :rtype: bool
        """

    @abc.abstractmethod
    def generate_random_number(self, size: int) -> bytes:
        """
        Generate random number on the car and return it.

        :param int size: Output data size in bytes (between 16 and 64, mod 4)

        :return: Random number generated by the chip
        :rtype: bytes

        :raises DataValidationException: size in not a number between 16 and 64 or is not
                                         divisible by 4
        """

    @abc.abstractmethod
    def generate_seed(self, pin: str = "") -> bytes:
        """
        Generate a seed directly on the card.

        :requires:
            - PIN code or challenge-response validated

        :param pin: PIN code of the card. Can be empty if card is opened with
                    challenge-response validation
        :type pin: str, optional

        :return: Primary node "m" UID (hash of public key)
        :rtype: bytes

        :raises KeyGenerationException: There was an issue with generating the key
        :raises KeyAlreadyGenerated: The card already has a seed generated
        """

    @abc.abstractmethod
    def get_public_key(self, derivation: Derivation, key_type: KeyType = KeyType.K1, path: str = "",
                       compressed: bool = True) -> str:
        """
        Get the public key from the card.

        :requires:
            - PIN code or challenge-response validated, except for PIN-less path
            - Seed must exist

        :param Derivation derivation: Derivation to use.
        :param KeyType key_type: Key type to use
        :param str path:
        :param bool compressed: The returned value is in compressed format.

        :return: The public key for the given path in hexadecimal string format
        :rtype: str

        :raises DerivationSelectionException: Card is not initialized with seed
        :raises ReadPublicKeyException: Invalid data received from card
        """

    @abc.abstractmethod
    def get_public_key_extended(self, key_type: KeyType = KeyType.K1, puk: str = "") -> str:
        """
        Get the extended public key (xpub) from the card.

        :requires:
            - PIN code or challenge-response validated
            - Seed must exist
            - XPUB capability must be enabled (or PUK provided to enable it)

        :param KeyType key_type: Key type to use (default: KeyType.K1)
        :param str puk: Optional PUK code to enable XPUB capability
        :return: Extended public key in hexadecimal string format
        :rtype: str

        :raises exceptions.SeedException: If no seed exists on the card
        :raises exceptions.ReadPublicKeyException: If invalid data received from card
        """

    def get_public_key_clear(self, derivation: int, path: str = "", compressed: bool = True) -> bytes:
        """
        Get the public key within clear channel

        :param derivation: Derivation + KeyType (e.g., Derivation.CURRENT_KEY + KeyType.K1)
        :param path: Optional BIP path string like "m/44'/0'/0'"
        :param compressed: Whether to return compressed format
        :return: Public key in bytes format
        :raises exceptions.ReadPublicKeyException: If bad data received
        """

    @abc.abstractmethod
    def set_pubexport(self, status: bool, p1: int, puk: str) -> None:
        """
        Set pubexport capability (xpub or clear pubkey)

        :param status: True to enable, False to disable
        :param p1: 0 for xpub, 1 for clear pubkey
        :param puk: PUK code
        :raises exceptions.DataValidationException: If p1 is invalid
        :raises exceptions.PukException: If PUK is incorrect
        """

    @abc.abstractmethod
    def set_xpubread(self, status: bool, puk: str) -> None:
        """
        Set extended public key read capability

        :param status: True to enable, False to disable
        :param puk: PUK code
        """

    @abc.abstractmethod
    def set_clearpubkey(self, status: bool, puk: str) -> None:
        """
        Set clear public key read capability

        :param status: True to enable, False to disable
        :param puk: PUK code
        """

    @abc.abstractmethod
    def decrypt(self, p1: int, pubkey: bytes, encrypted_data: bytes = b"", pin: str = "") -> bytes:
        """
        Decrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme).

        Generates a symmetric secret for simplified ECIES using an EC key in the BIP32 tree.
        This command is inspired by DECipher in OpenPGP smartcards. This allows asymmetric
        encryption using a key in the card seed tree. Anyone can encrypt with a public key
        from the card, and only the (private) key in the card can decrypt.

        During the seed loading, the card saves in a dedicated key slot the result of a
        fixed derivation path. The child EC key used for this command is fixed (relative
        to a given seed). The path is computed with SLIP17 for the URI "openpgp://cryptnox"
        with index=0, and equals: m/17'/910196630'/2006168372'/332516148'/580566270'

        The symmetric key is computed as SHA2(ECDH): SHA2-256(k.PubKey), where k is the
        private ECP256r1 key, the "decrypt" key slot.

        :param int p1: 0x00 = Output symmetric key, 0x01 = Decrypt data in card
        :param bytes pubkey: Third party public key in X9.62 uncompressed format (0x04|X|Y, 65 bytes)
        :param bytes encrypted_data: Encrypted data (required when p1=1, must be 16-byte aligned)
        :param str pin: PIN code (required if no user key auth, right-padded with 0x00)
        :return: Symmetric key (p1=0) or decrypted data (p1=1)
        :rtype: bytes

        :raises exceptions.SeedException: If no seed/key loaded
        :raises exceptions.PinException: If PIN is incorrect
        :raises exceptions.DataValidationException: If data length is incorrect
        :raises exceptions.GenericException: If other errors occur
        """

    def history(self, index: int = 0) -> NamedTuple:
        """
        Get history of hashes the card has signed regardless of any
        parameters given to sign

        :requires:
            - PIN code or challenge-response validated

        :param int index: Index of entry in history

        :return: Return entry containing signing_counter, representing index of sign call, and
                 hashed_data, the data that was signed
        :rtype: NamedTuple
        """

    @property
    def info(self) -> Dict[str, Any]:
        """
        Get relevant information about the card.

        :return: Dictionary containing information for the card
        :rtype: Dict[str, Any]
        """
        self._user = self._user or self._owner

        return {
            "type": self._type,
            "serial_number": self.serial_number,
            "applet_version": ".".join(map(str, self.applet_version)),
            "name": self._user.name,
            "email": self._user.email,
            "initialized": self.initialized,
            "seed": self.valid_key
        }

    def init(self, name: str, email: str, pin: str, puk: str,
             pairing_secret: bytes = BASIC_PAIRING_SECRET, nfc_sign: bool = False) -> bytes:
        """
        Initialize the Cryptnox card.

        Initialize the Cryptnox card with the owners name and email address.
        Set the PIN and PUK codes for authenticating with the card to be able
        to use it.

        :param str name: Name of the card owner
        :param str email: Email of the card owner
        :param str pin: PIN code that will be used to open the card
        :param str puk: PUK code that will be used to open the card
        :param bytes pairing_secret: Pairing secret to use with the card
        :param bool nfc_sign: Signature command can be used over NFC, only available on certain type

        :return: Pairing secret
        :rtype: bytes

        :raises InitializationException: There was an issue with initialization
        """
        puk = self.valid_puk(puk)
        pin = self.valid_pin(pin)
        if len(name) > 20:
            raise exceptions.DataValidationException("Name must be less than 20 characters")
        if len(email) > 60:
            raise exceptions.DataValidationException("Name must be less than 60 characters")
        pairing_secret = pairing_secret or BASIC_PAIRING_SECRET

        session_private_key = ec.generate_private_key(self._ALGORITHM())

        session_public_key = session_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)

        send_public_key = bytes.fromhex(f"{len(session_public_key):x}" +
                                        session_public_key.hex())

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self._ALGORITHM(), bytes.fromhex(self.connection.session_public_key))
        aes_init_key = session_private_key.exchange(ec.ECDH(), public_key)

        iv_init_key = secrets.token_bytes(nbytes=16)

        data = self._init_data(name, email, pin, puk, pairing_secret, nfc_sign)

        payload = pad_data(data)
        encrypted_payload = aes_encrypt(aes_init_key, iv_init_key, payload)
        data_init = send_public_key + iv_init_key + encrypted_payload
        apdu_init = [0x80, 0xFE, 0x00, 0x00, 82 + len(encrypted_payload)]
        apdu_init += binary_to_list(data_init)
        _, code1, code2 = self.connection.send_apdu(apdu_init)

        if code1 != 0x90 or code2 != 0x00:
            raise exceptions.InitializationException("Card is not initialized")

        return bytes([0]) + pairing_secret

    @property
    @abc.abstractmethod
    def initialized(self) -> bool:
        """
        :return: Whether the card is initialized
        :rtype: bool
        """

    @abc.abstractmethod
    def load_seed(self, seed: bytes, pin: str = "") -> None:
        """
        Load the given seed into the Cryptnox card.

        :requires:
            - PIN code or challenge-response validated

        :param bytes seed: Seed to initialize the card with
        :param pin: PIN code of the card. Can be empty if card is opened with
                    challenge-response validation
        :type pin: str, optional

        :raises KeyGenerationException: Data is not correct
        """

    @property
    def open(self) -> bool:
        """
        Check if the user has authenticated.

        :return: Whether the user has authenticated using the PIN code or
                 challenge-response validation
        :rtype: bool
        """
        return self.auth_type != AuthType.NO_AUTH

    @property
    def origin(self) -> Origin:
        """
        Check the card origin.

        :return: Return if the card is original Cryptnox card, fake or there's an
                 issue getting the information
        :rtype: Origin
        """
        if self._origin == Origin.UNKNOWN:
            self._origin = authenticity.origin(self.connection, self.debug)

        return self._origin

    @property
    @abc.abstractmethod
    def pin_authentication(self) -> bool:
        """
        :return: Whether the PIN code can be used for authentication
        :rtype: bool
        """

    @property
    @abc.abstractmethod
    def pinless_enabled(self) -> bool:
        """
        :return: Return whether the card has a pinless path
        :rtype: bool
        """

    @abc.abstractmethod
    def reset(self, puk: str) -> None:
        """
        Reset the card and return it to factory settings.

        :param puk: PUK code associated with the card
        """

    @property
    @abc.abstractmethod
    def seed_source(self) -> SeedSource:
        """
        :return: How the seed was generated
        :rtype: SeedSource
        """

    @abc.abstractmethod
    def set_pin_authentication(self, status: bool, puk: str) -> None:
        """
        Turn on/off authentication with the PIN code. Other methods can still be used.

        :param bool status: Status of PIN authentication
        :param str puk: PUK code associated with the card

        :raises DataValidationException: input data is not valid
        :raises PukException: PUK code is not valid
        """

    @abc.abstractmethod
    def set_pinless_path(self, path: str, puk: str) -> None:
        """
        Enable working with the card without a PIN on path.

        :param str path: Path to be available without a PIN code
        :param str puk: PUK code of the card

        :raises DataValidationException: input data is not valid
        :raises PukException: PUK code is not valid
        """

    @abc.abstractmethod
    def set_extended_public_key(self, status: bool, puk: str) -> None:
        """
        Turn on/off extended public key output.

        :requires:
            - Seed must be loaded

        :param bool status: Status of PIN authentication
        :param str puk: PUK code associated with the card

        :raises DataValidationException: input data is not valid
        :raises PukException: PUK code is not valid
        :raises KeyException: Seed not found
        """

    @abc.abstractmethod
    def sign(self, data: bytes, derivation: Derivation, key_type: KeyType = KeyType.K1,
             path: str = "", pin: str = "", filter_eos: bool = False) -> bytes:
        """
        Sign the message using given derivation.

        :requires:
            - PIN code provided, authenticate with user key by signing same message
              or PIN-less path used
            - Seed must be loaded

        :param bytes data: Data to sign
        :param Derivation derivation: Derivation to use.
        :param key_type: Key type to use. Defaults to K1
        :type key_type: KeyType, optional
        :param path: Path of the key. If empty use main key
        :type path: str, optional
        :param pin: PIN code of the card
        :type pin: str, optional
        :param bool filter_eos: Filter signature so it is valid for EOS network,
                                might take longer. Defaults to False
        :type filter_eos: str, optional

        :return: The signature generated by the card in DER common format.
        :rtype: bytes

        :raises DataException: Invalid data received during signature
        """

    def signature_check(self, nonce: bytes) -> SignatureCheckResult:
        """
        Sign random 32 bytes for validation that private key of public key is on the card.

        This call doesn't increase signature counter and doesn't go into signature history.

        :param bytes nonce: random 16 bytes that will be used to sign

        :return: Message that was signed and the signature
        :rtype: SignatureCheckResult

        :raises DataValidationException: Nonce has to be 16 bytes
        :raises SeedException: There is no seed on the card
        :raises DataException: Data returned from the card is not valid
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def signing_counter(self) -> int:
        """
        :return: Counter of how many times the card has been used to sign
        :rtype: int
        """

    def unblock_pin(self, puk: str, new_pin: str) -> None:
        """
        Verifies the user using the PUK code and sets a new PIN code on the card.

        Method should be used when the user has forgotten this/hers PIN code.
        By entering the PUK code the user verifies his/hers identity and can
        set the new PIN code on the card.
        Can be used only if the card is locked.

        :requires:
            - User PIN must be locked
            - PIN code authentication must be enabled

        :param str puk: PUK code for verification of the user, before changing
                        the PIN code.
        :param str new_pin: The desired PIN code to be set for the card (4-9 digits).

        :raises PukException: PUK code not valid
        :raises CardNotBlocked: Card is not blocked, operation can't be done
        """
        if not self.pin_authentication:
            raise exceptions.PinException("PIN authentication is disabled. Can not unblock it.")

        apdu = [0x80, 0x22, 0x00, 0x00]
        puk = self.valid_puk(puk)
        new_pin = self.valid_pin(new_pin, pin_name="new pin")

        try:
            self.connection.send_encrypted(apdu, bytes(puk, 'ascii') + bytes(new_pin, 'ascii'))
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error
        except (exceptions.SecureChannelException, exceptions.PinAuthenticationException) as error:
            raise exceptions.CardNotBlocked("Card is not blocked or pin disabled") from error

        if not self.open:
            self.auth_type = AuthType.PIN

    @abc.abstractmethod
    def user_key_add(self, slot: SlotIndex, data_info: str, public_key: bytes, puk_code: str,
                     cred_id: bytes = b"") -> None:
        """
        Add user public key into the card for user authentication

        :param int slot: Slot to write the public key to
                         1 - EC256R1
                         2 - RSA key, 2048 bits, public exponent must be 65537
                         3 - FIDO key
        :param bytes data_info: 64 bytes of user data
        :param bytes public_key: Public key of the secure element to be used for authentication
        :param str puk_code: PUK code of the card
        :param cred_id: Cred id. Used for FIDO2 authentication
        :type cred_id: bytes, optional

        :raises DataValidationException: Invalid input data
        """

    @abc.abstractmethod
    def user_key_delete(self, slot: SlotIndex, puk_code: str) -> None:
        """
        Delete the user key from slot and free up for insertion

        :param SlotIndex slot: Slot to remove the key from
        :param str puk_code: PUK code of the card

        :raises DataValidationException: Invalid input data
        """

    @abc.abstractmethod
    def user_key_info(self, slot: SlotIndex) -> Tuple[str, str]:
        """
        Get the description and public key of the user key

        :requires:
            - PIN code or challenge-response validated

        :param SlotIndex slot: Index of slot for which to fetch the description

        :return: Description and public key in slot
        :rtype: tuple[str, str]
        """

    @abc.abstractmethod
    def user_key_enabled(self, slot_index: SlotIndex) -> bool:
        """
        Check if user key is present in given slot

        :param SlotIndex slot_index: Slot index to check for

        :return: Whether the user key for slot is present
        :rtype: bool
        """

    @abc.abstractmethod
    def user_key_challenge_response_nonce(self) -> bytes:
        """
        Get 32 bytes random value from the card that is used to open the card with a user key

        Take nonce value from the card. Sign it with a third party application, like TPM.
        Send the signature back into the card using
        :func:`~cryptnox_sdk_py.card.base.Base.user_key_challenge_response_open`

        :return: 32 bytes random value used as nonce
        :rtype: bytes
        """

    @abc.abstractmethod
    def user_key_challenge_response_open(self, slot: SlotIndex, signature: bytes) -> bool:
        """
        Send the nonce signature to the card to open it for operations, like it was opened by a
        PIN code

        :param SlotIndex slot: Slot to use to open the card
        :param bytes signature: Signature generated by a third party like TPM.

        :return: Whether the challenge response authentication succeeded
        :rtype: bool

        :raises DataValidationException: invalid input data
        """

    @abc.abstractmethod
    def user_key_signature_open(self, slot: SlotIndex, message: bytes, signature: bytes) -> bool:
        """
        Used for opening the card to sign the given message

        :param SlotIndex slot: Slot to use to open the card
        :param bytes message: Message that will be sent to sign operation
        :param bytes signature: Signature generated by a third party, like TPM, on the same message

        :return: Whether the challenge response authentication succeeded
        :rtype: bool

        :raises DataValidationException: invalid input data
        """

    @property
    @abc.abstractmethod
    def valid_key(self) -> bool:
        """
        Check if the card has a valid key

        :return: Whether the card has a valid key.
        :rtype: bool
        """

    @staticmethod
    def valid_pin(pin: str, pin_name: str = "pin") -> str:
        """
        Check if provided pin is valid

        :param str pin: The pin to check if valid
        :param str pin_name: Value used in DataValidationException for pin name
        :return str: Provided pin in str format if valid

        :raise DataValidationException: Provided pin is not valid
        """
        if not 4 <= len(pin) <= 9:
            raise exceptions.DataValidationException(f"The {pin_name} must have between"
                                                     f" 4 and 9 numeric characters")

        if not pin.isdigit():
            raise exceptions.DataValidationException(f"The {pin_name} must be numeric.")

        return pin + ("\0" * (9 - len(pin)))

    @staticmethod
    @abc.abstractmethod
    def valid_puk(puk: str, puk_name: str = "puk") -> str:
        """
        Check if provided puk is valid

        :param str puk: The puk to check if valid (accepts all ASCII characters)
        :param puk_name: Value used in DataValidationException for puk name. Defaults to: puk
        :type puk_name: str, optional

        :return str: Provided puk in str format if valid

        :raise DataValidationException: Provided puk is not valid (wrong length or non-ASCII characters)
        """

    @abc.abstractmethod
    def verify_pin(self, pin: str) -> None:
        """
        Check PIN code and open the card for operations that are protected.

        The method is sending the PIN code to the card to open it for other
        operations. If there is an issue an exception will be raised.


        :param str pin: PIN code to check against the card.

        :raises PinException: Invalid PIN code
        :raises DataValidationException: Invalid length or PIN code authentication disabled
        :raises SoftLock: The card has been locked and needs power cycling before
                          it can be used again
        """

    def _change_secret(self, select_pin_puk: int, value: str):
        """
        Change secret, PIN or PUK code, of the card

        :param int select_pin_puk: Change the PIN or PUK code:
                                   0 - PIN
                                   1 - PUK
        :param str value: Value of the new secret
        """
        message = [0x80, 0x21, select_pin_puk, 0x00]

        if not self.initialized:
            raise exceptions.InitializationException("Card is not initialized")

        self.connection.send_encrypted(message, bytes(value, 'ascii'))

    @staticmethod
    def _get_coded_value(value):
        value_bytes = bytes(value, 'ascii')
        return bytes([len(value_bytes)]) + value_bytes

    def _init_data(self, name: str, email: str, pin: str, puk: str,
                   pairing_secret: bytes = BASIC_PAIRING_SECRET,
                   nfc_sign: bool = False):  # pylint: disable=unused-argument
        data = Base._get_coded_value(name) + Base._get_coded_value(email) + bytes(pin, 'ascii')
        data += bytes(puk, 'ascii') + pairing_secret

        return data

    @property
    @abc.abstractmethod
    def _owner(self) -> User:
        """
        Get the available information about the owner of the card from the card

        When the card is initialized the owner name and email address are stored
        on the card. This method will read and return them.

        :return: A dictionary containing the owner name and email address
        :rtype: Dict[str, str]

        :raises CryptnoxCard.PinException: PIN code wasn't validated.
        :raises CryptnoxCard.SecureChannelException: Secure channel not opened.
        """

    @classmethod
    def __subclasshook__(cls, c):
        if cls is Base:
            attrs = set(dir(c))

            if set(cls.__abstractmethods__) <= attrs:
                return True

        return NotImplemented

    @abc.abstractmethod
    def get_manufacturer_certificate(self, hexed: bool = True) -> Any:
        """
        Get the manufacturer certificate from the card.

        :param bool hexed: Return the certificate in hexadecimal string format
        :return: Manufacturer certificate in hexadecimal string or bytes format
        :rtype: Any
        """

    def __repr__(self):
        return f'{{"serial": {self.serial_number}, "version": {self.applet_version}}}'
