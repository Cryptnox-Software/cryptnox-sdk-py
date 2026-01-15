# -*- coding: utf-8 -*-
"""
Module containing class for Basic card of 1st generation
"""
from collections import namedtuple
from typing import (
    NamedTuple,
    Tuple
)

from cryptography.hazmat.primitives.asymmetric import ec

from . import base
from .custom_bits import CustomBits
from .user_data import UserData
from .. import exceptions
from ..binary_utils import path_to_bytes, binary_to_list
from ..cryptos import encode_pubkey
from ..enums import (
    Derivation,
    KeyType,
    SeedSource,
    SlotIndex
)


class BasicG1(base.Base):
    """
    Class containing functionality for Basic cards of the 1st generation
    """
    select_apdu = [0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12]
    puk_rule = "12 ASCII characters"

    _ALGORITHM = ec.SECP256R1
    PUK_LENGTH = 12
    MAX_ASCII_LENGTH = 128

    _INITIALIZATION_FLAG = int("01000000", 2)
    _SEED_FLAG = int("00100000", 2)
    _PIN_AUTH_FLAG = int("00010000", 2)
    _PINLESS_FLAG = int("00001000", 2)
    _EXTENDED_PUBLIC_KEY = int("00000100", 2)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_data = UserData(self, reading_index_offset=1)
        self.custom_bits = CustomBits(self._data[4:], self._update_custom_bytes)
        self.xpubread = False
        self.clearpubrd = False

    def change_pairing_key(self, index: int, pairing_key: bytes, puk: str = "") -> None:
        if len(pairing_key) != 32:
            raise exceptions.DataValidationException("Pairing key has to be 32 bytes.")
        if index != 0:
            raise exceptions.DataValidationException("Index must be 0")

        puk = self.valid_puk(puk)
        try:
            self.connection.send_encrypted([0x80, 0xDA, index, 0x00], pairing_key + puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error

    def derive(self, key_type: KeyType = KeyType.K1, path: str = ""):
        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("There is no seed on the card")

        message = [0x80, 0xD1, 0x08, 0x00]
        binary_path = path_to_bytes(path) if path else b""
        self.connection.send_encrypted(message, binary_path)

    def dual_seed_public_key(self, pin: str = "") -> bytes:
        if self.auth_type == base.AuthType.PIN:
            pin = self.valid_pin(pin)

        result = self.connection.send_encrypted([0x80, 0xD0, 0x04, 0x00], pin.encode("ascii"))

        if len(result) < 65:
            raise exceptions.DataException("Bad data received. Dual seed read card public key")

        return result

    def dual_seed_load(self, data: bytes, pin: str = "") -> None:
        if self.auth_type == base.AuthType.PIN:
            pin = self.valid_pin(pin)

        self.connection.send_encrypted([0x80, 0xD0, 0x05, 0x00], data + pin.encode("ascii"))

        if not self.open:
            self.auth_type = base.AuthType.PIN

    @property
    def extended_public_key(self) -> bool:
        return bool(self._data[1] & BasicG1._EXTENDED_PUBLIC_KEY)

    def generate_random_number(self, size: int) -> bytes:
        try:
            size = int(size)
        except ValueError as error:
            raise exceptions.DataValidationException("Checksum has to be an integer") from error
        if 16 > size > 64 or size % 4:
            raise exceptions.DataValidationException("Checksum value must be between 4 and 8.")

        return self.connection.send_encrypted([0x80, 0xD3, size, 0x00], b"")

    def generate_seed(self, pin: str = "") -> bytes:
        if self.auth_type != base.AuthType.USER_KEY:
            pin = self.valid_pin(pin)

        message = [0x80, 0xD4, 0x00, 0x00]

        try:
            result = self.connection.send_encrypted(message, pin.encode("ascii"))
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\nIt is not possible to "
                                                     "generate another one without resetting the card") from error
            raise

        self._data[1] |= BasicG1._SEED_FLAG

        if result and not self.open:
            self.auth_type = base.AuthType.PIN

        return result

    def get_manufacturer_certificate(self, hexed: bool = True):
        idx_page = 0
        mnft_cert_resp = self.connection.send_apdu([0x80, 0xF7, 0x00, idx_page, 0x00])[0]
        if not mnft_cert_resp or len(mnft_cert_resp) < 2:
            return "" if hexed else b""

        cert_len = (mnft_cert_resp[0] << 8) + mnft_cert_resp[1]
        while len(mnft_cert_resp) < (cert_len + 2):
            idx_page += 1
            mnft_cert_resp = (
                mnft_cert_resp
                + self.connection.send_apdu([0x80, 0xF7, 0x00, idx_page, 0x00])[0]
            )
        assert len(mnft_cert_resp) == (cert_len + 2)
        cert = mnft_cert_resp[2:]
        return "".join([f"{x:02x}" for x in cert])

    def get_public_key(self, derivation: Derivation, key_type: KeyType = KeyType.K1, path: str = "",
                       compressed: bool = True, hexed: bool = True) -> str:
        if derivation == Derivation.CURRENT_KEY and path:
            raise exceptions.DataValidationException("Path must be empty for current path")

        if not self.initialized:
            raise exceptions.InitializationException("Card is not initialized")

        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("There is no seed on the card")

        key_type = KeyType(key_type)
        derivation = Derivation(derivation)

        if derivation in (Derivation.PINLESS_PATH,
                          Derivation.DERIVE_AND_MAKE_CURRENT):
            raise exceptions.DerivationSelectionException("This operation doesn't support this derivation form")

        message = [0x80, 0xC2, derivation + key_type, 1]
        binary_path = path_to_bytes(path) if path else b""
        data = self.connection.send_encrypted(message, binary_path)

        result = data.hex() if hexed else data
        if compressed:
            result = encode_pubkey(result, "bin_compressed").hex()

        return result

    def get_public_key_extended(self, key_type: KeyType = KeyType.K1, puk: str = "") -> str:

        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("There is no seed on the card")

        # Step 1: Try to enable XPUB capability if PUK provided
        if puk:
            try:
                enable_data = b"\x01" + puk.encode("ascii")  # status=1 to enable + PUK bytes
                enable_apdu = [0x80, 0xC5, 0x00, 0x00]
                self.connection.send_encrypted(enable_apdu, enable_data)
            except (exceptions.GenericException, exceptions.PinException):
                # If enabling fails, continue anyway - it might already be enabled
                pass

        # Step 2: Build APDU to get extended public key
        p1 = 0x00 if key_type == KeyType.K1 else 0x10
        p2 = 0x02  # extended public key (BIP32)
        get_apdu = [0x80, 0xC2, p1, p2]

        # Send command and get response
        data = self.connection.send_encrypted(get_apdu, b"")

        # Return hex string result
        return data.hex()

    def get_public_key_clear(self, derivation: int, path: str = "", compressed: bool = True) -> bytes:

        # Validate inputs
        if not self.initialized:
            raise exceptions.InitializationException("Card is not initialized")

        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("There is no seed on the card")

        SELe = [0x80, 0xC2, int(derivation), 1]

        if not path:
            pubkeyl, status1, status2 = self.connection.send_apdu(SELe + [0])
        else:
            # Only for testing, should throw error
            path_bin = path_to_bytes(path)
            pubkeyl, status1, status2 = self.connection.send_apdu(SELe + [len(path_bin)] + binary_to_list(path_bin))

        # Check if we got an error status
        if status1 != 0x90 or status2 != 0x00:
            raise exceptions.ReadPublicKeyException(f"Card returned error status: {status1:02x}{status2:02x}")

        pubkey = bytes(pubkeyl)

        # Handle different public key formats returned by the card
        if len(pubkey) == 32:
            # Card returned only X-coordinate (32 bytes)
            # This is common for clear channel public key reading
            print(f"Received 32-byte public key (x-coordinate): {pubkey.hex()}")
            return pubkey

        if len(pubkey) == 33 and pubkey[0] in [0x02, 0x03]:
            # Compressed format (33 bytes starting with 0x02 or 0x03)
            return pubkey

        if len(pubkey) == 65 and pubkey[0] == 0x04:
            # Card returned uncompressed public key (65 bytes)
            if compressed:
                pub_bin = encode_pubkey(pubkey, "bin_compressed")
                return pub_bin
            return pubkey

        # Unknown format, return as-is
        return pubkey

    def decrypt(self, p1: int, pubkey: bytes, encrypted_data: bytes = b"", pin: str = "") -> bytes:

        # Validate inputs
        if not self.initialized:
            raise exceptions.InitializationException("Card is not initialized")

        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("No seed/key loaded")

        if p1 not in [0, 1]:
            raise exceptions.DataValidationException("P1 must be 0 (output symmetric key) or 1 (decrypt data)")

        if len(pubkey) != 65:
            raise exceptions.DataValidationException("Public key must be 65 bytes (X9.62 uncompressed format)")

        if pubkey[0] != 0x04:
            raise exceptions.DataValidationException("Public key must be in X9.62 uncompressed format (0x04|X|Y)")

        # Prepare data based on P1 and authentication status
        data = b""

        # Add PIN if provided (right-padded with 0x00 to 9 bytes)
        if pin:
            pin_bytes = pin.encode("ascii")
            if len(pin_bytes) > 9:
                raise exceptions.DataValidationException("PIN too long (max 9 characters)")
            pin_padded = pin_bytes + b"\x00" * (9 - len(pin_bytes))
            data += pin_padded

        # Add public key
        data += pubkey

        # Add encrypted data if P1=1
        if p1 == 1:
            if not encrypted_data:
                raise exceptions.DataValidationException("Encrypted data required when P1=1")

            # Check if data length is multiple of 16 bytes (AES block size)
            if len(encrypted_data) % 16 != 0:
                raise exceptions.DataValidationException("Encrypted data length must be multiple of 16 bytes")

            data += encrypted_data

        # Validate total data length
        if p1 == 0:
            # P1 = 0: No user key auth, with PIN: 74 bytes, User key auth, no PIN: 65 bytes
            expected_length = 74 if pin else 65
            if len(data) != expected_length:
                raise exceptions.DataValidationException(
                    f"Data length incorrect: {len(data)} bytes (expected {expected_length})")
        else:
            # P1 = 1: No user key auth, with PIN: at least 74 bytes, User key auth, no PIN: at least 65 bytes
            min_length = 74 if pin else 65
            if len(data) < min_length:
                raise exceptions.DataValidationException(
                    f"Data length too short: {len(data)} bytes (minimum {min_length})")

        # Send DECRYPT command
        cmd = [0x80, 0xC4, p1, 0x00]

        try:
            result = self.connection.send_encrypted(cmd, data)
            return result
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SeedException("No seed/key loaded") from error
            if error.status[0] == 0x63:
                raise exceptions.PinException("PIN is not correct") from error
            if error.status[0] == 0x6A and error.status[1] == 0x80:
                raise exceptions.DataValidationException("Data length is not correct") from error
            if error.status[0] == 0x69 and error.status[1] == 0x82:
                raise exceptions.GenericException("Data input length is far too long") from error
            raise

    def history(self, index: int = 0) -> NamedTuple:
        Entry = namedtuple('HistoryEntry', ['signing_counter', 'hashed_data'])

        result = self.connection.send_encrypted([0x80, 0xFB, index, 0x00], b"")

        return Entry(int.from_bytes(result[:4], "big"), result[4:])

    @property
    def initialized(self) -> bool:
        return bool(self._data[1] & BasicG1._INITIALIZATION_FLAG)

    def load_wrapped_seed(self, seed: bytes, pin: str = "") -> None:
        if self.auth_type == base.AuthType.PIN:
            pin = self.valid_pin(pin) or ""

        try:
            self.connection.send_encrypted([0x80, 0xD0, 0x06, 0x00], seed + pin.encode("ascii"))
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\nIt is not possible to "
                                                     "generate another one without resetting the card") from error
            raise

        self._data[1] |= BasicG1._SEED_FLAG

        if not self.open:
            self.auth_type = base.AuthType.PIN

    def load_seed(self, seed: bytes, pin: str = "") -> None:
        if self.auth_type == base.AuthType.PIN:
            pin = self.valid_pin(pin) or ""

        try:
            self.connection.send_encrypted([0x80, 0xD0, 0x03, 0x00], seed + pin.encode("ascii"))
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\nIt is not possible to "
                                                     "generate another one without resetting the card") from error
            raise

        self._data[1] |= BasicG1._SEED_FLAG

        if not self.open:
            self.auth_type = base.AuthType.PIN

    @property
    def pin_authentication(self) -> bool:
        return bool(self._data[1] & BasicG1._PIN_AUTH_FLAG)

    @property
    def pinless_enabled(self) -> bool:
        return bool(self._data[1] & BasicG1._PINLESS_FLAG)

    def reset(self, puk: str) -> None:
        puk = self.valid_puk(puk)

        try:
            self.connection.send_encrypted([0x80, 0xFD, 0, 0], puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error

        self.auth_type = base.AuthType.NO_AUTH

    @property
    def seed_source(self) -> SeedSource:
        if not self.valid_key:
            return SeedSource.NO_SEED

        return SeedSource(self._info[0])

    def set_pin_authentication(self, status: bool, puk: str) -> None:
        puk = self.valid_puk(puk)
        status = int(not status).to_bytes(1, "big")

        try:
            self.connection.send_encrypted([0x80, 0xC3, 0, 0], status + puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.PinAuthenticationException("PIN can't be set without user key.")
            raise

        self._data[1] |= BasicG1._PIN_AUTH_FLAG

    def set_pinless_path(self, path: str, puk: str) -> None:
        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("There is no seed on the card")

        puk = self.valid_puk(puk)
        path = path_to_bytes(path) if path else b""

        try:
            self.connection.send_encrypted([0x80, 0xC1, 0, 0], puk.encode("ascii") + path)
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error
        except exceptions.GenericException as error:
            if error.status[0] == 0x6A and error.status[1] == 0x80:
                raise exceptions.DataValidationException("Path length not multiple of 4")
            if error.status[0] == 0x69:
                if error.status[1] == 0x83:
                    raise exceptions.DataValidationException("Path doesn't start with EIP1581 path")
                if error.status[1] == 0x85:
                    raise exceptions.DataValidationException("No seed or extended key")

            raise

        self._data[1] |= BasicG1._PINLESS_FLAG

    def set_extended_public_key(self, status: bool, puk: str) -> None:
        """
        Set extended public key capability.

        This is a convenience wrapper around set_pubexport(status, 0, puk).
        Use set_pubexport() directly for more control.
        """
        self.set_pubexport(status, 0, puk)

    @property
    def signing_counter(self) -> int:
        result = self._info
        position = 1 + int(result[1]) + int(result[result[1] + 2]) + 2

        return int.from_bytes(result[position:], "big")

    def user_key_add(self, slot: SlotIndex, data_info: str, public_key: bytes, puk_code: str,
                     cred_id: bytes = b"") -> None:
        data_info_length = 64
        puk_code = self.valid_puk(puk_code)
        if len(data_info) > data_info_length:
            raise exceptions.DataValidationException(f"Data info can't be longer than {data_info_length} characters")

        data_info += "\0" * (data_info_length - len(data_info))

        data = bytes([slot]) + data_info.encode("ascii")
        if slot == SlotIndex.FIDO:
            if not cred_id:
                raise exceptions.DataValidationException("Cred id is required")
            data += bytes([len(cred_id)]) + cred_id
        data += public_key + puk_code.encode("ascii")

        try:
            self.connection.send_encrypted([0x80, 0xD5, 0x00, 0x00], data)
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            if error.status == 0x6984:
                raise exceptions.DataValidationException("Invalid public key")
            if error.status == 0x6986:
                raise exceptions.DataValidationException("Slot not empty")
            if error.status == 0x6700:
                raise exceptions.DataValidationException("Invalid data length")
            raise
        self._data[3] = BasicG1._set_bit(self._data[3], slot - 1)

    def user_key_delete(self, slot: SlotIndex, puk_code: str) -> None:
        puk_code = self.valid_puk(puk_code)
        data = bytes([slot.value]) + puk_code.encode("ascii")
        try:
            self.connection.send_encrypted([0x80, 0xD7, 0x00, 0x00], data)
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            if error.status == 0x6700:
                raise exceptions.DataValidationException("Invalid data length")
            if error.status == 0x6986:
                raise exceptions.DataValidationException("Slot empty")
            raise

        self._data[3] = BasicG1._clear_bit(self._data[3], slot - 1)

    def user_key_info(self, slot: SlotIndex) -> Tuple[str, str]:
        try:
            result = self.connection.send_encrypted([0x80, 0xFA, int(slot), 0x00], b"", True)
        except exceptions.GenericException as error:
            if error.status == 0x6985:
                raise exceptions.SecureChannelException("Command may need a secured channel")
            raise

        return result[:64].decode("ascii"), result[64:].hex()

    def user_key_enabled(self, slot_index: SlotIndex):
        return bool(self._data[3] & pow(2, slot_index - 1))

    def user_key_challenge_response_nonce(self) -> bytes:
        result = self.connection.send_encrypted([0x80, 0xD6, 0x01, 0x00], b"")

        return result

    def user_key_challenge_response_open(self, slot: SlotIndex, signature: bytes) -> bool:
        data = bytes([slot.value]) + signature
        try:
            result = self.connection.send_encrypted([0x80, 0xD6, 0x02, 0x00], data)
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            if error.status == 0x6985:
                raise exceptions.DataValidationException("Nonce not found")
            raise

        result = int.from_bytes(result, "big") == 0x01

        if result and not self.open:
            self.auth_type = base.AuthType.USER_KEY

        return result

    def user_key_signature_open(self, slot: SlotIndex, message: bytes, signature: bytes) -> bool:
        data = bytes([slot.value]) + message + signature
        try:
            result = self.connection.send_encrypted([0x80, 0xD6, 0x00, 0x00], data)
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            raise

        return int.from_bytes(result, "big") == 0x01

    def generate_seed_wrapper(self, size: int = 2048) -> bytes:
        if size % 8 != 0:
            raise exceptions.DataValidationException("Size must be a multiple of 8")
        try:
            size_bytes = size.to_bytes(2, 'big')
            return self.connection.send_encrypted([0x80, 0xF9, 0x00, 0x00], size_bytes, True)
        except Exception as error:
            raise error

    def sign_public(self, key_type: KeyType = KeyType.K1) -> bytes:
        if self.seed_source == "NO_SEED":
            raise exceptions.SeedException("There is no key on the card")

        CLA = 0x80
        INS = 0xC6
        P1 = key_type.value if key_type == KeyType.R1 else KeyType.K1.value
        P2 = 0x00
        DATA = b""

        apdu_command = [CLA, INS, P1, P2]
        response = self.connection.send_encrypted(apdu_command, DATA, True)

        return response

    def sign(self, data: bytes, derivation: Derivation = Derivation.CURRENT_KEY, key_type: KeyType = KeyType.K1,
             path: str = "", pin: str = "", filter_eos: bool = False) -> bytes:
        if self.seed_source == SeedSource.NO_SEED:
            raise exceptions.SeedException("There is no key on the card")

        pin = self.valid_pin(pin) if pin else ""
        derivation = Derivation(derivation)
        key_type = KeyType(key_type)

        if derivation == Derivation.DERIVE_AND_MAKE_CURRENT or \
                (derivation == Derivation.PINLESS_PATH and key_type == KeyType.R1):
            raise exceptions.DerivationSelectionException("This operation doesn't support this derivation form")

        signal = [0x80, 0xC0, derivation + key_type, 0x01 if filter_eos else 0x00]

        derivation_base = (derivation + key_type) & 0x0F
        if derivation_base in (1, 2):
            data += path_to_bytes(path)

        if pin:
            data += bytes(pin, 'ascii')

        result = self.connection.send_encrypted(signal, data)

        if not result or result[0] != 0x30:
            self.auth_type = base.AuthType.NO_AUTH
            raise exceptions.DataException("Invalid data received during signature")

        return result

    @property
    def valid_key(self) -> bool:
        return bool(self._data[1] & BasicG1._SEED_FLAG)

    @staticmethod
    def valid_puk(puk: str, puk_name: str = "puk") -> str:
        if len(puk) != BasicG1.PUK_LENGTH:
            raise exceptions.DataValidationException(f"The {puk_name} must have {BasicG1.PUK_LENGTH} "
                                                     f"ASCII characters")
        if not all(ord(c) < BasicG1.MAX_ASCII_LENGTH for c in puk):
            raise exceptions.DataValidationException(f"The {puk_name} must contain only ASCII characters.")

        return puk

    def signature_check(self, nonce: bytes) -> base.SignatureCheckResult:
        """
        Sign random 32 bytes for validation that private key of public key is on the card.

        BasicG1 cards do not support this operation. Use NFT card instead.

        :raises NotImplementedError: BasicG1 cards do not support signature_check
        """
        raise NotImplementedError("BasicG1 cards do not support signature_check")

    def verify_pin(self, pin: str) -> None:
        pin = self.valid_pin(pin)
        apdu = [0x80, 0x20, 0x00, 0x00]

        try:
            self.connection.send_encrypted(apdu, bytes(pin, 'ascii'))
        except exceptions.PinException as error:
            if error.number_of_retries != 0:
                raise

            apdu = [0x80, 0x22, 0x00, 0x00]
            try:
                self.connection.send_encrypted(apdu, bytes("", 'ascii') + bytes("", 'ascii'))
            except (exceptions.DataValidationException, exceptions.PinException):
                pass
            except exceptions.SecureChannelException as sc_error:
                raise exceptions.SoftLock("The card is soft locked. Power cycle required before it can be used "
                                          "again.") from sc_error
            raise
        except exceptions.GenericException as error:
            if error.status == 0x6700:
                raise exceptions.DataValidationException("Incorrect length")
            if error.status == 0x6986:
                raise exceptions.DataValidationException("PIN authentication disabled")

        if not self.open:
            self.auth_type = base.AuthType.PIN

    @staticmethod
    def _clear_bit(value, bit):
        return value & ~(1 << bit)

    @property
    def _info(self) -> bytes:
        try:
            result = self.connection.send_encrypted([0x80, 0xFA, 0x00, 0x00], b"")
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SecureChannelException("Command may need a secured channel")
            raise

        return result

    @property
    def _owner(self) -> base.User:
        try:
            data = self._info
        except exceptions.CryptnoxException:
            return base.User("", "")

        start = 1
        name_length = data[start]
        name = data[start + 1:start + name_length + 1].decode("ascii")
        email_length = data[name_length + 1 + start]
        user_list_offset = email_length + 2 + name_length + start
        email = data[start + name_length + 2:user_list_offset].decode("ascii")

        return base.User(name, email)

    @staticmethod
    def _set_bit(value, bit):
        return value | (1 << bit)

    def _update_custom_bytes(self, data: bytes) -> None:
        message = [0x80, 0xFC, 0x01, 0x00]
        self.connection.send_encrypted(message, data)

    def set_pubexport(self, status: bool, p1: int, puk: str) -> None:

        if p1 not in [0, 1]:
            raise exceptions.DataValidationException("P1 must be 0 (xpub) or 1 (clear pubkey)")

        puk = self.valid_puk(puk)

        cmd = [0x80, 0xC5, p1, 0x00]
        if status:
            statbin = b"\x01"  # Enable
        else:
            statbin = b"\x00"  # Disable

        try:
            self.connection.send_encrypted(cmd, statbin + puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(number_of_retries=error.number_of_retries) from error

    def set_xpubread(self, status: bool, puk: str) -> None:

        self.set_pubexport(status, 0, puk)
        self.xpubread = status

    def set_clearpubkey(self, status: bool, puk: str) -> None:

        self.set_pubexport(status, 1, puk)
        self.clearpubrd = status
