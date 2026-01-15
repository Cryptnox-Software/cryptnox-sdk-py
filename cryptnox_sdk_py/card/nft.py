# -*- coding: utf-8 -*-
"""
Module containing class for NFT card
"""
from typing import Tuple

from . import base
from . import basic_g1
from .user_data import UserData
from .. import exceptions
from ..enums import (
    Derivation,
    KeyType,
    SlotIndex
)


class Nft(basic_g1.BasicG1):
    """
    Class containing functionality for NFT card which has limited capabilities
    """
    type = ord("N")
    _type = "NFT"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_data = UserData(self, 1)

    def derive(self, key_type: KeyType = KeyType.K1, path: str = ""):
        raise NotImplementedError("Card doesn't have this functionality")

    def get_public_key(self, derivation: Derivation = Derivation.CURRENT_KEY,
                       key_type: KeyType = KeyType.K1, path: str = "",
                       compressed: bool = False, hexed: bool = True) -> str:
        if derivation is not Derivation.CURRENT_KEY:
            raise exceptions.DerivationSelectionException("This card type doesn't support this "
                                                          "derivation form")

        if key_type is not KeyType.K1:
            raise exceptions.KeySelectionException("This card type doesn't support this key type")

        return super().get_public_key(derivation, key_type, path, compressed, hexed)

    def get_public_key_clear(self, derivation: int, path: str = "", compressed: bool = True) -> bytes:

        if derivation != Derivation.CURRENT_KEY:
            raise exceptions.DerivationSelectionException("This card type doesn't support this derivation form")

        return super().get_public_key_clear(derivation, path, compressed)

    def set_pubexport(self, status: bool, p1: int, puk: str) -> None:

        if p1 not in [0, 1]:
            raise exceptions.DataValidationException("P1 must be 0 (xpub) or 1 (clear pubkey)")

        super().set_pubexport(status, p1, puk)

    def generate_random_number(self, size: int) -> bytes:
        raise NotImplementedError("Card doesn't have this functionality")

    def load_seed(self, seed: bytes, pin: str = "") -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def set_pin_authentication(self, status: bool, puk: str) -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def set_pinless_path(self, path: str, puk: str) -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_add(self, slot: SlotIndex, data_info: str, public_key: bytes, puk_code: str,
                     cred_id: bytes = b"") -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_delete(self, slot: SlotIndex, puk_code: str) -> None:
        raise NotImplementedError("")

    def user_key_info(self, slot: SlotIndex) -> Tuple[str, str]:
        raise NotImplementedError("")

    def user_key_enabled(self, slot_index: SlotIndex):
        return False

    def user_key_challenge_response_nonce(self) -> bytes:
        raise NotImplementedError("")

    def user_key_challenge_response_open(self, slot: SlotIndex, signature: bytes) -> bool:
        raise NotImplementedError("")

    def user_key_signature_open(self, slot: SlotIndex, message: bytes, signature: bytes) -> bool:
        raise NotImplementedError("")

    def signature_check(self, nonce: bytes) -> base.SignatureCheckResult:
        message = [0x80, 0xF8, 0x01, 0x00]

        try:
            result = self.connection.send_encrypted(message, nonce)
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x84:
                raise exceptions.DataValidationException("Nonce has to be 16 bytes.")
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SeedException("Seed not on card.")
            raise error

        if result[0:2] != b"CR" or result[35] != 0x00:
            raise exceptions.DataException("Result not in correct format.")

        return base.SignatureCheckResult(result[:36], result[36:])

    def _init_data(self, name: str, email: str, pin: str, puk: str,
                   pairing_secret: bytes = base.BASIC_PAIRING_SECRET, nfc_sign: bool = False):
        data = Nft._get_coded_value(name) + Nft._get_coded_value(email)
        data += bytes(pin, 'ascii') + bytes(puk, 'ascii')
        data += bytes.fromhex("5A5A") if nfc_sign else bytes.fromhex("A5A5")
        data += pairing_secret

        return data
