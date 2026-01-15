# -*- coding: utf-8 -*-
"""
Module containing check for verification of genuineness of a card
"""
import asyncio
import re
import secrets
import sys
from typing import List

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..binary_utils import list_to_hexadecimal, hexadecimal_to_list
from ..connection import Connection
from ..exceptions import GenuineCheckException
from ..enums import Origin

_ECDSA_SHA256 = "06082a8648ce3d040302" + "03"
_MANUFACTURER_CERTIFICATE_URL = "https://verify.cryptnox.tech/certificates/"
_PUBLIC_K1_OID = "2a8648ce3d030107034200"


def origin(connection: Connection, debug: bool = False) -> Origin:
    """
    Check the origin of the card, whether it's a genuine
    :param Connection connection: connection to use for the card
    :param bool debug: print debug messages

    :return: Whether the card on the connection is genuine

    :rtype: Origin
    """
    try:
        certificates = _manufacturer_public_keys()
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return Origin.UNKNOWN

    if not certificates:
        return Origin.UNKNOWN

    certificate = _manufacturer_certificate_data(connection, debug)
    signature = _manufacturer_signature(connection, debug)

    error = False

    for public_key in certificates:
        try:
            valid = _check_signature(certificate, public_key, signature)
        except (ValueError, TypeError, InvalidSignature):
            error = True
        else:
            if valid:
                return Origin.ORIGINAL

    if error:
        return Origin.UNKNOWN

    return Origin.FAKE


def session_public_key(connection: Connection, debug: bool = False) -> str:
    """
    Check if the card in the reader is genuine Cryptnox product

    :param Connection connection: Connection to use for operation
    :param bool debug: Prints information about communication

    :return: Session public key to use opening secure channel
    :rtype: str

    :raise GenuineCheckException: The card is not genuine
    """
    card_cert_hex = _get_card_certificate(connection, debug)
    card_cert_msg = bytes.fromhex(card_cert_hex[:148])
    card_cert_sig_hex = card_cert_hex[148:]

    if debug:
        print("Card msg")
        print(card_cert_msg.hex())
        print("Card sig")
        print(card_cert_sig_hex)

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                                                              _public_key(connection))
    if not _check_signature(card_cert_msg, public_key, card_cert_sig_hex):
        raise GenuineCheckException("Wrong card signature")

    return card_cert_hex[18:148]


def manufacturer_certificate(connection: Connection, debug: bool = False) -> str:
    """
    Get the manufacturer certificate from the card in connection.

    :param Connection connection: Connection to use for operation
    :param bool debug: Prints information about communication

    :return: Manufacturer certificate read from the card in hexadecimal format
    :rtype: str
    """
    idx_page = 0
    response = connection.send_apdu([0x80, 0xF7, 0x00, idx_page, 0x00])[0]
    if not response or len(response) < 2:
        return ""

    cert_len = (response[0] << 8) + response[1]
    while len(response) < (cert_len + 2):
        idx_page += 1
        next_page = connection.send_apdu([0x80, 0xF7, 0x00, idx_page, 0x00])[0]
        if not next_page:
            break
        response = response + next_page

    certificate = list_to_hexadecimal(response[2:cert_len + 2])
    if debug:
        print(f"Manufacturer certificate: {certificate}")

    return certificate


def _manufacturer_public_keys():
    async def fetch(session, url):
        async with session.get(url) as response:
            certificate = await response.read()
            return x509.load_pem_x509_certificate(certificate).public_key()

    async def fetch_all(session, certificates):
        tasks = [asyncio.create_task(fetch(session, _MANUFACTURER_CERTIFICATE_URL + certificate))
                 for certificate in certificates]

        results = await asyncio.gather(*tasks)

        return results

    async def fetch_certificates():
        async with aiohttp.ClientSession() as session:
            async with session.get(_MANUFACTURER_CERTIFICATE_URL) as response:
                data = await response.read()
                certificates = re.findall('href="(.+?crt)"', data.decode("UTF8"))

        async with aiohttp.ClientSession() as session:
            return await fetch_all(session, certificates)

    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    return asyncio.run(fetch_certificates())


def _check_signature(message: bytes, public_key: ec.EllipticCurvePublicKey,
                     signature_hex: str) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False

    return True


def _certificate_parts(connection: Connection, debug: bool = False) -> List[str]:
    # car pub hex 65B after r1:2a8648ce3d030107034200 k1:2b8104000a034200
    parts = manufacturer_certificate(connection, debug).split(_PUBLIC_K1_OID)
    if len(parts) < 2:
        raise GenuineCheckException("No ECDSA r1 Public key found")

    return parts


def _public_key(connection: Connection, debug: bool = False) -> bytes:
    public_key = _certificate_parts(connection)[1][:130]

    if debug:
        print("card public key hex")
        print(public_key)

    return bytes.fromhex(public_key)


def _manufacturer_certificate_data(connection: Connection, debug: bool = False) -> bytes:
    # datacert_hex : prem partie + 2a8648ce3d030107034200 + pubhex
    result = bytes.fromhex(_certificate_parts(connection, debug)[0][8:] +
                           _PUBLIC_K1_OID) + _public_key(connection)
    if debug:
        print("Manufacturer data")
        print(result.hex())

    return result


def _get_card_certificate(connection: Connection, debug: bool = False) -> str:
    nonce = secrets.randbits(64)
    nonce_list = hexadecimal_to_list(f"{nonce:016X}")
    certificate = connection.send_apdu([0x80, 0xF8, 0x00, 0x00, 0x08] + nonce_list)[0]

    card_cert_hex = list_to_hexadecimal(certificate)
    if debug:
        print("Card cert")
        print(card_cert_hex)
    # C ?
    if card_cert_hex[:2] != "43":
        print("Bad card certificate header")
        return ""
    # Nonce?
    if int(card_cert_hex[2:18], 16) != nonce:
        print("Card certificate nonce is not the one provided")
        return ""

    return card_cert_hex


def _manufacturer_signature(connection: Connection, debug: bool = False) -> str:
    certificate_parts = manufacturer_certificate(connection,
                                                 debug).split(_ECDSA_SHA256)

    if len(certificate_parts) < 2:
        return ""

    signature_length = int(certificate_parts[1][0:2], 16)
    signature = certificate_parts[1][2:]

    assert len(signature) == 2 * signature_length

    if certificate_parts[1][2:4] == "00":
        signature = certificate_parts[1][4:]

    if debug:
        print("mft cert sig hex")
        print(signature)

    return signature
