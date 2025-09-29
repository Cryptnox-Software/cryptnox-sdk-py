import pytest

from cryptnoxpy.card.basic_g1 import BasicG1
from cryptnoxpy import exceptions
from cryptnoxpy.binary_utils import path_to_bytes, binary_to_list


class FakeConnection:
    def __init__(self, responses):
        # responses: list of tuples (data_bytes, sw1, sw2)
        self._responses = list(responses)
        self.last_apdu = None

    def send_apdu(self, apdu):
        self.last_apdu = list(apdu)
        if not self._responses:
            raise AssertionError("No more fake responses configured")
        return self._responses.pop(0)

    def send_encrypted(self, apdu, data=b"", *args, **kwargs):
        # For BasicG1._info and other reads, return bytes where first byte encodes seed source
        # Use INTERNAL seed source ('S') to be valid
        if apdu[:3] == [0x80, 0xFA, 0x00]:
            # [seed_source, name_len=0, email_len=0, rest zeros]
            return bytes([ord('S'), 0, 0] + [0] * 20)
        # Default: behave like no data
        return b""


def make_basic_g1_for_tests(conn, initialized=True, has_seed=True):
    # Build 36 bytes of data for BasicG1 with flags in _data[1]
    flags = 0
    if initialized:
        flags |= 0x40  # _INITIALIZATION_FLAG
    if has_seed:
        flags |= 0x20  # _SEED_FLAG
    data = [0x00, flags] + [0x00] * 34
    applet_version = [1, 6, 1]
    return BasicG1(conn, serial=123, applet_version=applet_version, data=data, debug=False)


def test_basicg1_clear_pubkey_32byte_x_only_returns_same_bytes():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0)
    assert isinstance(result, (bytes, bytearray))
    assert bytes(result) == x_only


def test_basicg1_clear_pubkey_33byte_compressed_returns_as_is():
    compressed = b"\x02" + (b"\x22" * 32)
    conn = FakeConnection(responses=[(list(compressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=True)
    assert bytes(result) == compressed


def test_basicg1_clear_pubkey_65byte_uncompressed_respects_compressed_flag_false():
    # Uncompressed: 0x04 | X(32) | Y(32)
    uncompressed = b"\x04" + (b"\x33" * 64)
    conn = FakeConnection(responses=[(list(uncompressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=False)
    assert bytes(result) == uncompressed


def test_basicg1_clear_pubkey_status_error_raises():
    bad = b"\x00" * 10
    conn = FakeConnection(responses=[(list(bad), 0x6A, 0x80)])
    card = make_basic_g1_for_tests(conn)
    with pytest.raises(exceptions.ReadPublicKeyException):
        card.get_public_key_clear(derivation=0)


def test_basicg1_clear_pubkey_initialization_required():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    # initialized=False triggers InitializationException
    card = make_basic_g1_for_tests(conn, initialized=False, has_seed=True)
    with pytest.raises(exceptions.InitializationException):
        card.get_public_key_clear(derivation=0)


def test_basicg1_clear_pubkey_no_seed():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])

    # Mock send_encrypted to report NO_SEED (0)
    def send_encrypted_no_seed(apdu, data=b"", *args, **kwargs):
        if apdu[:3] == [0x80, 0xFA, 0x00]:
            return bytes([0, 0, 0] + [0] * 20)
        return b""

    conn.send_encrypted = send_encrypted_no_seed
    card = make_basic_g1_for_tests(conn, initialized=True, has_seed=False)
    with pytest.raises(exceptions.SeedException):
        card.get_public_key_clear(derivation=0)


def test_basicg1_clear_pubkey_with_path_apdu_composition():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    path = "m/44'/0'/0'"
    result = card.get_public_key_clear(derivation=0, path=path)
    assert bytes(result) == x_only
    # Verify APDU was composed correctly
    path_bin = path_to_bytes(path)
    expected = [0x80, 0xC2, 0x00, 0x01]
    expected = expected + [len(path_bin)] + list(binary_to_list(path_bin))
    assert conn.last_apdu == expected


def test_basicg1_clear_pubkey_unknown_length_passthrough():
    odd = b"\xAA" * 17
    conn = FakeConnection(responses=[(list(odd), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0)
    assert bytes(result) == odd


def test_basicg1_clear_pubkey_uncompressed_compressed_flag_true():
    # 65-byte uncompressed should compress to 33 bytes when compressed=True
    uncompressed = b"\x04" + (b"\x55" * 64)
    conn = FakeConnection(responses=[(list(uncompressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=True)
    assert len(result) == 33
    assert result[0] in (0x02, 0x03)


def test_basicg1_clear_pubkey_compressed_with_compressed_false_returns_as_is():
    compressed = b"\x02" + (b"\x66" * 32)
    conn = FakeConnection(responses=[(list(compressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=False)
    assert bytes(result) == compressed


def test_basicg1_clear_pubkey_nonzero_derivation():
    x_only = b"\x77" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=2)
    assert bytes(result) == x_only

import pytest

from cryptnoxpy.card.basic_g1 import BasicG1
from cryptnoxpy import exceptions
from cryptnoxpy.binary_utils import path_to_bytes, binary_to_list


class FakeConnection:
    def __init__(self, responses):
        # responses: list of tuples (data_bytes, sw1, sw2)
        self._responses = list(responses)
        self.last_apdu = None

    def send_apdu(self, apdu):
        self.last_apdu = list(apdu)
        if not self._responses:
            raise AssertionError("No more fake responses configured")
        return self._responses.pop(0)

    def send_encrypted(self, apdu, data=b"", *args, **kwargs):
        # For BasicG1._info and other reads, return bytes where first byte encodes seed source
        # Construct minimal info: first byte non-zero => SeedSource not NO_SEED
        # Return a dummy buffer of sufficient length
        if apdu[:3] == [0x80, 0xFA, 0x00]:
            # [seed_source, name_len=0, email_len=0, rest zeros]
            # Use INTERNAL seed source ('S') to be valid
            return bytes([ord('S'), 0, 0] + [0] * 20)
        # Default: behave like no data
        return b""


def make_basic_g1_for_tests(conn, initialized=True, has_seed=True):
    # Build 36 bytes of data for BasicG1 with flags in _data[1]
    flags = 0
    if initialized:
        flags |= 0x40  # _INITIALIZATION_FLAG
    if has_seed:
        flags |= 0x20  # _SEED_FLAG
    data = [0x00, flags] + [0x00] * 34
    applet_version = [1, 6, 1]
    return BasicG1(conn, serial=123, applet_version=applet_version, data=data, debug=False)


def test_basicg1_clear_pubkey_32byte_x_only_returns_same_bytes():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0)
    assert isinstance(result, (bytes, bytearray))
    assert bytes(result) == x_only


def test_basicg1_clear_pubkey_33byte_compressed_returns_as_is():
    compressed = b"\x02" + (b"\x22" * 32)
    conn = FakeConnection(responses=[(list(compressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=True)
    assert bytes(result) == compressed


def test_basicg1_clear_pubkey_65byte_uncompressed_respects_compressed_flag_false():
    # Uncompressed: 0x04 | X(32) | Y(32)
    uncompressed = b"\x04" + (b"\x33" * 64)
    conn = FakeConnection(responses=[(list(uncompressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=False)
    assert bytes(result) == uncompressed


def test_basicg1_clear_pubkey_status_error_raises():
    bad = b"\x00" * 10
    conn = FakeConnection(responses=[(list(bad), 0x6A, 0x80)])
    card = make_basic_g1_for_tests(conn)
    with pytest.raises(exceptions.ReadPublicKeyException):
        card.get_public_key_clear(derivation=0)


def test_basicg1_clear_pubkey_initialization_required():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    # initialized=False triggers InitializationException before APDU is used logically
    card = make_basic_g1_for_tests(conn, initialized=False, has_seed=True)
    with pytest.raises(exceptions.InitializationException):
        card.get_public_key_clear(derivation=0)


def test_basicg1_clear_pubkey_no_seed():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])

    # Mock send_encrypted to report NO_SEED (0)
    def send_encrypted_no_seed(apdu, data=b"", *args, **kwargs):
        if apdu[:3] == [0x80, 0xFA, 0x00]:
            return bytes([0, 0, 0] + [0] * 20)
        return b""

    conn.send_encrypted = send_encrypted_no_seed
    card = make_basic_g1_for_tests(conn, initialized=True, has_seed=False)
    with pytest.raises(exceptions.SeedException):
        card.get_public_key_clear(derivation=0)


def test_basicg1_clear_pubkey_with_path_apdu_composition():
    x_only = b"\x11" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    path = "m/44'/0'/0'"
    result = card.get_public_key_clear(derivation=0, path=path)
    assert bytes(result) == x_only
    # Verify APDU was composed correctly
    path_bin = path_to_bytes(path)
    expected = [0x80, 0xC2, 0x00, 0x01]
    expected = expected + [len(path_bin)] + list(binary_to_list(path_bin))
    assert conn.last_apdu == expected


def test_basicg1_clear_pubkey_unknown_length_passthrough():
    odd = b"\xAA" * 17
    conn = FakeConnection(responses=[(list(odd), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0)
    assert bytes(result) == odd


def test_basicg1_clear_pubkey_uncompressed_compressed_flag_true():
    # 65-byte uncompressed should compress to 33 bytes when compressed=True
    uncompressed = b"\x04" + (b"\x55" * 64)
    conn = FakeConnection(responses=[(list(uncompressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=True)
    assert len(result) == 33
    assert result[0] in (0x02, 0x03)


def test_basicg1_clear_pubkey_compressed_with_compressed_false_returns_as_is():
    compressed = b"\x02" + (b"\x66" * 32)
    conn = FakeConnection(responses=[(list(compressed), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=0, compressed=False)
    assert bytes(result) == compressed


def test_basicg1_clear_pubkey_nonzero_derivation():
    x_only = b"\x77" * 32
    conn = FakeConnection(responses=[(list(x_only), 0x90, 0x00)])
    card = make_basic_g1_for_tests(conn)
    result = card.get_public_key_clear(derivation=2)
    assert bytes(result) == x_only


## BasicG0 is abstract (missing several methods), so we limit tests to BasicG1 here.


