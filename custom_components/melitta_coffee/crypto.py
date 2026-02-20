import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from .const import (
    AES_KEY, AES_ENCRYPTED_DATA, IV_INIT,
    RC4_KEY_PART_A, RC4_KEY_PART_B, SBOX,
)

_LOGGER = logging.getLogger(__name__)

_RC4_KEY_CACHE = None
_ALL_RC4_KEYS = None
_ACTIVE_KEY_INDEX = 0


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    _LOGGER.debug(
        "AES-CBC decrypt: key=%d bytes, iv=%d bytes, data=%d bytes, data_hex=%s",
        len(key), len(iv), len(data), data.hex(),
    )
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()

    try:
        unpadder = sym_padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(decrypted) + unpadder.finalize()
        _LOGGER.debug("PKCS7 unpad OK: %d -> %d bytes, result_hex=%s", len(decrypted), len(unpadded), unpadded.hex())
        return unpadded
    except ValueError:
        _LOGGER.debug("PKCS7 unpad failed, returning raw %d bytes, result_hex=%s", len(decrypted), decrypted.hex())
        return decrypted


def _derive_all_rc4_keys() -> list[tuple[str, bytes]]:
    global _ALL_RC4_KEYS
    if _ALL_RC4_KEYS is not None:
        return _ALL_RC4_KEYS

    key_sources = [
        ("compound_B+A", RC4_KEY_PART_B + RC4_KEY_PART_A),
        ("compound_A+B", RC4_KEY_PART_A + RC4_KEY_PART_B),
        ("AES_KEY", AES_KEY),
    ]

    results = []
    for name, aes_key in key_sources:
        if len(aes_key) != 32:
            _LOGGER.debug("RC4 KEY: skipping %s (len=%d, need 32)", name, len(aes_key))
            continue
        try:
            rc4_key = _aes_cbc_decrypt(aes_key, IV_INIT, AES_ENCRYPTED_DATA)
            results.append((name, rc4_key))
            _LOGGER.debug(
                "RC4 KEY [%s]: derived %d bytes, first4=%s",
                name, len(rc4_key), rc4_key[:4].hex() if len(rc4_key) >= 4 else "N/A",
            )
        except Exception as e:
            _LOGGER.warning("RC4 KEY [%s]: derivation FAILED: %s", name, e)

    _ALL_RC4_KEYS = results
    return results


def get_rc4_key() -> bytes:
    global _RC4_KEY_CACHE, _ACTIVE_KEY_INDEX
    if _RC4_KEY_CACHE is not None:
        return _RC4_KEY_CACHE

    all_keys = _derive_all_rc4_keys()
    if not all_keys:
        raise RuntimeError("No RC4 keys could be derived")

    idx = _ACTIVE_KEY_INDEX % len(all_keys)
    name, rc4_key = all_keys[idx]
    _RC4_KEY_CACHE = rc4_key
    _LOGGER.debug(
        "RC4 key active [%d/%d]: %s (first4=%s)",
        idx + 1, len(all_keys), name,
        rc4_key[:4].hex() if len(rc4_key) >= 4 else "N/A",
    )
    return rc4_key


def rotate_rc4_key() -> str | None:
    global _RC4_KEY_CACHE, _ACTIVE_KEY_INDEX
    all_keys = _derive_all_rc4_keys()
    if len(all_keys) <= 1:
        return None

    _ACTIVE_KEY_INDEX = (_ACTIVE_KEY_INDEX + 1) % len(all_keys)
    _RC4_KEY_CACHE = None
    name, _ = all_keys[_ACTIVE_KEY_INDEX]
    _LOGGER.info(
        "RC4 key rotated to [%d/%d]: %s",
        _ACTIVE_KEY_INDEX + 1, len(all_keys), name,
    )
    return name


def get_all_rc4_keys() -> list[tuple[str, bytes]]:
    return _derive_all_rc4_keys()


class RC4:
    def __init__(self, key: bytes):
        self._sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self._sbox[i] + key[i % len(key)]) % 256
            self._sbox[i], self._sbox[j] = self._sbox[j], self._sbox[i]
        self._i = 0
        self._j = 0

    def crypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        i = self._i
        j = self._j
        sbox = self._sbox
        for k in range(len(data)):
            i = (i + 1) % 256
            j = (j + sbox[i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
            out[k] = data[k] ^ sbox[(sbox[i] + sbox[j]) % 256]
        self._i = i
        self._j = j
        return bytes(out)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    _LOGGER.debug("RC4 crypt: key=%d bytes, data=%d bytes, in_hex=%s", len(key), len(data), data.hex())
    rc4 = RC4(key)
    result = rc4.crypt(data)
    _LOGGER.debug("RC4 crypt result: out_hex=%s", result.hex())
    return result


def sbox_hash(data: bytes, length: int) -> bytes:
    _LOGGER.debug("SBOX hash input: data=%s, length=%d", data[:length].hex(), length)
    b1 = SBOX[data[0] & 0xFF]
    for i in range(1, length):
        b1 = SBOX[(b1 ^ data[i]) & 0xFF]
    result1 = (b1 + 93) & 0xFF

    b2 = SBOX[(data[0] + 1) & 0xFF]
    for i in range(1, length):
        b2 = SBOX[(b2 ^ data[i]) & 0xFF]
    result2 = (b2 + 167) & 0xFF

    result = bytes([result1, result2])
    _LOGGER.debug("SBOX hash output: %s (b1_final=%d, b2_final=%d)", result.hex(), result1, result2)
    return result
