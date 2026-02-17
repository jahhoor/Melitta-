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


def get_rc4_key() -> bytes:
    global _RC4_KEY_CACHE
    if _RC4_KEY_CACHE is not None:
        return _RC4_KEY_CACHE

    compound_key = RC4_KEY_PART_B + RC4_KEY_PART_A
    compound_matches_aes = (compound_key == AES_KEY)
    _LOGGER.warning(
        "=== RC4 KEY DERIVATION ===\n"
        "  AES key source: compound(R3.g.f2460b+f2459a) = %d bytes, first4=%s\n"
        "  AES_KEY constant (defined but unused): %d bytes, first4=%s\n"
        "  compound == AES_KEY: %s\n"
        "  IV: %d bytes, Encrypted data: %d bytes\n"
        "  NOTE: If auth fails, try swapping to AES_KEY for decryption.",
        len(compound_key), compound_key[:4].hex(),
        len(AES_KEY), AES_KEY[:4].hex(),
        compound_matches_aes,
        len(IV_INIT), len(AES_ENCRYPTED_DATA),
    )
    _LOGGER.debug(
        "RC4 KEY DERIVATION (full keys): compound=%s, AES_KEY=%s, IV=%s, data=%s",
        compound_key.hex(), AES_KEY.hex(), IV_INIT.hex(), AES_ENCRYPTED_DATA.hex(),
    )

    rc4_key = _aes_cbc_decrypt(compound_key, IV_INIT, AES_ENCRYPTED_DATA)

    _RC4_KEY_CACHE = rc4_key
    _LOGGER.warning(
        "=== RC4 KEY DERIVED ===\n"
        "  RC4 key length: %d bytes, first4=%s",
        len(rc4_key), rc4_key[:4].hex() if len(rc4_key) >= 4 else "N/A",
    )
    _LOGGER.debug("RC4 key hex [SENSITIVE]: %s", rc4_key.hex())
    return rc4_key


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
