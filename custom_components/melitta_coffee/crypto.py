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
_RC4_KEY_ALT_CACHE = None


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
    _LOGGER.debug(
        "Deriving PRIMARY RC4 key: compound_key=%d bytes (%s), IV=%s, encrypted_data=%d bytes",
        len(compound_key), compound_key.hex(), IV_INIT.hex(), len(AES_ENCRYPTED_DATA),
    )

    rc4_key = _aes_cbc_decrypt(compound_key, IV_INIT, AES_ENCRYPTED_DATA)

    _RC4_KEY_CACHE = rc4_key
    _LOGGER.info("RC4 key derived (primary): %d bytes", len(rc4_key))
    _LOGGER.debug("RC4 primary key hex [SENSITIVE]: %s", rc4_key.hex())
    return rc4_key


def get_rc4_key_alt() -> bytes:
    global _RC4_KEY_ALT_CACHE
    if _RC4_KEY_ALT_CACHE is not None:
        return _RC4_KEY_ALT_CACHE

    compound_key = RC4_KEY_PART_B + RC4_KEY_PART_A

    _LOGGER.debug(
        "Deriving ALT RC4 key: AES_KEY=%d bytes, compound_key=%d bytes",
        len(AES_KEY), len(compound_key),
    )

    try:
        _LOGGER.debug("Alt key step 1: AES-CBC decrypt with AES_KEY")
        intermediate = _aes_cbc_decrypt(AES_KEY, IV_INIT, AES_ENCRYPTED_DATA)
        _LOGGER.debug("Alt key step 1 result: %d bytes, hex=%s", len(intermediate), intermediate.hex())

        if len(intermediate) % 16 != 0:
            _LOGGER.warning(
                "Alt key step 1 produced %d bytes (not block-aligned), using raw 48-byte output",
                len(intermediate),
            )
            cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV_INIT), backend=default_backend())
            decryptor = cipher.decryptor()
            intermediate = decryptor.update(AES_ENCRYPTED_DATA) + decryptor.finalize()

        _LOGGER.debug("Alt key step 2: AES-CBC decrypt intermediate with compound_key")
        rc4_key = _aes_cbc_decrypt(compound_key, IV_INIT, intermediate)
    except Exception as err:
        _LOGGER.error("Alt RC4 key derivation failed: %s, falling back to primary", err)
        return get_rc4_key()

    _RC4_KEY_ALT_CACHE = rc4_key
    _LOGGER.info("RC4 key derived (alt): %d bytes", len(rc4_key))
    _LOGGER.debug("RC4 alt key hex [SENSITIVE]: %s", rc4_key.hex())
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
