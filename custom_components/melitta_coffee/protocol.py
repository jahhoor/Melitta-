import logging
from .const import FRAME_START, FRAME_END, COMMAND_REGISTRY
from .crypto import rc4_crypt, get_rc4_key

_LOGGER = logging.getLogger(__name__)


def compute_checksum(length: int, data: bytes) -> int:
    total = 0
    for i in range(1, length):
        total = (total + data[i]) & 0xFF
    return (~total) & 0xFF


def build_frame(command: str, session_key: bytes | None, payload: bytes | None, encrypt: bool) -> bytes:
    cmd_bytes = command.encode("latin-1")
    data_len = len(cmd_bytes) + 1
    if session_key is not None:
        data_len += 2
    if payload is not None:
        data_len += len(payload)
    data_len += 2

    frame = bytearray(data_len)
    frame[0] = FRAME_START
    pos = 1
    for b in cmd_bytes:
        frame[pos] = b
        pos += 1

    if session_key is not None:
        frame[pos] = session_key[0]
        frame[pos + 1] = session_key[1]
        pos += 2

    if payload is not None:
        for b in payload:
            frame[pos] = b
            pos += 1

    chk = compute_checksum(pos, frame)
    frame[pos] = chk
    frame[pos + 1] = FRAME_END

    _LOGGER.warning(
        "build_frame: cmd=%r, session=%s, payload=%s, encrypt=%s, checksum=0x%02x, plaintext_hex=%s",
        command,
        session_key.hex() if session_key else "None",
        payload.hex() if payload else "None",
        encrypt,
        chk,
        bytes(frame).hex(),
    )

    if encrypt:
        apk_offset = len(cmd_bytes) + 1
        apk_count = pos - len(cmd_bytes)
        actual_start = apk_offset + 1
        actual_count = apk_count
        rc4_key = get_rc4_key()
        plaintext = bytes(frame[actual_start:actual_start + actual_count])
        encrypted = rc4_crypt(rc4_key, plaintext)
        for i in range(actual_count):
            frame[actual_start + i] = encrypted[i]
        _LOGGER.warning(
            "build_frame encrypted_hex=%s (encrypt_start=%d, encrypt_count=%d, plaintext_byte[%d]=0x%02x)",
            bytes(frame).hex(), actual_start, actual_count, apk_offset, frame[apk_offset],
        )

    return bytes(frame)


class EfComFrame:
    def __init__(self, command: str, payload: bytes, encrypted: bool):
        self.command = command
        self.payload = payload
        self.encrypted = encrypted

    def __repr__(self):
        return f"EfComFrame(cmd={self.command!r}, payload={self.payload.hex()}, enc={self.encrypted})"


class EfComParser:
    def __init__(self):
        self._buffer = bytearray(256)
        self._pos = 0
        self._expected_len = 0
        self._unknown_cmds_logged = set()

    def reset(self):
        self._pos = 0
        self._expected_len = 0

    def feed(self, data: bytes) -> list[EfComFrame]:
        frames = []
        for byte_val in data:
            frame = self._process_byte(byte_val)
            if frame is not None:
                frames.append(frame)
        return frames

    def _process_byte(self, b: int) -> EfComFrame | None:
        if self._pos == 0:
            if b == FRAME_START:
                self._buffer[0] = b
                self._pos = 1
                self._expected_len = 0
            return None

        if b == FRAME_START and self._pos > 0:
            _LOGGER.debug(
                "FRAME_START mid-parse at pos=%d, resyncing",
                self._pos,
            )
            self._buffer[0] = b
            self._pos = 1
            self._expected_len = 0
            return None

        if self._pos >= 256:
            _LOGGER.warning("Parser buffer overflow, resetting")
            self.reset()
            return None

        self._buffer[self._pos] = b
        self._pos += 1

        if self._expected_len == 0 and self._pos >= 3:
            self._expected_len = self._detect_frame_length()

        if self._expected_len > 0:
            if self._pos == self._expected_len:
                frame = self._try_parse_frame()
                self.reset()
                return frame
            elif self._pos > self._expected_len:
                self.reset()
                return None
            return None

        if self._pos > 4 and b == FRAME_END:
            frame = self._try_parse_frame()
            self.reset()
            return frame

        return None

    def _detect_frame_length(self) -> int:
        data = bytes(self._buffer[:self._pos])

        for cmd_str, (payload_len, _) in COMMAND_REGISTRY.items():
            cmd_bytes = cmd_str.encode("latin-1")
            cmd_len = len(cmd_bytes)

            if self._pos < 1 + cmd_len:
                continue

            if data[1:1 + cmd_len] == cmd_bytes:
                expected = 1 + cmd_len + payload_len + 2
                _LOGGER.debug("Detected frame cmd=%r, expected_len=%d", cmd_str, expected)
                return expected

        return 0

    def _try_parse_frame(self) -> EfComFrame | None:
        data = bytes(self._buffer[:self._pos])
        _LOGGER.debug("Parsing frame: %d bytes, raw_hex=%s", self._pos, data.hex())

        for cmd_str, (payload_len, is_encrypted) in COMMAND_REGISTRY.items():
            cmd_bytes = cmd_str.encode("latin-1")
            cmd_len = len(cmd_bytes)

            expected_len = 1 + cmd_len + payload_len + 2
            if self._pos != expected_len:
                continue

            if data[1:1 + cmd_len] != cmd_bytes:
                continue

            _LOGGER.debug(
                "Command match: cmd=%r, payload_len=%d, encrypted=%s",
                cmd_str, payload_len, is_encrypted,
            )

            if is_encrypted:
                frame = self._decrypt_frame(data, cmd_str, cmd_len, payload_len)
                if frame is not None:
                    return frame
                frame = self._try_plaintext(data, cmd_str, cmd_len, payload_len)
                if frame is not None:
                    _LOGGER.debug("Encrypted decode failed, plaintext fallback succeeded for cmd=%r", cmd_str)
                    return frame
            else:
                frame = self._try_plaintext(data, cmd_str, cmd_len, payload_len)
                if frame is not None:
                    return frame

        cmd_hex = data[1:3].hex() if self._pos >= 3 else data[1:2].hex()
        if cmd_hex not in self._unknown_cmds_logged:
            self._unknown_cmds_logged.add(cmd_hex)
            _LOGGER.debug(
                "Unknown command in %d-byte frame (cmd_bytes=%s), dropping (APK behavior)",
                self._pos, cmd_hex,
            )
        return None

    def _decrypt_frame(self, data: bytes, cmd_str: str, cmd_len: int, payload_len: int) -> EfComFrame | None:
        work = bytearray(data)
        rc4_key = get_rc4_key()

        decrypt_start = cmd_len + 2
        decrypt_count = payload_len + 1
        if decrypt_start + decrypt_count > len(work):
            _LOGGER.debug("Decrypt range exceeds frame length, skipping")
            return None

        encrypted_portion = bytes(work[decrypt_start:decrypt_start + decrypt_count])
        decrypted = rc4_crypt(rc4_key, encrypted_portion)
        for i in range(decrypt_count):
            work[decrypt_start + i] = decrypted[i]

        chk_pos = self._pos - 2
        expected_chk = compute_checksum(chk_pos, work)
        actual_chk = work[chk_pos]

        _LOGGER.debug(
            "Decrypt cmd=%r: checksum computed=0x%02x, in_frame=0x%02x, match=%s",
            cmd_str, expected_chk, actual_chk, expected_chk == actual_chk,
        )

        if expected_chk == actual_chk:
            payload_start = cmd_len + 1
            payload = bytes(work[payload_start:payload_start + payload_len])
            _LOGGER.info(
                "FRAME DECODED (encrypted): cmd=%r, payload=%s (%d bytes)",
                cmd_str, payload.hex(), len(payload),
            )
            return EfComFrame(cmd_str, payload, True)

        return None

    def _try_plaintext(self, data: bytes, cmd_str: str, cmd_len: int, payload_len: int) -> EfComFrame | None:
        work = bytearray(data)
        chk_pos = self._pos - 2
        expected_chk = compute_checksum(chk_pos, work)

        if expected_chk == work[chk_pos]:
            payload_start = cmd_len + 1
            payload = bytes(work[payload_start:payload_start + payload_len])
            _LOGGER.info(
                "FRAME DECODED (plaintext): cmd=%r, payload=%s (%d bytes)",
                cmd_str, payload.hex(), len(payload),
            )
            return EfComFrame(cmd_str, payload, False)

        return None
