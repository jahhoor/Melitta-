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

    _LOGGER.debug(
        "build_frame: cmd=%r, session=%s, payload=%s, encrypt=%s, checksum=0x%02x, plaintext_frame=%s",
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
        _LOGGER.debug(
            "build_frame encrypt (APK off-by-one): apk_offset=%d, apk_count=%d, "
            "actual_start=%d, actual_count=%d, plaintext_byte_at_%d=0x%02x",
            apk_offset, apk_count, actual_start, actual_count,
            apk_offset, frame[apk_offset],
        )
        rc4_key = get_rc4_key()
        plaintext = bytes(frame[actual_start:actual_start + actual_count])
        encrypted = rc4_crypt(rc4_key, plaintext)
        for i in range(actual_count):
            frame[actual_start + i] = encrypted[i]
        _LOGGER.debug("build_frame final (encrypted): %s", bytes(frame).hex())

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
                "FRAME_START (0x53) received mid-parse at pos=%d, resyncing (discarding %d buffered bytes)",
                self._pos, self._pos,
            )
            self._buffer[0] = b
            self._pos = 1
            self._expected_len = 0
            return None

        if self._pos >= 256:
            _LOGGER.warning("Parser buffer overflow (256 bytes), resetting")
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

            _LOGGER.debug("Trying COMMAND_REGISTRY match: cmd=%r, payload_len=%d, is_encrypted=%s", cmd_str, payload_len, is_encrypted)

            if is_encrypted:
                frame = self._try_decode(data, cmd_str, cmd_len, payload_len, try_encrypted=True)
                if frame is not None:
                    return frame
                _LOGGER.debug("Encrypted decode failed for cmd=%r, trying plaintext", cmd_str)
                frame = self._try_decode(data, cmd_str, cmd_len, payload_len, try_encrypted=False)
                if frame is not None:
                    return frame
            else:
                frame = self._try_decode(data, cmd_str, cmd_len, payload_len, try_encrypted=False)
                if frame is not None:
                    return frame

        _LOGGER.warning("Failed to parse frame: %s", data.hex())
        return None

    def _try_decode(self, data: bytes, cmd_str: str, cmd_len: int, payload_len: int, try_encrypted: bool) -> EfComFrame | None:
        if not try_encrypted:
            work = bytearray(data)
            chk_pos = self._pos - 2
            expected_chk = compute_checksum(chk_pos, work)
            if expected_chk == work[chk_pos]:
                payload_start = cmd_len + 1
                payload = bytes(work[payload_start:payload_start + payload_len])
                _LOGGER.warning("FRAME DECODED: cmd=%r, key=plaintext, payload=%s (%d bytes)", cmd_str, payload.hex(), len(payload))
                return EfComFrame(cmd_str, payload, False)
            return None

        rc4_key = get_rc4_key()

        for mode in ("apk_offbyone", "standard"):
            work = bytearray(data)

            if mode == "apk_offbyone":
                apk_offset = cmd_len + 1
                apk_count = payload_len + 1
                actual_start = apk_offset + 1
                actual_count = apk_count
                if actual_start + actual_count > len(work):
                    _LOGGER.debug("try_decode %s: range exceeds frame, skipping", mode)
                    continue
                encrypted_portion = bytes(work[actual_start:actual_start + actual_count])
                decrypted = rc4_crypt(rc4_key, encrypted_portion)
                for i in range(actual_count):
                    work[actual_start + i] = decrypted[i]
            else:
                enc_start = cmd_len + 1
                enc_len = payload_len + 1
                encrypted_portion = bytes(work[enc_start:enc_start + enc_len])
                _LOGGER.debug(
                    "try_decode cmd=%r standard: enc_start=%d, enc_len=%d",
                    cmd_str, enc_start, enc_len,
                )
                decrypted = rc4_crypt(rc4_key, encrypted_portion)
                for i in range(enc_len):
                    work[enc_start + i] = decrypted[i]

            chk_pos = self._pos - 2
            expected_chk = compute_checksum(chk_pos, work)
            _LOGGER.debug(
                "try_decode cmd=%r %s: checksum computed=0x%02x, in_frame=0x%02x, match=%s",
                cmd_str, mode, expected_chk, work[chk_pos], expected_chk == work[chk_pos],
            )
            if expected_chk == work[chk_pos]:
                payload_start = cmd_len + 1
                payload = bytes(work[payload_start:payload_start + payload_len])
                _LOGGER.warning("FRAME DECODED: cmd=%r, mode=%s, payload=%s (%d bytes)", cmd_str, mode, payload.hex(), len(payload))
                return EfComFrame(cmd_str, payload, True)

        return None
