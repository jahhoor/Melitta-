import asyncio
import logging
import os
import struct
from datetime import datetime
from typing import Any, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError

from .const import (
    MELITTA_SERVICE_UUID,
    MELITTA_READ_CHAR_UUID,
    MELITTA_WRITE_CHAR_UUID,
    FRAME_START,
    FRAME_END,
    FRAME_MAX_SIZE,
    BLE_MTU_SIZE,
    CMD_AUTH,
    CMD_KEEPALIVE,
    CMD_BREW,
    CMD_WRITE_VALUE,
    CMD_READ_VALUE,
    CMD_SET_PROCESS,
    CMD_STATUS,
    CMD_RECIPE_CONFIRM,
    CMD_ALPHA_VALUE,
    CMD_VERSION,
    CMD_ACK,
    CMD_NACK,
    KEEPALIVE_INTERVAL,
    SBOX,
    PROCESS_MAP,
    SUBPROCESS_MAP,
    MANIPULATION_MAP,
    BEVERAGE_MAP,
    BEVERAGE_NAMES,
    BEVERAGE_TO_DIRECT_KEY,
    DIRECT_KEY_MAP,
    STRENGTH_MAP,
    STRENGTH_NAMES,
    DEFAULT_RECIPES,
    CONNECT_TIMEOUT,
    Process,
    InfoFlag,
    RecipeProcess,
    Shots,
    Blend,
    Intensity,
    Aroma,
    Temperature,
)

_LOGGER = logging.getLogger(__name__)

MELITTA_KEYWORDS = ["melitta", "caffeo", "barista"]
RECONNECT_INTERVALS = [5, 10, 30, 60, 120]


def _sbox_hash(data: bytes) -> bytes:
    sbox = SBOX
    b1 = sbox[(data[0] + 256) % 256]
    for i in range(1, len(data)):
        b1 = sbox[((b1 ^ data[i]) + 256) % 256]
    h1 = (b1 + 93) & 0xFF

    b2 = sbox[(data[0] + 257) % 256]
    for i in range(1, len(data)):
        b2 = sbox[((b2 ^ data[i]) + 256) % 256]
    h2 = (b2 + 167) & 0xFF

    return bytes([h1, h2])


def _compute_checksum(frame_bytes: bytes, length: int) -> int:
    total = 0
    for i in range(1, length):
        total = (total + frame_bytes[i]) & 0xFF
    return (~total) & 0xFF


def _build_frame(cmd_id: str, payload: bytes = b"", require_auth: bool = False) -> bytes:
    cmd_bytes = cmd_id.encode("latin-1")
    frame = bytearray()
    frame.append(FRAME_START)
    frame.extend(cmd_bytes)
    if payload:
        frame.extend(payload)
    checksum = _compute_checksum(frame, len(frame))
    frame.append(checksum)
    frame.append(FRAME_END)
    return bytes(frame)


class EfComParser:

    def __init__(self, on_frame: Callable):
        self._buffer = bytearray(FRAME_MAX_SIZE)
        self._pos = 0
        self._on_frame = on_frame
        self._known_commands: dict[str, int] = {}

    def register_command(self, cmd_id: str, payload_length: int) -> None:
        self._known_commands[cmd_id] = payload_length

    def feed(self, byte_val: int) -> None:
        if self._pos <= 0:
            if byte_val == FRAME_START:
                self._buffer[0] = byte_val
                self._pos = 1
            return

        if self._pos >= FRAME_MAX_SIZE:
            self._reset()
            return

        self._buffer[self._pos] = byte_val
        self._pos += 1

        if byte_val != FRAME_END or self._pos < 4:
            return

        try:
            cmd2 = self._buffer[1:3].decode("latin-1")
        except Exception:
            cmd2 = None

        try:
            cmd1 = self._buffer[1:2].decode("latin-1")
        except Exception:
            cmd1 = None

        matched = False
        for cmd_id, expected_len in self._known_commands.items():
            if cmd_id == cmd2 or cmd_id == cmd1:
                total = len(cmd_id) + 1 + expected_len + 2
                if total == self._pos:
                    payload_start = len(cmd_id) + 1
                    checksum_pos = self._pos - 2
                    expected_checksum = _compute_checksum(self._buffer, checksum_pos)
                    if self._buffer[checksum_pos] == expected_checksum:
                        payload = bytes(self._buffer[payload_start:payload_start + expected_len])
                        self._on_frame(cmd_id, payload)
                    else:
                        _LOGGER.debug(
                            "Checksum mismatch for %s: expected 0x%02x got 0x%02x",
                            cmd_id, expected_checksum, self._buffer[checksum_pos],
                        )
                    self._reset()
                    return
                if total > self._pos:
                    matched = True

        if not matched:
            self._resync()

    def _reset(self) -> None:
        self._pos = 0

    def _resync(self) -> None:
        for i in range(1, self._pos):
            if self._buffer[i] == FRAME_START:
                remaining = self._pos - i
                self._buffer[0:remaining] = self._buffer[i:self._pos]
                self._pos = remaining
                return
        self._reset()


class MelittaDevice:

    def __init__(self, address: str, name: str = "Melitta", hass=None) -> None:
        self._address = address
        self._name = name
        self._hass = hass
        self._client: BleakClient | None = None
        self._is_connected = False
        self._has_ever_connected = False
        self._authenticated = False
        self._session_key: bytes | None = None
        self._auth_challenge: bytes | None = None
        self._auth_event: asyncio.Event | None = None
        self._ack_event: asyncio.Event | None = None
        self._last_ack: bool = False

        self._status = "offline"
        self._status_raw: str | None = None
        self._process: int = 0
        self._subprocess: int = 0
        self._info_flags: int = 0
        self._manipulation: int = 0
        self._progress: int = 0
        self._water_level = "unknown"
        self._bean_level = "unknown"
        self._error: str | None = None
        self._is_brewing = False
        self._current_beverage: str | None = None
        self._strength = "medium"
        self._cups = 1
        self._temperature: int | None = None
        self._total_brews = 0
        self._version: str | None = None

        self._callbacks: list[Callable] = []
        self._lock = asyncio.Lock()
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 5
        self._reconnect_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._shutting_down = False
        self._last_connect_time: str | None = None
        self._last_error_message: str | None = None
        self._services_discovered = False
        self._discovered_services_info: str = "Nog niet verbonden"
        self._raw_notifications: list[dict[str, str]] = []
        self._last_raw_status_hex: str | None = None
        self._last_write_result: str | None = None
        self._read_char: str | None = None
        self._write_char: str | None = None

        self._rx_buffer = bytearray()
        self._parser = EfComParser(self._on_efcom_frame)
        self._register_known_commands()

    def _register_known_commands(self) -> None:
        self._parser.register_command(CMD_AUTH, 8)
        self._parser.register_command(CMD_KEEPALIVE, 0)
        self._parser.register_command(CMD_STATUS, 8)
        self._parser.register_command(CMD_ACK, 0)
        self._parser.register_command(CMD_NACK, 0)
        self._parser.register_command(CMD_VERSION, 20)
        self._parser.register_command(CMD_ALPHA_VALUE, 32)
        self._parser.register_command(CMD_RECIPE_CONFIRM, 20)

    @property
    def address(self) -> str:
        return self._address

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_connected(self) -> bool:
        return self._is_connected and self._authenticated

    @property
    def is_ble_connected(self) -> bool:
        return self._is_connected

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def status(self) -> str:
        return self._status

    @property
    def status_raw(self) -> str | None:
        return self._status_raw

    @property
    def process_state(self) -> str:
        return PROCESS_MAP.get(self._process, f"unknown_{self._process}")

    @property
    def subprocess_state(self) -> str:
        return SUBPROCESS_MAP.get(self._subprocess, "none")

    @property
    def progress(self) -> int:
        return self._progress

    @property
    def water_level(self) -> str:
        return self._water_level

    @property
    def bean_level(self) -> str:
        return self._bean_level

    @property
    def error(self) -> str | None:
        return self._error

    @property
    def is_brewing(self) -> bool:
        return self._is_brewing

    @property
    def current_beverage(self) -> str | None:
        return self._current_beverage

    @property
    def strength(self) -> str:
        return self._strength

    @property
    def cups(self) -> int:
        return self._cups

    @property
    def temperature(self) -> int | None:
        return self._temperature

    @property
    def total_brews(self) -> int:
        return self._total_brews

    @property
    def version(self) -> str | None:
        return self._version

    @property
    def last_connect_time(self) -> str | None:
        return self._last_connect_time

    @property
    def last_error_message(self) -> str | None:
        return self._last_error_message

    @property
    def services_discovered(self) -> bool:
        return self._services_discovered

    @property
    def discovered_services_info(self) -> str:
        return self._discovered_services_info

    @property
    def raw_notifications(self) -> list[dict[str, str]]:
        return self._raw_notifications

    @property
    def last_raw_status_hex(self) -> str | None:
        return self._last_raw_status_hex

    @property
    def last_write_result(self) -> str | None:
        return self._last_write_result

    @property
    def needs_beans_1(self) -> bool:
        return bool(self._info_flags & (1 << InfoFlag.FILL_BEANS_1))

    @property
    def needs_beans_2(self) -> bool:
        return bool(self._info_flags & (1 << InfoFlag.FILL_BEANS_2))

    @property
    def needs_cleaning(self) -> bool:
        return bool(self._info_flags & (1 << InfoFlag.EASY_CLEAN))

    @property
    def powder_filled(self) -> bool:
        return bool(self._info_flags & (1 << InfoFlag.POWDER_FILLED))

    def set_strength(self, strength: str) -> None:
        if strength in STRENGTH_MAP:
            self._strength = strength
            self._notify_callbacks()

    def set_cups(self, cups: int) -> None:
        if 1 <= cups <= 12:
            self._cups = cups
            self._notify_callbacks()

    def register_callback(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable) -> None:
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _notify_callbacks(self) -> None:
        for callback in self._callbacks:
            try:
                callback()
            except Exception:
                _LOGGER.exception("Error calling callback")

    async def connect(self) -> bool:
        async with self._lock:
            if self._is_connected and self._client:
                try:
                    if self._client.is_connected:
                        if self._authenticated:
                            return True
                except Exception:
                    pass
                self._is_connected = False
                self._authenticated = False
                self._client = None

            try:
                _LOGGER.debug("Connecting to Melitta at %s", self._address)
                self._client = BleakClient(
                    self._address,
                    timeout=CONNECT_TIMEOUT,
                    disconnected_callback=self._on_disconnect,
                )
                await self._client.connect()
                self._is_connected = True
                self._has_ever_connected = True
                self._reconnect_attempts = 0
                self._last_connect_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._last_error_message = None

                await self._discover_services()
                await self._subscribe_notifications()
                await self._authenticate()

                if self._authenticated:
                    self._status = "ready"
                    self._start_keepalive()
                    _LOGGER.info("Connected and authenticated with Melitta at %s", self._address)
                    await self._request_initial_status()
                else:
                    self._status = "auth_failed"
                    _LOGGER.warning("Connected but authentication failed for %s", self._address)

                self._notify_callbacks()
                return self._authenticated

            except (BleakError, asyncio.TimeoutError, OSError) as err:
                error_msg = str(err)
                _LOGGER.warning("Failed to connect to Melitta at %s: %s", self._address, error_msg)
                self._is_connected = False
                self._authenticated = False
                self._client = None
                self._last_error_message = error_msg
                if not self._has_ever_connected:
                    self._status = "offline"
                self._notify_callbacks()
                return False

    async def disconnect(self) -> None:
        self._shutting_down = True
        self._stop_keepalive()

        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

        async with self._lock:
            if self._client:
                try:
                    if self._read_char and self._client.is_connected:
                        await self._client.stop_notify(self._read_char)
                        _LOGGER.debug("Unsubscribed from notifications on %s", self._read_char)
                except (BleakError, OSError) as err:
                    _LOGGER.debug("Failed to unsubscribe notifications: %s", err)

                try:
                    if self._client.is_connected:
                        await self._client.disconnect()
                        _LOGGER.info("Disconnected BLE client from %s", self._address)
                except (BleakError, OSError) as err:
                    _LOGGER.debug("BLE disconnect error: %s", err)

                self._client = None
            self._is_connected = False
            self._authenticated = False
            self._session_key = None
            self._read_char = None
            self._write_char = None
            self._status = "offline"
            self._notify_callbacks()
            _LOGGER.info("Melitta device %s fully cleaned up", self._address)

    def _on_disconnect(self, client: BleakClient) -> None:
        _LOGGER.info("Disconnected from Melitta at %s", self._address)
        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        self._client = None
        self._status = "offline"
        self._stop_keepalive()
        self._notify_callbacks()

        if not self._shutting_down:
            self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        if self._reconnect_task and not self._reconnect_task.done():
            return

        if self._reconnect_attempts >= self._max_reconnect_attempts:
            _LOGGER.info(
                "Max reconnect attempts (%d) reached for %s",
                self._max_reconnect_attempts,
                self._address,
            )
            self._reconnect_attempts = 0
            return

        delay = RECONNECT_INTERVALS[
            min(self._reconnect_attempts, len(RECONNECT_INTERVALS) - 1)
        ]
        self._reconnect_attempts += 1
        _LOGGER.debug(
            "Scheduling reconnect attempt %d in %ds for %s",
            self._reconnect_attempts,
            delay,
            self._address,
        )

        loop = asyncio.get_event_loop()
        self._reconnect_task = loop.create_task(self._reconnect_after_delay(delay))

    async def _reconnect_after_delay(self, delay: float) -> None:
        try:
            await asyncio.sleep(delay)
            if not self._shutting_down and not self._is_connected:
                connected = await self.connect()
                if not connected and not self._shutting_down:
                    self._schedule_reconnect()
        except asyncio.CancelledError:
            pass
        except Exception as err:
            _LOGGER.debug("Reconnect failed for %s: %s", self._address, err)
            if not self._shutting_down:
                self._schedule_reconnect()

    async def _request_initial_status(self) -> None:
        try:
            frame = _build_frame(CMD_STATUS, b"")
            await self._send_raw(frame)
            _LOGGER.debug("Initial status request sent")
        except Exception as err:
            _LOGGER.debug("Initial status request failed: %s", err)

    async def _ensure_connected(self) -> bool:
        if self._is_connected and self._authenticated and self._client:
            try:
                if self._client.is_connected:
                    return True
            except Exception:
                pass
            self._is_connected = False
            self._authenticated = False
            self._client = None

        return await self.connect()

    async def _discover_services(self) -> None:
        if not self._client or not self._is_connected:
            return

        try:
            services = self._client.services
            info_lines = []
            self._read_char = None
            self._write_char = None

            for service in services:
                svc_desc = service.description or "Onbekend"
                info_lines.append(f"Service: {service.uuid} ({svc_desc})")

                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    info_lines.append(f"  Kenmerk: {char.uuid} [{props}]")

                    uuid_lower = char.uuid.lower()
                    if uuid_lower == MELITTA_READ_CHAR_UUID.lower():
                        self._read_char = char.uuid
                    elif uuid_lower == MELITTA_WRITE_CHAR_UUID.lower():
                        self._write_char = char.uuid

            info_lines.append(f"Leesbare kenmerk: {self._read_char or 'Niet gevonden'}")
            info_lines.append(f"Schrijfbare kenmerk: {self._write_char or 'Niet gevonden'}")
            self._discovered_services_info = "\n".join(info_lines)
            self._services_discovered = bool(self._read_char and self._write_char)

            if not self._services_discovered:
                _LOGGER.warning(
                    "Required characteristics not found on %s (read=%s, write=%s)",
                    self._address, self._read_char, self._write_char,
                )
                self._last_error_message = "Melitta BLE kenmerken niet gevonden"

        except (BleakError, OSError) as err:
            _LOGGER.error("Failed to discover services: %s", err)
            self._last_error_message = f"Service discovery mislukt: {err}"

    async def _subscribe_notifications(self) -> None:
        if not self._client or not self._read_char:
            return

        try:
            await self._client.start_notify(
                self._read_char, self._handle_notification
            )
            _LOGGER.info("Subscribed to notifications on %s", self._read_char)
        except (BleakError, OSError) as err:
            _LOGGER.warning("Failed to subscribe to %s: %s", self._read_char, err)

    def _handle_notification(self, sender: Any, data: bytearray) -> None:
        hex_str = data.hex()
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        _LOGGER.debug("RX [%s]: %s", timestamp, hex_str)

        notification_entry = {
            "time": timestamp,
            "sender": str(sender),
            "hex": hex_str,
            "length": str(len(data)),
        }
        self._raw_notifications.append(notification_entry)
        if len(self._raw_notifications) > 50:
            self._raw_notifications = self._raw_notifications[-50:]

        for byte_val in data:
            self._parser.feed(byte_val)

    def _on_efcom_frame(self, cmd_id: str, payload: bytes) -> None:
        _LOGGER.debug("EfCom frame: cmd=%s payload=%s", cmd_id, payload.hex())

        if cmd_id == CMD_AUTH:
            self._handle_auth_response(payload)
        elif cmd_id == CMD_STATUS:
            self._handle_status(payload)
        elif cmd_id == CMD_ACK:
            self._handle_ack(True)
        elif cmd_id == CMD_NACK:
            self._handle_ack(False)
        elif cmd_id == CMD_VERSION:
            self._handle_version(payload)
        elif cmd_id == CMD_ALPHA_VALUE:
            self._handle_alpha_value(payload)
        elif cmd_id == CMD_RECIPE_CONFIRM:
            _LOGGER.debug("Recipe confirmed: %s", payload.hex())

    async def _authenticate(self) -> None:
        if not self._services_discovered:
            _LOGGER.warning("Cannot authenticate: services not discovered")
            self._authenticated = False
            return

        self._auth_event = asyncio.Event()
        self._auth_challenge = os.urandom(4)

        challenge_hash = _sbox_hash(self._auth_challenge)
        auth_payload = self._auth_challenge + challenge_hash

        frame = _build_frame(CMD_AUTH, auth_payload, require_auth=True)

        try:
            await self._send_raw(frame)
            try:
                await asyncio.wait_for(self._auth_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                _LOGGER.warning("Authentication timeout for %s", self._address)
                self._authenticated = False
                self._last_error_message = "Authenticatie timeout"
        except (BleakError, OSError) as err:
            _LOGGER.warning("Auth send failed: %s", err)
            self._authenticated = False
            self._last_error_message = f"Authenticatie mislukt: {err}"

    def _handle_auth_response(self, payload: bytes) -> None:
        if len(payload) != 8:
            _LOGGER.warning("Invalid auth response length: %d", len(payload))
            self._authenticated = False
            if self._auth_event:
                self._auth_event.set()
            return

        echo = payload[0:4]
        session_key = payload[4:6]
        response_hash = payload[6:8]

        if echo != self._auth_challenge:
            _LOGGER.warning("Auth challenge mismatch")
            self._authenticated = False
            if self._auth_event:
                self._auth_event.set()
            return

        verify_data = payload[0:6]
        expected_hash = _sbox_hash(verify_data)
        if response_hash != expected_hash:
            _LOGGER.warning("Auth hash verification failed")
            self._authenticated = False
            if self._auth_event:
                self._auth_event.set()
            return

        self._session_key = session_key
        self._authenticated = True
        _LOGGER.info("Authentication successful, session key: %s", session_key.hex())

        if self._auth_event:
            self._auth_event.set()

    def _handle_status(self, payload: bytes) -> None:
        if len(payload) < 8:
            return

        self._last_raw_status_hex = payload.hex()

        process = struct.unpack(">H", payload[0:2])[0]
        subprocess = struct.unpack(">H", payload[2:4])[0]
        info_flags = payload[4]
        manipulation = payload[5]
        progress = struct.unpack(">H", payload[6:8])[0]

        self._process = process
        self._subprocess = subprocess
        self._info_flags = info_flags
        self._manipulation = manipulation
        self._progress = progress

        old_status = self._status
        self._status = PROCESS_MAP.get(process, f"unknown_{process}")

        if manipulation != 0:
            manip_str = MANIPULATION_MAP.get(manipulation)
            if manip_str:
                self._error = manip_str
                if manipulation == 4:
                    self._water_level = "empty"
        else:
            self._error = None

        if info_flags & (1 << InfoFlag.FILL_BEANS_1):
            self._bean_level = "empty"
        elif info_flags & (1 << InfoFlag.FILL_BEANS_2):
            self._bean_level = "low"
        else:
            if self._bean_level in ("empty", "low"):
                self._bean_level = "ok"

        if manipulation != 4:
            if self._water_level == "empty":
                self._water_level = "ok"

        was_brewing = self._is_brewing
        self._is_brewing = (process == Process.PRODUCT)

        if was_brewing and not self._is_brewing and process == Process.READY:
            self._total_brews += 1
            self._current_beverage = None

        self._status_raw = (
            f"process={process} subprocess={subprocess} "
            f"info=0x{info_flags:02x} manip={manipulation} progress={progress}%"
        )

        _LOGGER.debug(
            "Status: %s subprocess=%s progress=%d%% manip=%s info=0x%02x",
            self._status, SUBPROCESS_MAP.get(subprocess, "?"),
            progress, MANIPULATION_MAP.get(manipulation, "?"), info_flags,
        )

        self._notify_callbacks()

    def _handle_ack(self, success: bool) -> None:
        self._last_ack = success
        if self._ack_event:
            self._ack_event.set()

    def _handle_version(self, payload: bytes) -> None:
        try:
            self._version = payload.decode("utf-8").rstrip("\x00")
            _LOGGER.info("Machine version: %s", self._version)
        except Exception:
            self._version = payload.hex()

    def _handle_alpha_value(self, payload: bytes) -> None:
        if len(payload) >= 2:
            param_id = struct.unpack(">H", payload[0:2])[0]
            try:
                value = payload[2:].decode("utf-8").rstrip("\x00")
            except Exception:
                value = payload[2:].hex()
            _LOGGER.debug("Alpha value: id=%d value=%s", param_id, value)

    def _start_keepalive(self) -> None:
        self._stop_keepalive()
        loop = asyncio.get_event_loop()
        self._keepalive_task = loop.create_task(self._keepalive_loop())

    def _stop_keepalive(self) -> None:
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            self._keepalive_task = None

    async def _keepalive_loop(self) -> None:
        try:
            while self._is_connected and self._authenticated:
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                if self._is_connected and self._authenticated:
                    try:
                        frame = _build_frame(CMD_KEEPALIVE)
                        await self._send_raw(frame)
                        _LOGGER.debug("Keepalive sent")
                    except Exception as err:
                        _LOGGER.warning("Keepalive failed: %s", err)
                        break
        except asyncio.CancelledError:
            pass

    async def _send_raw(self, data: bytes) -> None:
        if not self._client or not self._write_char:
            raise BleakError("Not connected")

        for i in range(0, len(data), BLE_MTU_SIZE):
            chunk = data[i:i + BLE_MTU_SIZE]
            await self._client.write_gatt_char(self._write_char, chunk)

    async def _send_command(self, cmd_id: str, payload: bytes = b"") -> bool:
        if not await self._ensure_connected():
            self._last_write_result = "Niet verbonden"
            return False

        frame = _build_frame(cmd_id, payload)
        self._ack_event = asyncio.Event()

        try:
            await self._send_raw(frame)
            hex_str = frame.hex()
            self._last_write_result = f"Sent: {cmd_id} ({hex_str})"
            _LOGGER.debug("Sent command %s: %s", cmd_id, hex_str)

            try:
                await asyncio.wait_for(self._ack_event.wait(), timeout=3.0)
                if self._last_ack:
                    self._last_write_result = f"OK: {cmd_id}"
                    return True
                else:
                    self._last_write_result = f"NACK: {cmd_id}"
                    return False
            except asyncio.TimeoutError:
                self._last_write_result = f"Timeout: {cmd_id}"
                return True

        except (BleakError, OSError) as err:
            self._last_write_result = f"Error: {err}"
            _LOGGER.error("Failed to send command %s: %s", cmd_id, err)
            self._last_error_message = f"Commando mislukt: {err}"
            self._is_connected = False
            self._authenticated = False
            self._client = None
            self._stop_keepalive()
            self._notify_callbacks()
            self._schedule_reconnect()
            return False

    async def brew(
        self,
        beverage: str = "espresso",
        strength: str = "medium",
        cups: int = 1,
    ) -> bool:
        bev_type = BEVERAGE_MAP.get(beverage, 0)
        intensity = STRENGTH_MAP.get(strength, Intensity.MEDIUM)

        recipe = DEFAULT_RECIPES.get(beverage, DEFAULT_RECIPES["espresso"])
        process_type = recipe["process"]
        shots = recipe["shots"]
        portion = recipe["portion"]

        direct_key_name = BEVERAGE_TO_DIRECT_KEY.get(beverage)
        direct_key = DIRECT_KEY_MAP.get(direct_key_name, 7) if direct_key_name else 7

        recipe_id = 200 + bev_type

        component1 = bytes([
            process_type,
            shots,
            Blend.BLEND_1,
            intensity,
            Aroma.STANDARD,
            Temperature.NORMAL,
            portion & 0xFF,
            0,
        ])

        if beverage in ("cappuccino", "caffe_latte", "cafe_au_lait", "flat_white",
                        "latte_macchiato", "latte_macchiato_extra", "latte_macchiato_triple",
                        "espresso_macchiato"):
            component2 = bytes([
                RecipeProcess.STEAM,
                Shots.NONE,
                Blend.BARISTA_T,
                Intensity.MEDIUM,
                Aroma.STANDARD,
                Temperature.NORMAL,
                100,
                0,
            ])
        elif beverage == "hot_water":
            component2 = bytes([0] * 8)
        elif beverage in ("milk", "milk_froth"):
            component2 = bytes([0] * 8)
        else:
            component2 = bytes([0] * 8)

        payload = bytearray(66)
        struct.pack_into(">H", payload, 0, recipe_id)
        payload[2] = bev_type
        payload[3] = direct_key
        payload[4:12] = component1
        payload[12:20] = component2

        self._current_beverage = beverage
        self._strength = strength
        self._cups = cups

        success = await self._send_command(CMD_BREW, bytes(payload))
        if success:
            self._is_brewing = True
            self._notify_callbacks()
        return success

    async def stop(self) -> bool:
        success = await self._send_command(CMD_SET_PROCESS, struct.pack(">H", Process.READY))
        if success:
            self._is_brewing = False
            self._current_beverage = None
            self._notify_callbacks()
        return success

    async def clean(self) -> bool:
        success = await self._send_command(CMD_SET_PROCESS, struct.pack(">H", Process.CLEANING))
        if success:
            self._status = "cleaning"
            self._notify_callbacks()
        return success

    async def easy_clean(self) -> bool:
        success = await self._send_command(CMD_SET_PROCESS, struct.pack(">H", Process.EASY_CLEAN))
        if success:
            self._status = "easy_clean"
            self._notify_callbacks()
        return success

    async def intensive_clean(self) -> bool:
        success = await self._send_command(CMD_SET_PROCESS, struct.pack(">H", Process.INTENSIVE_CLEAN))
        if success:
            self._status = "intensive_clean"
            self._notify_callbacks()
        return success

    async def rinse(self) -> bool:
        return await self.easy_clean()

    async def descale(self) -> bool:
        success = await self._send_command(CMD_SET_PROCESS, struct.pack(">H", Process.DESCALING))
        if success:
            self._status = "descaling"
            self._notify_callbacks()
        return success

    async def standby(self) -> bool:
        success = await self._send_command(CMD_SET_PROCESS, struct.pack(">H", Process.SWITCH_OFF))
        if success:
            self._status = "switch_off"
            self._notify_callbacks()
        return success

    async def read_value(self, param_id: int) -> bool:
        return await self._send_command(CMD_READ_VALUE, struct.pack(">H", param_id))

    async def write_value(self, param_id: int, value: int) -> bool:
        payload = struct.pack(">Hi", param_id, value)
        return await self._send_command(CMD_WRITE_VALUE, payload)

    async def update(self) -> None:
        if not self._is_connected:
            await self.connect()
        elif self._authenticated:
            try:
                frame = _build_frame(CMD_STATUS, b"")
                await self._send_raw(frame)
            except Exception as err:
                _LOGGER.debug("Status poll failed: %s", err)
                self._is_connected = False
                self._authenticated = False
                self._client = None
                self._stop_keepalive()
                self._notify_callbacks()
                if not self._shutting_down:
                    self._schedule_reconnect()


async def discover_all_ble_devices(timeout: float = 10.0) -> list:
    try:
        devices = await BleakScanner.discover(timeout=timeout)
        return devices
    except Exception as err:
        _LOGGER.warning("BLE scan failed: %s", err)
        return []
