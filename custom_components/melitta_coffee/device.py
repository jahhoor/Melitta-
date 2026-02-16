import asyncio
import logging
import os
import struct
from datetime import datetime
from typing import Callable

from bleak import BleakClient, BleakError

from .const import (
    BLE_READ_UUID, BLE_WRITE_UUID,
    CMD_AUTH, CMD_KEEPALIVE, CMD_STATUS, CMD_BREW, CMD_WRITE,
    KEEPALIVE_INTERVAL,
    MACHINE_STATE_NAMES,
    BEVERAGE_NAMES,
)
from .crypto import sbox_hash
from .protocol import build_frame, EfComParser, EfComFrame

_LOGGER = logging.getLogger(__name__)

AUTH_TIMEOUT = 5.0
CONNECT_TIMEOUT = 15.0
DISCONNECT_TIMEOUT = 10.0


class MelittaDevice:
    def __init__(self, address: str, name: str | None = None):
        self._address = address
        self._name = name or f"Melitta {address}"
        self._client: BleakClient | None = None
        self._parser = EfComParser()
        self._session_key: bytes | None = None
        self._auth_challenge: bytes | None = None
        self._auth_event = asyncio.Event()
        self._authenticated = False
        self._is_connected = False
        self._shutting_down = False
        self._keepalive_task: asyncio.Task | None = None
        self._callbacks: list[Callable] = []
        self._status = "offline"
        self._machine_state: int | None = None
        self._machine_state_name: str = "Unknown"
        self._last_error: str | None = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 5
        self._last_status_data: bytes | None = None
        self._strength: int = 2
        self._cups: int = 1
        self._water_level: int | None = None
        self._bean_level: int | None = None
        self._drip_tray_full: bool = False
        self._brew_progress: int | None = None
        self._error_code: int | None = None

    @property
    def address(self) -> str:
        return self._address

    @property
    def name(self) -> str:
        return self._name

    @property
    def status(self) -> str:
        return self._status

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def machine_state(self) -> int | None:
        return self._machine_state

    @property
    def machine_state_name(self) -> str:
        return self._machine_state_name

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def water_level(self) -> int | None:
        return self._water_level

    @property
    def bean_level(self) -> int | None:
        return self._bean_level

    @property
    def drip_tray_full(self) -> bool:
        return self._drip_tray_full

    @property
    def brew_progress(self) -> int | None:
        return self._brew_progress

    @property
    def error_code(self) -> int | None:
        return self._error_code

    @property
    def strength(self) -> int:
        return self._strength

    @strength.setter
    def strength(self, value: int):
        self._strength = max(0, min(4, value))

    @property
    def cups(self) -> int:
        return self._cups

    @cups.setter
    def cups(self, value: int):
        self._cups = max(1, min(2, value))

    def register_callback(self, callback: Callable) -> Callable:
        self._callbacks.append(callback)
        def remove():
            if callback in self._callbacks:
                self._callbacks.remove(callback)
        return remove

    def _notify_callbacks(self):
        for cb in self._callbacks:
            try:
                cb()
            except Exception:
                _LOGGER.exception("Error in callback")

    def _on_disconnect(self, client: BleakClient):
        was_auth = self._status == "authenticating"
        prev_status = self._status
        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            self._keepalive_task = None

        if was_auth:
            self._status = "auth_dropped"
            self._last_error = "Machine dropped connection during authentication. Press 'Verbinden' on the machine display."
            self._auth_event.set()
        elif not self._shutting_down:
            self._status = "offline"
            self._last_error = "Connection lost"

        _LOGGER.warning(
            "DISCONNECTED from %s: prev_status=%s, was_auth=%s, shutting_down=%s, new_status=%s",
            self._address, prev_status, was_auth, self._shutting_down, self._status,
        )
        self._notify_callbacks()

    def _on_notification(self, sender, data: bytes):
        _LOGGER.info("BLE RX notification: %d bytes, raw_hex=%s, sender=%s", len(data), data.hex(), sender)
        frames = self._parser.feed(data)
        if not frames:
            _LOGGER.debug("No complete frames parsed from this notification (buffering)")
        for frame in frames:
            _LOGGER.info("Parsed frame from notification: %s", frame)
            self._handle_frame(frame)

    def _handle_frame(self, frame: EfComFrame):
        _LOGGER.debug("Received frame: %s", frame)

        if frame.command == CMD_AUTH:
            self._handle_auth_response(frame)
        elif frame.command == CMD_STATUS:
            self._handle_status_response(frame)
        elif frame.command == CMD_KEEPALIVE:
            _LOGGER.debug("Keepalive acknowledged")
        elif frame.command == "A":
            _LOGGER.debug("ACK received")
        elif frame.command == "N":
            _LOGGER.warning("NACK received")
        else:
            _LOGGER.debug("Unhandled frame: %s", frame)

    def _handle_auth_response(self, frame: EfComFrame):
        payload = frame.payload
        _LOGGER.info(
            "Auth response received: %d bytes, payload=%s, encrypted=%s",
            len(payload), payload.hex(), frame.encrypted,
        )
        if len(payload) != 8:
            _LOGGER.error("Auth response has unexpected length: %d (expected 8)", len(payload))
            self._auth_event.set()
            return

        echo = payload[0:4]
        session = payload[4:6]
        hash_received = payload[6:8]

        _LOGGER.debug(
            "Auth response fields: echo=%s, session=%s, hash=%s",
            echo.hex(), session.hex(), hash_received.hex(),
        )

        if self._auth_challenge is None:
            _LOGGER.error("Received auth response without pending challenge")
            self._auth_event.set()
            return

        _LOGGER.debug(
            "Auth challenge comparison: sent=%s, echoed=%s, match=%s",
            self._auth_challenge.hex(), echo.hex(), echo == self._auth_challenge,
        )
        if echo != self._auth_challenge:
            _LOGGER.error(
                "Auth challenge echo MISMATCH: sent=%s, got=%s",
                self._auth_challenge.hex(), echo.hex(),
            )
            self._auth_event.set()
            return

        verify_data = payload[0:6]
        expected_hash = sbox_hash(verify_data, len(verify_data))
        _LOGGER.debug(
            "Auth hash verification: verify_data=%s, expected=%s, received=%s, match=%s",
            verify_data.hex(), expected_hash.hex(), hash_received.hex(),
            hash_received == expected_hash,
        )
        if hash_received != expected_hash:
            _LOGGER.error(
                "Auth hash MISMATCH: expected=%s, received=%s (verify_data=%s)",
                expected_hash.hex(), hash_received.hex(), verify_data.hex(),
            )
            self._auth_event.set()
            return

        self._session_key = session
        self._authenticated = True
        _LOGGER.info("Authentication SUCCESSFUL")
        _LOGGER.debug("Session key [SENSITIVE]: %s", session.hex())
        self._auth_event.set()

    def _handle_status_response(self, frame: EfComFrame):
        self._last_status_data = frame.payload
        payload = frame.payload
        _LOGGER.info(
            "Status response: %d bytes, raw_payload=%s, encrypted=%s",
            len(payload), payload.hex(), frame.encrypted,
        )
        if len(payload) >= 2:
            state_value = struct.unpack(">H", payload[0:2])[0]
            self._machine_state = state_value
            self._machine_state_name = MACHINE_STATE_NAMES.get(state_value, f"Unknown ({state_value})")
            _LOGGER.debug("  state bytes=[%s] -> value=%d (%s)", payload[0:2].hex(), state_value, self._machine_state_name)
        if len(payload) >= 3:
            self._water_level = payload[2] & 0xFF
            _LOGGER.debug("  water_level byte=0x%02x -> %d%%", payload[2], self._water_level)
        if len(payload) >= 4:
            self._bean_level = payload[3] & 0xFF
            _LOGGER.debug("  bean_level byte=0x%02x -> %d%%", payload[3], self._bean_level)
        if len(payload) >= 5:
            self._drip_tray_full = (payload[4] & 0x01) != 0
            _LOGGER.debug("  drip_tray byte=0x%02x -> full=%s", payload[4], self._drip_tray_full)
        if len(payload) >= 6:
            self._brew_progress = payload[5] & 0xFF
            _LOGGER.debug("  brew_progress byte=0x%02x -> %d%%", payload[5], self._brew_progress)
        if len(payload) >= 8:
            self._error_code = struct.unpack(">H", payload[6:8])[0]
            _LOGGER.debug("  error_code bytes=[%s] -> %d", payload[6:8].hex(), self._error_code)
            if self._error_code == 0:
                self._error_code = None
        _LOGGER.info(
            "Status parsed: state=%s, water=%s%%, beans=%s%%, tray_full=%s, progress=%s%%, error=%s",
            self._machine_state_name,
            self._water_level,
            self._bean_level,
            self._drip_tray_full,
            self._brew_progress,
            self._error_code,
        )
        self._notify_callbacks()

    async def connect(self) -> bool:
        if self._is_connected and self._authenticated:
            _LOGGER.debug("Already connected and authenticated to %s", self._address)
            return True

        _LOGGER.info("Connecting to %s (attempt %d/%d)...", self._address, self._reconnect_attempts + 1, self._max_reconnect_attempts)

        try:
            self._status = "connecting"
            self._notify_callbacks()

            self._client = BleakClient(
                self._address,
                timeout=CONNECT_TIMEOUT,
                disconnected_callback=self._on_disconnect,
            )
            _LOGGER.debug("BleakClient created, connecting with timeout=%ds...", CONNECT_TIMEOUT)
            await self._client.connect()
            self._is_connected = True
            self._reconnect_attempts = 0
            self._last_error = None
            _LOGGER.info("BLE connected to %s", self._address)

            _LOGGER.debug("Starting notifications on %s", BLE_READ_UUID)
            await self._client.start_notify(BLE_READ_UUID, self._on_notification)
            _LOGGER.debug("Notifications started")

            self._status = "authenticating"
            self._notify_callbacks()

            if not self._shutting_down:
                await self._authenticate()

            if not self._is_connected:
                _LOGGER.warning("Connection lost during auth for %s", self._address)
                return False

            if self._authenticated:
                self._status = "ready"
                self._start_keepalive()
                _LOGGER.info("CONNECTED and AUTHENTICATED with %s", self._address)
                await self._request_status()
            else:
                self._status = "connected_not_auth"
                _LOGGER.warning("Connected but NOT authenticated to %s - machine may need pairing button press", self._address)

            self._notify_callbacks()
            return self._authenticated

        except (BleakError, asyncio.TimeoutError, OSError) as err:
            self._status = "offline"
            self._last_error = str(err)
            self._reconnect_attempts += 1
            _LOGGER.error("CONNECT FAILED to %s: %s (attempt %d)", self._address, err, self._reconnect_attempts)
            self._notify_callbacks()
            return False

    async def _authenticate(self):
        self._auth_challenge = os.urandom(4)
        challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
        auth_payload = self._auth_challenge + challenge_hash

        _LOGGER.info(
            "Starting authentication: challenge=%s, hash=%s, auth_payload=%s",
            self._auth_challenge.hex(), challenge_hash.hex(), auth_payload.hex(),
        )

        auth_encrypted = build_frame(CMD_AUTH, None, auth_payload, encrypt=True)
        auth_plaintext = build_frame(CMD_AUTH, None, auth_payload, encrypt=False)

        _LOGGER.debug("Auth encrypted frame: %s", auth_encrypted.hex())
        _LOGGER.debug("Auth plaintext frame: %s", auth_plaintext.hex())

        for attempt, (frame, desc) in enumerate([
            (auth_encrypted, "encrypted"),
            (auth_plaintext, "plaintext"),
        ]):
            if not self._is_connected:
                _LOGGER.warning("Connection lost before auth attempt %d", attempt + 1)
                return

            self._auth_event.clear()
            self._authenticated = False

            _LOGGER.info(
                "Auth attempt %d/2 (%s): writing %d bytes to %s, frame=%s",
                attempt + 1, desc, len(frame), BLE_WRITE_UUID, frame.hex(),
            )

            try:
                await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False)
                _LOGGER.debug("Auth frame written successfully")
            except Exception as err:
                _LOGGER.error("Failed to send auth frame (%s): %s", desc, err)
                continue

            try:
                await asyncio.wait_for(self._auth_event.wait(), timeout=AUTH_TIMEOUT)
            except asyncio.TimeoutError:
                _LOGGER.info("Auth TIMEOUT after %.1fs with %s frame (no response from machine)", AUTH_TIMEOUT, desc)
                continue

            if self._authenticated:
                _LOGGER.info("Authentication SUCCEEDED with %s frame on attempt %d", desc, attempt + 1)
                return

            _LOGGER.info("Auth attempt %d (%s) completed but authentication failed", attempt + 1, desc)
            await asyncio.sleep(0.5)

        _LOGGER.warning("ALL auth attempts FAILED for %s - machine may need pairing confirmation", self._address)

    def _start_keepalive(self):
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
        self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())

    async def _keepalive_loop(self):
        try:
            while self._is_connected and self._authenticated:
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                if not self._is_connected or not self._authenticated:
                    break
                try:
                    frame = build_frame(CMD_KEEPALIVE, self._session_key, None, encrypt=True)
                    await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False)
                    _LOGGER.debug("Keepalive sent")
                except Exception as err:
                    _LOGGER.warning("Keepalive failed: %s", err)
                    break
        except asyncio.CancelledError:
            pass

    async def _request_status(self):
        if not self._is_connected or not self._authenticated:
            return
        try:
            frame = build_frame(CMD_STATUS, self._session_key, None, encrypt=True)
            await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False)
            _LOGGER.debug("Status request sent")
        except Exception as err:
            _LOGGER.warning("Status request failed: %s", err)

    async def async_update(self):
        if not self._is_connected:
            if self._reconnect_attempts < self._max_reconnect_attempts:
                await self.connect()
            return

        if self._is_connected and not self._authenticated:
            await self._authenticate()
            if self._authenticated:
                self._status = "ready"
                self._start_keepalive()
                self._notify_callbacks()

        if self._authenticated:
            await self._request_status()

    async def brew(self, beverage_type: int, strength: int | None = None, cups: int | None = None) -> bool:
        if not self._authenticated or not self._session_key:
            _LOGGER.warning("Cannot brew: not authenticated (auth=%s, session=%s)", self._authenticated, self._session_key is not None)
            return False

        s = strength if strength is not None else self._strength
        c = cups if cups is not None else self._cups
        payload = bytes([beverage_type & 0xFF, s & 0xFF, c & 0xFF])

        bev_name = BEVERAGE_NAMES.get(beverage_type, f"type_{beverage_type}")
        _LOGGER.info(
            "Brewing: %s (type=%d), strength=%d, cups=%d, payload=%s",
            bev_name, beverage_type, s, c, payload.hex(),
        )

        try:
            frame = build_frame(CMD_BREW, self._session_key, payload, encrypt=True)
            _LOGGER.debug("Brew frame: %s", frame.hex())
            await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False)
            _LOGGER.info("Brew command SENT for %s (strength=%d, cups=%d)", bev_name, s, c)
            return True
        except Exception as err:
            _LOGGER.error("Brew command FAILED: %s", err)
            return False

    async def send_write(self, param_id: int, value: int) -> bool:
        if not self._authenticated or not self._session_key:
            _LOGGER.warning("Cannot write: not authenticated")
            return False

        payload = bytes([
            (param_id >> 8) & 0xFF, param_id & 0xFF,
            (value >> 24) & 0xFF, (value >> 16) & 0xFF,
            (value >> 8) & 0xFF, value & 0xFF,
        ])

        try:
            frame = build_frame(CMD_WRITE, self._session_key, payload, encrypt=True)
            await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False)
            _LOGGER.debug("Write command sent: param=%d, value=%d", param_id, value)
            return True
        except Exception as err:
            _LOGGER.error("Write command failed: %s", err)
            return False

    async def disconnect(self):
        self._shutting_down = True
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            self._keepalive_task = None

        if self._client and self._is_connected:
            try:
                await asyncio.wait_for(self._client.disconnect(), timeout=DISCONNECT_TIMEOUT)
            except (BleakError, asyncio.TimeoutError, OSError) as err:
                _LOGGER.warning("Disconnect error: %s", err)

        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        self._status = "offline"
        self._shutting_down = False
        self._notify_callbacks()
