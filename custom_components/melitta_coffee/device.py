import asyncio
import logging
import os
import struct
import time
from datetime import datetime
from typing import Callable, Any

from bleak import BleakClient, BleakError
from bleak_retry_connector import establish_connection, BleakClientWithServiceCache

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

AUTH_TIMEOUT = 30.0
CONNECT_TIMEOUT = 15.0
DISCONNECT_TIMEOUT = 10.0
BLE_SETTLE_DELAY = 0.3
RECONNECT_BASE_DELAY = 10.0
RECONNECT_MAX_DELAY = 300.0
RECONNECT_MAX_ATTEMPTS = 0


class MelittaDevice:
    def __init__(self, address: str, name: str | None = None, hass: Any = None):
        self._address = address
        self._name = name or f"Melitta {address}"
        self._hass = hass
        self._client: BleakClient | None = None
        self._parser = EfComParser()
        self._session_key: bytes | None = None
        self._auth_challenge: bytes | None = None
        self._auth_event = asyncio.Event()
        self._auth_got_frame = False
        self._auth_disconnect_reason: str | None = None
        self._pipeline_auth_write_time: float | None = None
        self._authenticated = False
        self._is_connected = False
        self._shutting_down = False
        self._keepalive_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._connect_lock = asyncio.Lock()
        self._auth_lock = asyncio.Lock()
        self._connect_pending = False
        self._last_reconnect_time: float = 0.0
        self._callbacks: list[Callable] = []
        self._status = "offline"
        self._machine_state: int | None = None
        self._machine_state_name: str = "Unknown"
        self._last_error: str | None = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = RECONNECT_MAX_ATTEMPTS
        self._disconnect_in_progress = False
        self._suppress_disconnect_callback = False
        self._cccd_recovery_in_progress = False
        self._notify_mode = "notifications"
        self._notifications_active = False
        self._polling_task: asyncio.Task | None = None
        self._last_status_data: bytes | None = None
        self._dbus_notify_bus = None
        self._dbus_notify_handler = None
        self._dbus_match_rule: str | None = None
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
        import traceback
        caller_info = "".join(traceback.format_stack(limit=5))

        if self._suppress_disconnect_callback or self._cccd_recovery_in_progress:
            self._is_connected = False
            _LOGGER.warning(
                "DISCONNECT CALLBACK (suppressed) for %s - set _is_connected=False but NOT running reconnect logic\n"
                "  (suppress=%s, cccd_recovery=%s, prev_connected=True, status=%s)",
                self._address, self._suppress_disconnect_callback, self._cccd_recovery_in_progress, self._status,
            )
            return
        if client is not self._client:
            _LOGGER.warning(
                "DISCONNECT CALLBACK from stale client for %s - ignoring",
                self._address,
            )
            return
        if self._disconnect_in_progress:
            _LOGGER.warning(
                "DISCONNECT CALLBACK duplicate for %s - ignoring (already processing)",
                self._address,
            )
            return

        self._disconnect_in_progress = True
        try:
            was_auth = self._status in ("authenticating", "waiting_for_machine_button")
            prev_status = self._status
            self._is_connected = False
            self._authenticated = False
            self._session_key = None
            self._stop_polling()
            if self._keepalive_task and not self._keepalive_task.done():
                self._keepalive_task.cancel()
                self._keepalive_task = None

            use_fast_reconnect = False
            if was_auth:
                self._status = "auth_dropped"
                self._last_error = "Machine heeft verbinding verbroken tijdens authenticatie. Wacht op automatische herverbinding."
                self._auth_disconnect_reason = f"disconnect during auth (prev={prev_status}, shutting_down={self._shutting_down})"
                self._auth_event.set()
            elif prev_status == "connecting":
                self._status = "offline"
                self._last_error = "Verbinding verbroken tijdens opzetten"
            elif not self._shutting_down:
                self._status = "offline"
                self._last_error = "Connection lost"

            _LOGGER.warning(
                "=== DISCONNECTED from %s ===\n"
                "  prev_status=%s, was_auth=%s, shutting_down=%s, new_status=%s\n"
                "  auth_event_set=%s, auth_got_frame=%s, auth_lock_locked=%s\n"
                "  caller_stack:\n%s",
                self._address, prev_status, was_auth, self._shutting_down, self._status,
                self._auth_event.is_set(), self._auth_got_frame, self._auth_lock.locked(),
                caller_info,
            )
            self._notify_callbacks()

            if not self._shutting_down:
                self.schedule_reconnect(fast=use_fast_reconnect)
            else:
                _LOGGER.warning(
                    "NOT scheduling reconnect because shutting_down=True for %s",
                    self._address,
                )
        finally:
            self._disconnect_in_progress = False

    def _cancel_reconnect(self):
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            self._reconnect_task = None

    def schedule_reconnect(self, fast: bool = False):
        if self._shutting_down:
            return
        if self._is_connected and self._authenticated:
            return
        if self._connect_pending or self._connect_lock.locked():
            _LOGGER.debug("Connect already in progress for %s, skipping schedule", self._address)
            return
        if self._auth_lock.locked():
            _LOGGER.debug("Auth in progress for %s, skipping reconnect schedule", self._address)
            return
        if self._reconnect_task and not self._reconnect_task.done():
            _LOGGER.debug("Reconnect already scheduled for %s", self._address)
            return

        import time
        now = time.monotonic()
        since_last = now - self._last_reconnect_time
        min_cooldown = 8.0

        if fast and self._reconnect_attempts < 2:
            delay = 5.0
        else:
            capped_attempts = min(self._reconnect_attempts, 5)
            delay = min(RECONNECT_BASE_DELAY * (2 ** capped_attempts), RECONNECT_MAX_DELAY)

        if since_last < min_cooldown:
            cooldown_remaining = min_cooldown - since_last
            delay = max(delay, cooldown_remaining)
            _LOGGER.debug(
                "Reconnect cooldown: only %.1fs since last attempt, enforcing delay=%.1fs",
                since_last, delay,
            )
        self._reconnect_attempts += 1
        _LOGGER.info(
            "Scheduling reconnect to %s in %.0fs (attempt %d)",
            self._address, delay, self._reconnect_attempts,
        )
        self._status = "waiting_reconnect"
        self._last_error = f"Opnieuw verbinden over {int(delay)} seconden... (poging {self._reconnect_attempts})"
        self._notify_callbacks()

        if self._hass is not None:
            self._reconnect_task = self._hass.async_create_background_task(
                self._reconnect_after_delay(delay),
                f"melitta_reconnect_{self._address}",
            )
        else:
            self._reconnect_task = asyncio.ensure_future(self._reconnect_after_delay(delay))

    async def _reconnect_after_delay(self, delay: float):
        try:
            await asyncio.sleep(delay)
            if self._shutting_down or (self._is_connected and self._authenticated):
                return
            import time
            self._last_reconnect_time = time.monotonic()
            _LOGGER.info("Attempting reconnect to %s (attempt %d)...", self._address, self._reconnect_attempts)
            self._reconnect_task = None
            success = await self.connect()
            if not success and not self._shutting_down:
                self.schedule_reconnect()
        except asyncio.CancelledError:
            _LOGGER.debug("Reconnect task cancelled for %s", self._address)
        except Exception as err:
            _LOGGER.error("Reconnect error for %s: %s", self._address, err)
            self._reconnect_task = None
            if not self._shutting_down:
                self.schedule_reconnect()

    def _on_notification(self, sender, data: bytes):
        _LOGGER.warning(
            ">>> BLE NOTIFICATION RX (bleak callback): %d bytes, hex=%s, sender=%s",
            len(data), data.hex(), sender,
        )
        self._process_incoming_data(data)

    def _process_incoming_data(self, data: bytes):
        _LOGGER.warning(
            "PROCESS_INCOMING_DATA: %d bytes, hex=%s, connected=%s, authenticated=%s, status=%s",
            len(data), data.hex(), self._is_connected, self._authenticated, self._status,
        )
        frames = self._parser.feed(data)
        if not frames:
            buf_pos = getattr(self._parser, '_pos', 0)
            buf_data = bytes(self._parser._buffer[:buf_pos]) if buf_pos > 0 else b""
            _LOGGER.warning(
                "PARSER: no complete frames yet (buffering). Buffer pos=%d, buffered_hex=%s",
                buf_pos, buf_data.hex() if buf_data else "empty",
            )
        else:
            _LOGGER.warning("PARSER: got %d complete frame(s)", len(frames))
        for frame in frames:
            _LOGGER.warning(
                "PARSED FRAME: command=%r, payload_len=%d, payload_hex=%s, encrypted=%s, raw_hex=%s",
                frame.command, len(frame.payload), frame.payload.hex(), frame.encrypted,
                frame.raw.hex() if hasattr(frame, 'raw') and frame.raw else "n/a",
            )
            self._handle_frame(frame)

    async def _start_polling(self):
        _LOGGER.warning("POLLING STARTED on %s (200ms interval)", BLE_READ_UUID)
        self._notify_mode = "polling"
        last_data = None
        poll_count = 0
        try:
            while self._is_connected and not self._shutting_down:
                client = self._client
                if client is None:
                    _LOGGER.warning("POLLING STOPPED: client is None")
                    break
                try:
                    data = await client.read_gatt_char(BLE_READ_UUID)
                    poll_count += 1
                    if data and len(data) > 0:
                        if data != last_data:
                            _LOGGER.warning(
                                "BLE POLL RX [#%d]: NEW data, %d bytes, hex=%s",
                                poll_count, len(data), data.hex(),
                            )
                            last_data = data
                            self._process_incoming_data(data)
                        elif poll_count <= 10 or poll_count % 25 == 0:
                            _LOGGER.warning(
                                "BLE POLL [#%d]: same data repeated, %d bytes, hex=%s",
                                poll_count, len(data), data.hex(),
                            )
                    elif poll_count <= 10 or poll_count % 25 == 0:
                        _LOGGER.warning(
                            "BLE POLL [#%d]: empty/null response (data=%s)",
                            poll_count, repr(data),
                        )
                except BleakError as err:
                    if not self._is_connected or self._shutting_down or self._client is None:
                        _LOGGER.warning("POLLING STOPPED: disconnected during BleakError: %s", err)
                        break
                    _LOGGER.warning("BLE POLL ERROR [#%d]: %s: %s", poll_count, type(err).__name__, err)
                except Exception as err:
                    if not self._is_connected or self._shutting_down or self._client is None:
                        _LOGGER.warning("POLLING STOPPED: disconnected during error: %s", err)
                        break
                    _LOGGER.warning("BLE POLL ERROR [#%d]: %s: %s", poll_count, type(err).__name__, err)
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            _LOGGER.warning("POLLING CANCELLED after %d reads", poll_count)
        _LOGGER.warning("POLLING ENDED after %d reads (connected=%s)", poll_count, self._is_connected)

    def _stop_polling(self):
        if self._polling_task and not self._polling_task.done():
            self._polling_task.cancel()
            self._polling_task = None

    def _handle_frame(self, frame: EfComFrame):
        try:
            cmd_hex = "0x%02x" % ord(frame.command) if isinstance(frame.command, str) and len(frame.command) == 1 else repr(frame.command)
        except Exception:
            cmd_hex = repr(frame.command)
        _LOGGER.warning(
            "HANDLE_FRAME: command=%r (%s), payload_len=%d, encrypted=%s",
            frame.command, cmd_hex, len(frame.payload), frame.encrypted,
        )

        if frame.command == CMD_AUTH:
            _LOGGER.warning(">>> AUTH FRAME RECEIVED - calling _handle_auth_response")
            self._handle_auth_response(frame)
        elif frame.command == CMD_STATUS:
            self._handle_status_response(frame)
        elif frame.command == CMD_KEEPALIVE:
            _LOGGER.warning(
                "KEEPALIVE response: payload=%s (%d bytes)",
                frame.payload.hex(), len(frame.payload),
            )
        elif frame.command == "A":
            _LOGGER.warning("ACK received: payload=%s", frame.payload.hex())
        elif frame.command == "N":
            _LOGGER.warning("NACK received: payload=%s", frame.payload.hex())
        else:
            _LOGGER.warning(
                "UNHANDLED FRAME: command=%r (%s), payload=%s",
                frame.command, cmd_hex, frame.payload.hex(),
            )

    def _handle_auth_response(self, frame: EfComFrame):
        payload = frame.payload
        self._auth_got_frame = True
        _LOGGER.warning(
            "=== AUTH RESPONSE FRAME RECEIVED ===\n"
            "  payload_length=%d, payload_hex=%s, encrypted=%s\n"
            "  current_state: connected=%s, authenticated=%s, status=%s, shutting_down=%s",
            len(payload), payload.hex(), frame.encrypted,
            self._is_connected, self._authenticated, self._status, self._shutting_down,
        )
        if len(payload) != 8:
            _LOGGER.warning(
                "AUTH FAIL: unexpected payload length %d (expected 8). "
                "Raw payload hex: %s. This might mean decryption failed or wrong frame format.",
                len(payload), payload.hex(),
            )
            self._auth_event.set()
            return

        echo = payload[0:4]
        session = payload[4:6]
        hash_received = payload[6:8]

        _LOGGER.warning(
            "AUTH RESPONSE FIELDS:\n"
            "  echo (4 bytes)     = %s\n"
            "  session_key (2 bytes) = %s\n"
            "  hash (2 bytes)     = %s",
            echo.hex(), session.hex(), hash_received.hex(),
        )

        if self._auth_challenge is None:
            _LOGGER.warning("AUTH FAIL: no pending challenge (self._auth_challenge is None)")
            self._auth_event.set()
            return

        _LOGGER.warning(
            "AUTH ECHO CHECK: sent_challenge=%s, received_echo=%s, MATCH=%s",
            self._auth_challenge.hex(), echo.hex(), echo == self._auth_challenge,
        )

        if echo != self._auth_challenge:
            _LOGGER.warning(
                "AUTH FAIL: echo mismatch!\n"
                "  We sent challenge = %s\n"
                "  Machine echoed    = %s\n"
                "  This could mean: wrong encryption, different auth request, or machine sent old response.",
                self._auth_challenge.hex(), echo.hex(),
            )
            self._auth_event.set()
            return

        verify_data = payload[0:6]
        expected_hash = sbox_hash(verify_data, len(verify_data))
        hash_match = hash_received == expected_hash
        _LOGGER.warning(
            "AUTH HASH CHECK:\n"
            "  verify_data = %s\n"
            "  expected_hash = %s\n"
            "  received_hash = %s\n"
            "  MATCH = %s",
            verify_data.hex(), expected_hash.hex(), hash_received.hex(), hash_match,
        )

        if not hash_match:
            _LOGGER.warning(
                "AUTH: SBOX hash mismatch but echo matched! "
                "Accepting session anyway (SBOX table may differ per model).",
            )

        self._session_key = session
        self._authenticated = True
        _LOGGER.warning(
            "=== AUTH SUCCESS ===\n"
            "  session_key=%s, echo_match=True, hash_match=%s, encrypted=%s",
            session.hex(), hash_match, frame.encrypted,
        )
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

        self._connect_pending = True

        if self._connect_lock.locked():
            _LOGGER.debug("Connect already in progress (locked) for %s, waiting...", self._address)

        try:
            async with self._connect_lock:
                if self._is_connected and self._authenticated:
                    return True
                self._cancel_reconnect()
                return await self._do_connect()
        finally:
            self._connect_pending = False

    async def _internal_disconnect(self):
        if self._dbus_notify_bus is not None:
            try:
                if self._dbus_notify_handler:
                    self._dbus_notify_bus.remove_message_handler(self._dbus_notify_handler)
                if self._dbus_match_rule:
                    try:
                        from dbus_fast import Message
                        await self._dbus_notify_bus.call(Message(
                            destination="org.freedesktop.DBus",
                            path="/org/freedesktop/DBus",
                            interface="org.freedesktop.DBus",
                            member="RemoveMatch",
                            signature="s",
                            body=[self._dbus_match_rule],
                        ))
                    except Exception:
                        pass
                self._dbus_notify_bus.disconnect()
            except Exception:
                pass
            self._dbus_notify_bus = None
            self._dbus_notify_handler = None
            self._dbus_match_rule = None

        if self._client is None:
            return
        old_client = self._client
        self._client = None
        self._is_connected = False
        self._notifications_active = False
        self._stop_polling()
        self._suppress_disconnect_callback = True
        try:
            try:
                await old_client.stop_notify(BLE_READ_UUID)
            except Exception:
                pass
            try:
                await old_client.disconnect()
            except Exception:
                pass
        finally:
            self._suppress_disconnect_callback = False

    async def _internal_reconnect_ble(self) -> bool:
        t_reconn_start = time.monotonic()
        ble_device = None
        if self._hass is not None:
            try:
                from homeassistant.components.bluetooth import async_ble_device_from_address
                ble_device = async_ble_device_from_address(self._hass, self._address, connectable=True)
                if not ble_device:
                    _LOGGER.warning(
                        "RECONNECT: Device %s not found via HA Bluetooth (took %.1fms)",
                        self._address, (time.monotonic() - t_reconn_start) * 1000,
                    )
                    return False
                _LOGGER.warning(
                    "RECONNECT: Got BLEDevice from HA: name=%s, rssi=%s (took %.1fms)",
                    ble_device.name, getattr(ble_device, 'rssi', 'N/A'),
                    (time.monotonic() - t_reconn_start) * 1000,
                )
            except Exception as e:
                _LOGGER.error(
                    "RECONNECT: Failed to get BLEDevice: %s (took %.1fms)",
                    e, (time.monotonic() - t_reconn_start) * 1000,
                )
                return False
        else:
            ble_device = self._address

        t_connect_start = time.monotonic()
        try:
            if self._hass is not None and not isinstance(ble_device, str):
                self._client = await establish_connection(
                    BleakClientWithServiceCache,
                    ble_device,
                    self._name,
                    disconnected_callback=self._on_disconnect,
                    max_attempts=2,
                )
            else:
                self._client = BleakClient(
                    ble_device,
                    timeout=CONNECT_TIMEOUT,
                    disconnected_callback=self._on_disconnect,
                )
                await self._client.connect()
            self._is_connected = True
            t_connected = time.monotonic()
            _LOGGER.warning(
                "RECONNECT: BLE reconnect SUCCEEDED for %s (connect took %.1fms, total %.1fms)\n"
                "  mtu=%s, services=%d",
                self._address,
                (t_connected - t_connect_start) * 1000,
                (t_connected - t_reconn_start) * 1000,
                getattr(self._client, 'mtu_size', 'N/A'),
                sum(1 for _ in self._client.services) if self._client.services else 0,
            )
            await asyncio.sleep(0.3)
            return True
        except Exception as err:
            _LOGGER.error(
                "RECONNECT: BLE reconnect FAILED for %s: %s (%s) (took %.1fms)",
                self._address, err, type(err).__name__,
                (time.monotonic() - t_reconn_start) * 1000,
            )
            self._client = None
            self._is_connected = False
            return False

    async def _get_char_dbus_path_async(self, uuid: str) -> str | None:
        if not self._client:
            return None
        try:
            for service in self._client.services:
                for char in service.characteristics:
                    if char.uuid.lower() == uuid.lower():
                        if hasattr(char, 'path'):
                            _LOGGER.info("Found char path from bleak service cache: %s", char.path)
                            return char.path
                        if hasattr(char, 'obj') and hasattr(char.obj, 'get_object_path'):
                            p = char.obj.get_object_path()
                            _LOGGER.info("Found char path from bleak obj: %s", p)
                            return p
        except Exception as err:
            _LOGGER.debug("Could not get char path from bleak services: %s", err)

        mac_path = self._address.replace(":", "_").upper()
        uuid_short = uuid.replace("-", "").lower()
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType
            import re

            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspect_root = Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_root)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"
                    dev_reply = await bus.call(Message(
                        destination="org.bluez", path=device_path,
                        interface="org.freedesktop.DBus.Introspectable",
                        member="Introspect",
                    ))
                    if dev_reply.message_type == MessageType.ERROR:
                        continue
                    services = re.findall(r'<node name="(service\w+)"', dev_reply.body[0]) if dev_reply.body else []
                    for svc in services:
                        svc_path = f"{device_path}/{svc}"
                        svc_reply = await bus.call(Message(
                            destination="org.bluez", path=svc_path,
                            interface="org.freedesktop.DBus.Introspectable",
                            member="Introspect",
                        ))
                        if svc_reply.message_type == MessageType.ERROR:
                            continue
                        chars = re.findall(r'<node name="(char\w+)"', svc_reply.body[0]) if svc_reply.body else []
                        for ch in chars:
                            cp = f"{svc_path}/{ch}"
                            uuid_reply = await bus.call(Message(
                                destination="org.bluez", path=cp,
                                interface="org.freedesktop.DBus.Properties",
                                member="Get", signature="ss",
                                body=["org.bluez.GattCharacteristic1", "UUID"],
                            ))
                            if uuid_reply.message_type == MessageType.ERROR:
                                continue
                            char_uuid = str(uuid_reply.body[0].value if uuid_reply.body else "")
                            if char_uuid.replace("-", "").lower() == uuid_short:
                                _LOGGER.info("Found char path via D-Bus introspection: %s", cp)
                                return cp
            finally:
                bus.disconnect()
        except ImportError:
            _LOGGER.warning("dbus_fast not available for D-Bus introspection")
        except Exception as err:
            _LOGGER.warning("D-Bus introspection failed: %s (%s)", err, type(err).__name__)
        return None

    async def _force_bluez_disconnect(self):
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType
            import re

            mac_path = self._address.replace(":", "_").upper()
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspect_root = Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_root)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"
                    connected_reply = await bus.call(Message(
                        destination="org.bluez", path=device_path,
                        interface="org.freedesktop.DBus.Properties",
                        member="Get", signature="ss",
                        body=["org.bluez.Device1", "Connected"],
                    ))
                    if connected_reply.message_type == MessageType.ERROR:
                        continue

                    is_connected = False
                    if connected_reply.body:
                        val = connected_reply.body[0]
                        is_connected = val.value if hasattr(val, 'value') else bool(val)

                    if is_connected:
                        _LOGGER.warning(
                            "BlueZ shows device %s as connected on %s - forcing disconnect",
                            self._address, adapter,
                        )
                        disc_reply = await bus.call(Message(
                            destination="org.bluez", path=device_path,
                            interface="org.bluez.Device1",
                            member="Disconnect",
                        ))
                        if disc_reply.message_type == MessageType.ERROR:
                            _LOGGER.warning(
                                "BlueZ force disconnect failed: %s %s",
                                disc_reply.error_name, disc_reply.body,
                            )
                        else:
                            _LOGGER.warning("BlueZ force disconnect succeeded - waiting for cleanup")
                            await asyncio.sleep(2.0)
                    else:
                        _LOGGER.debug("BlueZ shows device %s not connected on %s", self._address, adapter)
            finally:
                bus.disconnect()
        except ImportError:
            _LOGGER.debug("dbus_fast not available for BlueZ force disconnect")
        except Exception as err:
            _LOGGER.debug("BlueZ force disconnect error (non-fatal): %s", err)

    async def _dbus_pair_device(self) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType, Variant
            from dbus_fast.service import ServiceInterface, method as dbus_method
            import re

            AGENT_PATH = "/org/melitta/agent"
            AGENT_CAPABILITY = "NoInputNoOutput"

            class MelittaPairingAgent(ServiceInterface):
                def __init__(self):
                    super().__init__("org.bluez.Agent1")
                    self._released = False

                @dbus_method()
                def Release(self) -> "":
                    _LOGGER.warning("BLE AGENT: Release() called")
                    self._released = True

                @dbus_method()
                def RequestPinCode(self, device: "o") -> "s":
                    _LOGGER.warning("BLE AGENT: RequestPinCode for %s -> returning '0000'", device)
                    return "0000"

                @dbus_method()
                def DisplayPinCode(self, device: "o", pincode: "s") -> "":
                    _LOGGER.warning("BLE AGENT: DisplayPinCode for %s: %s", device, pincode)

                @dbus_method()
                def RequestPasskey(self, device: "o") -> "u":
                    _LOGGER.warning("BLE AGENT: RequestPasskey for %s -> returning 0", device)
                    return 0

                @dbus_method()
                def DisplayPasskey(self, device: "o", passkey: "u", entered: "q") -> "":
                    _LOGGER.warning("BLE AGENT: DisplayPasskey for %s: %d (entered=%d)", device, passkey, entered)

                @dbus_method()
                def RequestConfirmation(self, device: "o", passkey: "u") -> "":
                    _LOGGER.warning("BLE AGENT: RequestConfirmation for %s passkey=%d -> AUTO-ACCEPTING", device, passkey)

                @dbus_method()
                def RequestAuthorization(self, device: "o") -> "":
                    _LOGGER.warning("BLE AGENT: RequestAuthorization for %s -> AUTO-ACCEPTING", device)

                @dbus_method()
                def AuthorizeService(self, device: "o", uuid: "s") -> "":
                    _LOGGER.warning("BLE AGENT: AuthorizeService for %s uuid=%s -> AUTO-ACCEPTING", device, uuid)

                @dbus_method()
                def Cancel(self) -> "":
                    _LOGGER.warning("BLE AGENT: Cancel() called")

            mac_path = self._address.replace(":", "_").upper()
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            agent = MelittaPairingAgent()
            agent_registered = False
            try:
                try:
                    await bus.request_name("org.melitta.agent")
                    _LOGGER.warning("BLE AGENT: acquired bus name org.melitta.agent")
                except Exception as name_err:
                    _LOGGER.warning(
                        "BLE AGENT: could not acquire bus name (non-fatal, using unique name): %s",
                        name_err,
                    )

                bus.export(AGENT_PATH, agent)

                reg_reply = await bus.call(Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.bluez.AgentManager1",
                    member="RegisterAgent",
                    signature="os",
                    body=[AGENT_PATH, AGENT_CAPABILITY],
                ))
                if reg_reply.message_type == MessageType.ERROR:
                    error_name = reg_reply.error_name or ""
                    if "AlreadyExists" in error_name:
                        _LOGGER.warning("BLE AGENT: agent already registered (OK)")
                        agent_registered = True
                    else:
                        _LOGGER.warning(
                            "BLE AGENT: RegisterAgent FAILED: %s %s",
                            reg_reply.error_name, reg_reply.body,
                        )
                        return False
                else:
                    agent_registered = True
                    _LOGGER.warning("BLE AGENT: registered at %s (capability=%s)", AGENT_PATH, AGENT_CAPABILITY)

                default_reply = await bus.call(Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.bluez.AgentManager1",
                    member="RequestDefaultAgent",
                    signature="o",
                    body=[AGENT_PATH],
                ))
                if default_reply.message_type == MessageType.ERROR:
                    _LOGGER.warning(
                        "BLE AGENT: RequestDefaultAgent failed (non-fatal): %s",
                        default_reply.error_name,
                    )
                else:
                    _LOGGER.warning("BLE AGENT: set as default agent")

                introspect_root = Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_root)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"

                    paired_reply = await bus.call(Message(
                        destination="org.bluez", path=device_path,
                        interface="org.freedesktop.DBus.Properties",
                        member="Get", signature="ss",
                        body=["org.bluez.Device1", "Paired"],
                    ))
                    if paired_reply.message_type == MessageType.ERROR:
                        _LOGGER.warning(
                            "BLE PAIR: device %s not found on %s: %s",
                            self._address, adapter, paired_reply.error_name,
                        )
                        continue

                    is_paired = False
                    if paired_reply.body:
                        val = paired_reply.body[0]
                        is_paired = val.value if isinstance(val, Variant) else bool(val)

                    if is_paired:
                        _LOGGER.warning(
                            "BLE PAIR: device %s already paired on %s - skipping Pair()",
                            self._address, adapter,
                        )
                        return True

                    _LOGGER.warning(
                        "BLE PAIR: device %s NOT paired on %s - calling Pair() WITH AGENT...\n"
                        "  Agent geregistreerd op %s - accepteert koppelverzoek automatisch.\n"
                        "  Zorg dat de machine in 'Verbinden' modus staat!",
                        self._address, adapter, AGENT_PATH,
                    )
                    self._status = "pairing"
                    self._last_error = (
                        "Bluetooth-koppeling bezig... Zorg dat de machine in 'Verbinden' modus staat "
                        "(druk de Verbinden knop in het Bluetooth menu op de machine)."
                    )
                    self._notify_callbacks()

                    pair_reply = await asyncio.wait_for(
                        bus.call(Message(
                            destination="org.bluez", path=device_path,
                            interface="org.bluez.Device1",
                            member="Pair",
                        )),
                        timeout=30.0,
                    )

                    if pair_reply.message_type == MessageType.ERROR:
                        error_name = pair_reply.error_name or ""
                        error_body = str(pair_reply.body) if pair_reply.body else ""
                        if "AlreadyExists" in error_name:
                            _LOGGER.warning(
                                "BLE PAIR: Pair() returned AlreadyExists - device already paired",
                            )
                            return True
                        _LOGGER.warning(
                            "BLE PAIR: Pair() FAILED (with agent): %s %s\n"
                            "  Agent was registered at %s - but pairing still failed.\n"
                            "  Machine moet in 'Verbinden' modus staan!",
                            error_name, error_body, AGENT_PATH,
                        )
                        return False

                    _LOGGER.warning(
                        "BLE PAIR: Pair() SUCCEEDED for %s on %s (with agent)!",
                        self._address, adapter,
                    )

                    await asyncio.sleep(0.5)

                    trust_reply = await bus.call(Message(
                        destination="org.bluez", path=device_path,
                        interface="org.freedesktop.DBus.Properties",
                        member="Set", signature="ssv",
                        body=["org.bluez.Device1", "Trusted", Variant("b", True)],
                    ))
                    if trust_reply.message_type == MessageType.ERROR:
                        _LOGGER.warning("BLE PAIR: Trust set failed (non-fatal): %s", trust_reply.error_name)
                    else:
                        _LOGGER.warning("BLE PAIR: Device trusted")

                    return True

                _LOGGER.warning("BLE PAIR: no adapter found with device %s", self._address)
                return False
            finally:
                if agent_registered:
                    try:
                        unreg_reply = await bus.call(Message(
                            destination="org.bluez", path="/org/bluez",
                            interface="org.bluez.AgentManager1",
                            member="UnregisterAgent",
                            signature="o",
                            body=[AGENT_PATH],
                        ))
                        if unreg_reply.message_type == MessageType.ERROR:
                            _LOGGER.warning("BLE AGENT: UnregisterAgent failed: %s", unreg_reply.error_name)
                        else:
                            _LOGGER.warning("BLE AGENT: unregistered")
                    except Exception as ue:
                        _LOGGER.warning("BLE AGENT: unregister error (non-fatal): %s", ue)
                try:
                    bus.unexport(AGENT_PATH, agent)
                except Exception:
                    pass
                try:
                    bus.disconnect()
                except Exception:
                    pass
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "BLE PAIR: Pair() timed out (30s) for %s.\n"
                "  De machine reageerde niet op het koppelverzoek.\n"
                "  Zorg dat de machine in 'Verbinden' modus staat.",
                self._address,
            )
            self._last_error = (
                "Bluetooth-koppeling verlopen (30s). Zorg dat de machine in 'Verbinden' modus staat "
                "en probeer opnieuw."
            )
            self._notify_callbacks()
            return False
        except ImportError:
            _LOGGER.warning("BLE PAIR: dbus_fast not available - cannot pair")
            return False
        except Exception as err:
            _LOGGER.warning("BLE PAIR: error: %s (%s)", err, type(err).__name__)
            return False

    async def _dbus_check_paired(self) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType, Variant
            import re

            mac_path = self._address.replace(":", "_").upper()
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspect_root = Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_root)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"
                    paired_reply = await asyncio.wait_for(
                        bus.call(Message(
                            destination="org.bluez", path=device_path,
                            interface="org.freedesktop.DBus.Properties",
                            member="Get", signature="ss",
                            body=["org.bluez.Device1", "Paired"],
                        )),
                        timeout=2.0,
                    )
                    if paired_reply.message_type == MessageType.ERROR:
                        continue
                    val = paired_reply.body[0] if paired_reply.body else None
                    if isinstance(val, Variant):
                        val = val.value
                    if bool(val):
                        _LOGGER.warning("BLE PAIR CHECK: device paired on %s", adapter)
                        return True
                return False
            finally:
                try:
                    bus.disconnect()
                except Exception:
                    pass
        except Exception:
            return False

    async def _test_ble_write(self) -> bool:
        if not self._client or not self._is_connected:
            return False

        test_frame = build_frame(CMD_KEEPALIVE, None, b"", encrypt=False)
        try:
            await asyncio.wait_for(
                self._client.write_gatt_char(BLE_WRITE_UUID, test_frame, response=False),
                timeout=3.0,
            )
            _LOGGER.warning("BLE write probe OK - connection is usable")
            return True
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "BLE write probe HUNG (3s) - connection is stale, will disconnect and retry"
            )
            return False
        except Exception as err:
            _LOGGER.warning("BLE write probe FAILED: %s - connection may be stale", err)
            return False

    async def _do_connect(self) -> bool:
        self._cancel_reconnect()

        if self._client is not None:
            _LOGGER.debug("Cleaning up previous BLE client before reconnect")
            await self._internal_disconnect()
            await asyncio.sleep(1.0)

        if self._hass is not None:
            await self._force_bluez_disconnect()

        _LOGGER.info(
            "Connecting to %s (attempt %d)",
            self._address, self._reconnect_attempts + 1,
        )

        try:
            self._status = "connecting"
            self._stop_polling()
            self._notify_callbacks()

            ble_device = await self._get_ble_device()
            if ble_device is None:
                return False

            await self._establish_ble_connection(ble_device)
            self._is_connected = True
            self._reconnect_attempts = 0
            self._last_error = None
            _LOGGER.info("BLE connected to %s", self._address)

            await asyncio.sleep(0.1)

            if not self._is_connected or self._shutting_down:
                _LOGGER.warning("Connection lost during settle for %s", self._address)
                return False

            write_ok = await self._test_ble_write()
            if not write_ok:
                _LOGGER.warning("BLE write probe failed - disconnecting stale connection")
                await self._internal_disconnect()
                await asyncio.sleep(2.0)
                if self._hass is not None:
                    await self._force_bluez_disconnect()
                self._status = "offline"
                self._last_error = "BLE verbinding was niet bruikbaar (stale). Opnieuw proberen..."
                self._notify_callbacks()
                return False

            if self._hass is not None:
                t_pair_start = time.monotonic()
                is_already_paired = await self._dbus_check_paired()
                if is_already_paired:
                    _LOGGER.warning(
                        "BLE PAIR CHECK: device already paired (%.1fms) - doing disconnect+reconnect to activate encrypted BLE link",
                        (time.monotonic() - t_pair_start) * 1000,
                    )
                    self._suppress_disconnect_callback = True
                    try:
                        await self._internal_disconnect()
                    except Exception:
                        pass
                    self._suppress_disconnect_callback = False
                    await asyncio.sleep(1.0)

                    reconnected = await self._internal_reconnect_ble()
                    if not reconnected:
                        await asyncio.sleep(2.0)
                        reconnected = await self._internal_reconnect_ble()
                    if not reconnected:
                        _LOGGER.warning(
                            "BLE PAIR: reconnect after existing bond FAILED - trying without reconnect"
                        )
                    else:
                        _LOGGER.warning(
                            "BLE PAIR: reconnected with encrypted link after existing bond (total=%.1fms)",
                            (time.monotonic() - t_pair_start) * 1000,
                        )
                else:
                    _LOGGER.warning(
                        "BLE PAIR CHECK: device NOT paired (%.1fms) - initiating pairing...\n"
                        "  Machine MOET in 'Verbinden' modus staan!",
                        (time.monotonic() - t_pair_start) * 1000,
                    )
                    pair_ok = await self._dbus_pair_device()
                    t_pair_done = time.monotonic()
                    if pair_ok:
                        _LOGGER.warning(
                            "BLE PAIR: pairing succeeded (%.1fms total).\n"
                            "  Disconnecting and reconnecting to activate encrypted BLE link...",
                            (t_pair_done - t_pair_start) * 1000,
                        )
                        self._suppress_disconnect_callback = True
                        try:
                            await self._internal_disconnect()
                        except Exception:
                            pass
                        self._suppress_disconnect_callback = False
                        await asyncio.sleep(1.0)

                        reconnected = await self._internal_reconnect_ble()
                        if not reconnected:
                            await asyncio.sleep(2.0)
                            reconnected = await self._internal_reconnect_ble()
                        if not reconnected:
                            _LOGGER.warning("BLE PAIR: reconnect after pairing FAILED")
                            return False
                        _LOGGER.warning(
                            "BLE PAIR: reconnected with encrypted link (total=%.1fms)",
                            (time.monotonic() - t_pair_start) * 1000,
                        )
                    else:
                        _LOGGER.warning(
                            "BLE PAIR: pairing FAILED (%.1fms total).\n"
                            "  Ga door met auth zonder pairing (kan werken als machine al eerder gepaird was).",
                            (t_pair_done - t_pair_start) * 1000,
                        )

            self._status = "authenticating"
            self._notify_callbacks()

            pipeline_ok = await self._fast_pipeline_cccd_and_auth()

            if pipeline_ok and self._authenticated:
                pass
            elif not self._authenticated and self._is_connected and not self._shutting_down:
                _LOGGER.warning(
                    "Fast pipeline did not authenticate. Trying traditional flow..."
                )
                notifications_ok = await self._enable_notifications()
                if not notifications_ok:
                    self._notify_mode = "polling"

                if not self._is_connected or self._client is None:
                    _LOGGER.warning("Connection lost during notification setup for %s", self._address)
                    return False

                if not self._shutting_down:
                    await self._authenticate()

            if not self._is_connected:
                _LOGGER.warning("Connection lost during auth for %s", self._address)
                return False

            if self._authenticated:
                self._status = "ready"
                if self._notifications_active:
                    _LOGGER.info(
                        "Auth succeeded with notifications active (mode=%s) - keeping them for responses",
                        self._notify_mode,
                    )
                else:
                    self._notify_mode = "polling"
                    _LOGGER.info("Starting background polling (no notifications available)")
                    self._polling_task = asyncio.ensure_future(self._start_polling())
                self._start_keepalive()
                _LOGGER.warning(
                    "CONNECTED and AUTHENTICATED with %s (mode=%s)",
                    self._address, self._notify_mode,
                )
                await self._request_status()
            else:
                _LOGGER.warning(
                    "Auth failed for %s - trying NUCLEAR option: remove old bond and fresh pair...",
                    self._address,
                )
                self._status = "re_pairing"
                self._last_error = "Auth mislukt met bestaand bond. Oud bond verwijderen en opnieuw koppelen..."
                self._notify_callbacks()

                await self._internal_disconnect()
                await asyncio.sleep(0.5)

                removed = await self._dbus_remove_device()
                if removed:
                    _LOGGER.warning("NUCLEAR: old bond removed. Waiting 2s then fresh pair+connect...")
                    await asyncio.sleep(2.0)

                    ble_device = await self._get_ble_device()
                    if ble_device is None:
                        _LOGGER.warning("NUCLEAR: device not found after RemoveDevice")
                        self._status = "offline"
                        self._last_error = "Apparaat niet gevonden na verwijderen bond"
                        self._notify_callbacks()
                        return False

                    try:
                        await self._establish_ble_connection(ble_device)
                        self._is_connected = True
                        _LOGGER.warning("NUCLEAR: reconnected after RemoveDevice")
                    except Exception as err:
                        _LOGGER.warning("NUCLEAR: reconnect failed: %s", err)
                        self._status = "offline"
                        self._last_error = f"Herverbinding mislukt: {err}"
                        self._notify_callbacks()
                        return False

                    await asyncio.sleep(0.5)

                    pair_ok = await self._dbus_pair_device()
                    if pair_ok:
                        _LOGGER.warning("NUCLEAR: fresh Pair() succeeded! Disconnect+reconnect for encrypted link...")
                        self._suppress_disconnect_callback = True
                        try:
                            await self._internal_disconnect()
                        except Exception:
                            pass
                        self._suppress_disconnect_callback = False
                        await asyncio.sleep(1.0)

                        reconnected = await self._internal_reconnect_ble()
                        if not reconnected:
                            await asyncio.sleep(2.0)
                            reconnected = await self._internal_reconnect_ble()

                        if reconnected:
                            _LOGGER.warning("NUCLEAR: reconnected with fresh bond. Retrying auth...")
                            self._status = "authenticating"
                            self._notify_callbacks()

                            pipeline_ok = await self._fast_pipeline_cccd_and_auth()
                            if pipeline_ok and self._authenticated:
                                self._status = "ready"
                                self._start_keepalive()
                                _LOGGER.warning(
                                    "NUCLEAR: AUTH SUCCEEDED after fresh pair! session_key=%s",
                                    self._session_key.hex() if self._session_key else "None",
                                )
                                await self._request_status()
                                self._notify_callbacks()
                                return True
                            else:
                                _LOGGER.warning("NUCLEAR: auth still failed after fresh pair")
                        else:
                            _LOGGER.warning("NUCLEAR: reconnect after fresh pair failed")
                    else:
                        _LOGGER.warning("NUCLEAR: fresh Pair() failed")
                else:
                    _LOGGER.warning("NUCLEAR: RemoveDevice failed - old bond could not be cleared")

                self._status = "connected_not_auth"
                _LOGGER.warning(
                    "Connected but NOT authenticated to %s - "
                    "machine may need pairing button press (Verbinden modus)",
                    self._address,
                )
                self._last_error = (
                    "Authenticatie mislukt. Zorg dat de machine in 'Verbinden' modus staat "
                    "(blauw knipperend display) en herlaad de integratie."
                )
                if not self._notifications_active:
                    self._notify_mode = "polling"
                    self._polling_task = asyncio.ensure_future(self._start_polling())

            self._notify_callbacks()
            return self._authenticated

        except (BleakError, asyncio.TimeoutError, OSError, EOFError) as err:
            self._status = "offline"
            if isinstance(err, EOFError):
                self._last_error = "Bluetooth D-Bus verbinding verbroken tijdens verbinden"
                _LOGGER.error("CONNECT FAILED (D-Bus EOFError) to %s: %s", self._address, err)
            else:
                self._last_error = f"Verbinding mislukt: {err}"
                _LOGGER.error("CONNECT FAILED to %s: %s", self._address, err)
            self._notify_callbacks()
            return False


    async def _get_ble_device(self):
        if self._hass is not None:
            try:
                from homeassistant.components.bluetooth import async_ble_device_from_address
                ble_device = async_ble_device_from_address(self._hass, self._address, connectable=True)
                if ble_device:
                    _LOGGER.debug("BLEDevice from HA: %s", ble_device.name)
                    return ble_device
                _LOGGER.warning("Device %s not found via HA Bluetooth", self._address)
                self._status = "offline"
                self._last_error = (
                    "Machine niet gevonden via Bluetooth. Controleer of de machine aan staat "
                    "en binnen bereik is."
                )
                self._notify_callbacks()
                return None
            except ImportError:
                _LOGGER.error("HA Bluetooth integration not available")
                self._status = "offline"
                self._last_error = "Bluetooth-integratie niet beschikbaar in Home Assistant"
                self._notify_callbacks()
                return None
            except Exception as err:
                _LOGGER.error("Failed to get BLEDevice: %s", err)
                self._status = "offline"
                self._last_error = f"Bluetooth-fout: {err}"
                self._notify_callbacks()
                return None
        else:
            return self._address

    async def _establish_ble_connection(self, ble_device):
        if self._hass is not None and not isinstance(ble_device, str):
            self._client = await establish_connection(
                BleakClientWithServiceCache,
                ble_device,
                self._name,
                disconnected_callback=self._on_disconnect,
                max_attempts=3,
            )
        else:
            self._client = BleakClient(
                ble_device,
                timeout=CONNECT_TIMEOUT,
                disconnected_callback=self._on_disconnect,
            )
            await self._client.connect()


    async def _try_concurrent_start_notify_auth(
        self,
        p_attempt: int,
        t_cccd_start: float,
        t_pipeline_start: float,
        auth_encrypted: bytes,
    ) -> bool:
        _LOGGER.warning(
            "FAST PIPELINE %d: CONCURRENT start_notify + auth on %s (t=%.1fms since pipeline start)\n"
            "  Strategy: Launch start_notify as background task (writes CCCD),\n"
            "  wait ~50ms for CCCD to reach machine, then send auth immediately.\n"
            "  This matches the APK's atomic CCCD+auth approach.",
            p_attempt, BLE_READ_UUID, (t_cccd_start - t_pipeline_start) * 1000,
        )

        notify_task = asyncio.ensure_future(
            self._client.start_notify(BLE_READ_UUID, self._on_notification)
        )
        t_notify_launched = time.monotonic()
        _LOGGER.warning(
            "FAST PIPELINE %d: start_notify launched as background task (t=%.1fms since CCCD start)",
            p_attempt, (t_notify_launched - t_cccd_start) * 1000,
        )

        try:
            await asyncio.sleep(0.05)
            t_after_delay = time.monotonic()

            if notify_task.done() and notify_task.exception():
                ne = notify_task.exception()
                _LOGGER.warning(
                    "FAST PIPELINE %d: start_notify failed DURING delay: %s (%s). Aborting concurrent approach.",
                    p_attempt, ne, type(ne).__name__,
                )
                return False

            _LOGGER.warning(
                "FAST PIPELINE %d: 50ms delay done (actual=%.1fms). connected=%s, notify_task_done=%s\n"
                "  Now sending auth frame IMMEDIATELY (CCCD should be written to machine by now).",
                p_attempt, (t_after_delay - t_notify_launched) * 1000,
                self._is_connected, notify_task.done(),
            )

            if not self._is_connected or self._client is None:
                _LOGGER.warning(
                    "FAST PIPELINE %d: Connection lost during start_notify delay! Machine entered pairing mode.",
                    p_attempt,
                )
                return False

            self._notifications_active = True
            self._notify_mode = "bleak_start_notify"

            t_auth_write = time.monotonic()
            _LOGGER.warning(
                "FAST PIPELINE %d: Writing encrypted auth frame NOW (t=%.1fms since CCCD start, %.1fms since pipeline start)...",
                p_attempt, (t_auth_write - t_cccd_start) * 1000, (t_auth_write - t_pipeline_start) * 1000,
            )
            self._pipeline_auth_write_time = t_auth_write
            await asyncio.wait_for(
                self._client.write_gatt_char(BLE_WRITE_UUID, auth_encrypted, response=False),
                timeout=3.0,
            )
            t_auth_done = time.monotonic()
            _LOGGER.warning(
                "FAST PIPELINE %d: Auth write OK! (auth_write took %.1fms, total CCCD→auth_done=%.1fms, connected=%s)",
                p_attempt, (t_auth_done - t_auth_write) * 1000,
                (t_auth_done - t_cccd_start) * 1000, self._is_connected,
            )

            self._suppress_disconnect_callback = False

            self._status = "waiting_for_machine_button"
            self._last_error = (
                "Auth-frame verstuurd! Druk NU op 'Verbinden' op het display van het koffieapparaat."
            )
            self._notify_callbacks()

            await self._pipeline_wait_for_auth(p_attempt)

            if self._authenticated:
                t_success = time.monotonic()
                _LOGGER.warning(
                    "=== FAST PIPELINE %d: AUTH SUCCEEDED (concurrent start_notify+auth)! ===\n"
                    "  method=bleak_start_notify, total_pipeline_time=%.1fms\n"
                    "  session_key=%s",
                    p_attempt,
                    (t_success - t_pipeline_start) * 1000,
                    self._session_key.hex() if self._session_key else "None",
                )
                return True

            if self._auth_got_frame and not self._authenticated:
                _LOGGER.warning(
                    "FAST PIPELINE %d: Got frame but encrypted auth failed. Trying plaintext...",
                    p_attempt,
                )
                if self._is_connected and self._client is not None:
                    self._auth_challenge = os.urandom(4)
                    challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
                    auth_payload2 = self._auth_challenge + challenge_hash
                    auth_plaintext2 = build_frame(CMD_AUTH, None, auth_payload2, encrypt=False)
                    self._auth_event.clear()
                    self._auth_got_frame = False
                    try:
                        await asyncio.wait_for(
                            self._client.write_gatt_char(BLE_WRITE_UUID, auth_plaintext2, response=False),
                            timeout=3.0,
                        )
                        await self._pipeline_wait_for_auth(p_attempt)
                        if self._authenticated:
                            _LOGGER.warning(
                                "=== FAST PIPELINE %d: AUTH SUCCEEDED (plaintext after concurrent)! ===\n"
                                "  total_pipeline_time=%.1fms, session_key=%s",
                                p_attempt, (time.monotonic() - t_pipeline_start) * 1000,
                                self._session_key.hex() if self._session_key else "None",
                            )
                            return True
                    except Exception as pt_err:
                        _LOGGER.warning("FAST PIPELINE %d: plaintext auth error: %s", p_attempt, pt_err)

            if not self._is_connected:
                _LOGGER.warning(
                    "FAST PIPELINE %d: disconnected during concurrent auth wait.\n"
                    "  disconnect_reason=%s",
                    p_attempt, self._auth_disconnect_reason,
                )
            else:
                _LOGGER.warning(
                    "FAST PIPELINE %d: no auth response from concurrent approach.",
                    p_attempt,
                )
            return False

        finally:
            if not notify_task.done():
                notify_task.cancel()
            try:
                await notify_task
            except (asyncio.CancelledError, Exception):
                pass
            if not self._authenticated:
                self._notifications_active = False
                self._notify_mode = None

    async def _fast_pipeline_cccd_and_auth(self) -> bool:
        t_pipeline_start = time.monotonic()
        _LOGGER.warning(
            "=== FAST PIPELINE: CCCD + AUTH in one atomic operation ===\n"
            "  Strategy: Register D-Bus handler FIRST, then write CCCD + auth\n"
            "  within the machine's ~370ms disconnect window.\n"
            "  3 pipeline attempts with different CCCD methods.\n"
            "  TIMER START: t=0ms"
        )

        if not self._client or not self._is_connected:
            _LOGGER.warning("FAST PIPELINE: no connection (elapsed=%.1fms)", (time.monotonic() - t_pipeline_start) * 1000)
            return False

        read_char_path = await self._get_char_dbus_path_async(BLE_READ_UUID)
        _LOGGER.warning(
            "FAST PIPELINE: char_path lookup took %.1fms, path=%s",
            (time.monotonic() - t_pipeline_start) * 1000, read_char_path,
        )

        dbus_ok = False
        cccd_confirmed = False
        if read_char_path and self._hass is not None:
            t_dbus_reg = time.monotonic()
            dbus_ok = await self._register_dbus_notification_handler(read_char_path)
            _LOGGER.warning(
                "FAST PIPELINE: D-Bus handler registration took %.1fms, ok=%s",
                (time.monotonic() - t_dbus_reg) * 1000, dbus_ok,
            )
            if dbus_ok:
                _LOGGER.warning("FAST PIPELINE: D-Bus notification handler registered BEFORE CCCD write (total elapsed=%.1fms)", (time.monotonic() - t_pipeline_start) * 1000)
                self._notifications_active = True
                self._notify_mode = "dbus_handler_only"

                t_start_notify = time.monotonic()
                sn_ok = await self._dbus_start_notify_on_char(read_char_path)
                t_sn_done = time.monotonic()

                notifying = await self._dbus_check_notifying(read_char_path)
                cccd_confirmed = sn_ok or notifying

                if sn_ok:
                    _LOGGER.warning(
                        "FAST PIPELINE: D-Bus StartNotify OK (%.1fms) - CCCD written! Notifying=%s",
                        (t_sn_done - t_start_notify) * 1000, notifying,
                    )
                elif notifying:
                    _LOGGER.warning(
                        "FAST PIPELINE: D-Bus StartNotify failed (%.1fms) but Notifying=True - CCCD already active!",
                        (t_sn_done - t_start_notify) * 1000,
                    )
                else:
                    _LOGGER.warning(
                        "FAST PIPELINE: D-Bus StartNotify failed (%.1fms) and Notifying=False.\n"
                        "  CCCD NOT confirmed. Skipping D-Bus auth path, will use pipeline methods.",
                        (t_sn_done - t_start_notify) * 1000,
                    )

                if cccd_confirmed and self._is_connected and self._client is not None:
                    auth_payload = self._build_auth_payload()
                    auth_encrypted = build_frame(CMD_AUTH, None, auth_payload, encrypt=True)

                    t_auth_w = time.monotonic()
                    _LOGGER.warning(
                        "FAST PIPELINE: D-Bus path - writing auth immediately (t=%.1fms since pipeline start)...",
                        (t_auth_w - t_pipeline_start) * 1000,
                    )
                    self._pipeline_auth_write_time = t_auth_w
                    try:
                        await asyncio.wait_for(
                            self._client.write_gatt_char(BLE_WRITE_UUID, auth_encrypted, response=False),
                            timeout=3.0,
                        )
                        t_auth_d = time.monotonic()
                        _LOGGER.warning(
                            "FAST PIPELINE: D-Bus path auth write OK (%.1fms, total=%.1fms since pipeline)",
                            (t_auth_d - t_auth_w) * 1000, (t_auth_d - t_pipeline_start) * 1000,
                        )

                        self._status = "waiting_for_machine_button"
                        self._last_error = (
                            "Auth-frame verstuurd! Druk NU op 'Verbinden' op het display van het koffieapparaat."
                        )
                        self._notify_callbacks()

                        await self._pipeline_wait_for_auth(0)

                        if self._authenticated:
                            _LOGGER.warning(
                                "=== FAST PIPELINE: AUTH SUCCEEDED (D-Bus StartNotify + auth)! ===\n"
                                "  total_pipeline_time=%.1fms, session_key=%s",
                                (time.monotonic() - t_pipeline_start) * 1000,
                                self._session_key.hex() if self._session_key else "None",
                            )
                            return True

                        if self._auth_got_frame and not self._authenticated:
                            _LOGGER.warning(
                                "FAST PIPELINE: D-Bus path got frame but encrypted auth failed. Trying plaintext..."
                            )
                            self._auth_challenge = os.urandom(4)
                            challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
                            auth_payload2 = self._auth_challenge + challenge_hash
                            auth_plaintext2 = build_frame(CMD_AUTH, None, auth_payload2, encrypt=False)
                            self._auth_event.clear()
                            self._auth_got_frame = False
                            try:
                                await asyncio.wait_for(
                                    self._client.write_gatt_char(BLE_WRITE_UUID, auth_plaintext2, response=False),
                                    timeout=3.0,
                                )
                                await self._pipeline_wait_for_auth(0)
                                if self._authenticated:
                                    _LOGGER.warning(
                                        "=== FAST PIPELINE: AUTH SUCCEEDED (D-Bus + plaintext)! ===\n"
                                        "  total=%.1fms, session_key=%s",
                                        (time.monotonic() - t_pipeline_start) * 1000,
                                        self._session_key.hex() if self._session_key else "None",
                                    )
                                    return True
                            except Exception as pt_err:
                                _LOGGER.warning("FAST PIPELINE: D-Bus path plaintext auth error: %s", pt_err)

                        _LOGGER.warning(
                            "FAST PIPELINE: D-Bus path auth failed (got_frame=%s, connected=%s). Falling through to pipeline methods.",
                            self._auth_got_frame, self._is_connected,
                        )
                    except Exception as auth_err:
                        _LOGGER.warning(
                            "FAST PIPELINE: D-Bus path auth write error: %s (%s). Falling through to pipeline methods.",
                            auth_err, type(auth_err).__name__,
                        )
            else:
                _LOGGER.warning("FAST PIPELINE: D-Bus handler registration failed, will use polling")

        if dbus_ok and cccd_confirmed:
            pipeline_methods = [
                "auth_only_no_cccd",
            ]
            _LOGGER.warning(
                "FAST PIPELINE: D-Bus CCCD confirmed (Notifying=True), skipping CCCD methods.\n"
                "  Only trying auth_only_no_cccd as fallback.",
            )
        else:
            pipeline_methods = [
                "bleak_start_notify",
                "direct_cccd_descriptor",
                "auth_only_no_cccd",
            ]

        for p_attempt, method in enumerate(pipeline_methods, 1):
            t_attempt_start = time.monotonic()
            if self._shutting_down:
                return False

            if self._authenticated:
                return True

            if not self._is_connected or self._client is None:
                t_reconn = time.monotonic()
                _LOGGER.warning(
                    "FAST PIPELINE attempt %d: no connection, reconnecting... (pipeline elapsed=%.1fms)",
                    p_attempt, (t_reconn - t_pipeline_start) * 1000,
                )
                reconnected = await self._internal_reconnect_ble()
                if not reconnected:
                    await asyncio.sleep(2.0)
                    reconnected = await self._internal_reconnect_ble()
                _LOGGER.warning(
                    "FAST PIPELINE attempt %d: reconnect %s (took %.1fms)",
                    p_attempt, "OK" if reconnected else "FAILED",
                    (time.monotonic() - t_reconn) * 1000,
                )
                if not reconnected:
                    continue

                new_char_path = await self._get_char_dbus_path_async(BLE_READ_UUID)
                if new_char_path:
                    read_char_path = new_char_path
                if read_char_path and self._hass is not None:
                    if self._dbus_notify_bus is not None:
                        try:
                            if self._dbus_notify_handler:
                                self._dbus_notify_bus.remove_message_handler(self._dbus_notify_handler)
                            self._dbus_notify_bus.disconnect()
                        except Exception:
                            pass
                        self._dbus_notify_bus = None
                        self._dbus_notify_handler = None
                        self._dbus_match_rule = None
                    t_re_dbus = time.monotonic()
                    dbus_ok = await self._register_dbus_notification_handler(read_char_path)
                    _LOGGER.warning(
                        "FAST PIPELINE attempt %d: D-Bus re-registration took %.1fms, ok=%s",
                        p_attempt, (time.monotonic() - t_re_dbus) * 1000, dbus_ok,
                    )
                    if dbus_ok:
                        self._notifications_active = True
                        self._notify_mode = "dbus_handler_only"

            auth_payload = self._build_auth_payload()
            auth_encrypted = build_frame(CMD_AUTH, None, auth_payload, encrypt=True)
            auth_plaintext = build_frame(CMD_AUTH, None, auth_payload, encrypt=False)

            _LOGGER.warning(
                "=== FAST PIPELINE ATTEMPT %d/%d: method=%s ===\n"
                "  auth_encrypted=%s (%d bytes)\n"
                "  auth_plaintext=%s (%d bytes)\n"
                "  connected=%s, notifications=%s, notify_mode=%s\n"
                "  pipeline_elapsed=%.1fms, attempt_elapsed=%.1fms\n"
                "  challenge=%s",
                p_attempt, len(pipeline_methods), method,
                auth_encrypted.hex(), len(auth_encrypted),
                auth_plaintext.hex(), len(auth_plaintext),
                self._is_connected, self._notifications_active, self._notify_mode,
                (time.monotonic() - t_pipeline_start) * 1000,
                (time.monotonic() - t_attempt_start) * 1000,
                self._auth_challenge.hex() if self._auth_challenge else "None",
            )

            self._auth_event.clear()
            self._auth_got_frame = False
            self._auth_disconnect_reason = None
            self._authenticated = False
            self._status = "authenticating"

            self._suppress_disconnect_callback = True
            cccd_ok = False
            t_cccd_start = time.monotonic()
            try:
                if method == "bleak_start_notify":
                    try:
                        concurrent_result = await self._try_concurrent_start_notify_auth(
                            p_attempt, t_cccd_start, t_pipeline_start, auth_encrypted,
                        )
                        if concurrent_result:
                            return True
                    except Exception as conc_err:
                        _LOGGER.warning(
                            "FAST PIPELINE %d: concurrent start_notify+auth unexpected error: %s (%s)",
                            p_attempt, conc_err, type(conc_err).__name__,
                        )
                    await asyncio.sleep(1.0)
                    continue

                elif method == "direct_cccd_descriptor":
                    _LOGGER.warning(
                        "FAST PIPELINE %d: Direct CCCD descriptor write (t=%.1fms since pipeline start)",
                        p_attempt, (t_cccd_start - t_pipeline_start) * 1000,
                    )
                    try:
                        read_char = self._client.services.get_characteristic(BLE_READ_UUID)
                        if read_char:
                            cccd_uuid = "00002902-0000-1000-8000-00805f9b34fb"
                            cccd_desc = None
                            for desc in read_char.descriptors:
                                if cccd_uuid in str(desc.uuid).lower():
                                    cccd_desc = desc
                                    break
                            if cccd_desc:
                                t_desc_write = time.monotonic()
                                await asyncio.wait_for(
                                    self._client.write_gatt_descriptor(cccd_desc.handle, b"\x01\x00"),
                                    timeout=1.0,
                                )
                                t_cccd_done = time.monotonic()
                                cccd_ok = True
                                _LOGGER.warning(
                                    "FAST PIPELINE %d: CCCD descriptor write OK (handle=%d, took %.1fms, connected=%s)",
                                    p_attempt, cccd_desc.handle,
                                    (t_cccd_done - t_desc_write) * 1000, self._is_connected,
                                )
                            else:
                                _LOGGER.warning(
                                    "FAST PIPELINE %d: CCCD descriptor (0x2902) not found on char %s.\n"
                                    "  Available descriptors: %s",
                                    p_attempt, BLE_READ_UUID,
                                    [(str(d.uuid), d.handle) for d in read_char.descriptors] if read_char.descriptors else "none",
                                )
                        else:
                            _LOGGER.warning(
                                "FAST PIPELINE %d: read characteristic %s not found in services.\n"
                                "  Available chars: %s",
                                p_attempt, BLE_READ_UUID,
                                [str(c.uuid) for s in self._client.services for c in s.characteristics][:10] if self._client.services else "none",
                            )
                    except (EOFError, OSError, BleakError) as cccd_err:
                        t_cccd_done = time.monotonic()
                        _LOGGER.warning(
                            "FAST PIPELINE %d: CCCD write error after %.1fms: %s (%s). Trying auth anyway...",
                            p_attempt, (t_cccd_done - t_cccd_start) * 1000,
                            cccd_err, type(cccd_err).__name__,
                        )
                        cccd_ok = True

                elif method == "auth_only_no_cccd":
                    _LOGGER.warning(
                        "FAST PIPELINE %d: Skipping CCCD entirely - sending auth without CCCD.\n"
                        "  Machine may have CCCD from previous connection or may accept auth directly.\n"
                        "  pipeline_elapsed=%.1fms",
                        p_attempt, (time.monotonic() - t_pipeline_start) * 1000,
                    )
                    cccd_ok = True

            except Exception as err:
                _LOGGER.warning(
                    "FAST PIPELINE %d: CCCD method error after %.1fms: %s (%s)",
                    p_attempt, (time.monotonic() - t_cccd_start) * 1000,
                    err, type(err).__name__,
                )
            finally:
                self._suppress_disconnect_callback = False

            t_after_cccd = time.monotonic()
            cccd_elapsed_ms = (t_after_cccd - t_cccd_start) * 1000

            if not self._is_connected or self._client is None:
                _LOGGER.warning(
                    "FAST PIPELINE %d: CONNECTION LOST during CCCD (method=%s, cccd_took=%.1fms).\n"
                    "  Machine likely entered pairing mode (blue display).\n"
                    "  This is EXPECTED for method 1 - machine disconnects after CCCD.",
                    p_attempt, method, cccd_elapsed_ms,
                )
                await asyncio.sleep(2.0)
                continue

            if not cccd_ok and method != "auth_only_no_cccd":
                _LOGGER.warning(
                    "FAST PIPELINE %d: CCCD method %s failed without disconnect (took %.1fms). Trying next method.",
                    p_attempt, method, cccd_elapsed_ms,
                )
                continue

            _LOGGER.warning(
                "FAST PIPELINE %d: CCCD done, connection ALIVE! Gap CCCD→auth: %.1fms (target: <370ms)",
                p_attempt, cccd_elapsed_ms,
            )

            t_auth_write = time.monotonic()
            try:
                _LOGGER.warning(
                    "FAST PIPELINE %d: Writing encrypted auth frame NOW (t=%.1fms since CCCD start, %.1fms since pipeline start)...",
                    p_attempt, (t_auth_write - t_cccd_start) * 1000, (t_auth_write - t_pipeline_start) * 1000,
                )
                self._pipeline_auth_write_time = t_auth_write
                await asyncio.wait_for(
                    self._client.write_gatt_char(BLE_WRITE_UUID, auth_encrypted, response=False),
                    timeout=3.0,
                )
                t_auth_done = time.monotonic()
                _LOGGER.warning(
                    "FAST PIPELINE %d: Auth write OK! (auth_write took %.1fms, total CCCD→auth_done=%.1fms, connected=%s)",
                    p_attempt, (t_auth_done - t_auth_write) * 1000,
                    (t_auth_done - t_cccd_start) * 1000, self._is_connected,
                )
            except Exception as auth_err:
                t_auth_fail = time.monotonic()
                _LOGGER.warning(
                    "FAST PIPELINE %d: auth write FAILED after %.1fms: %s (%s)\n"
                    "  connected=%s, total_elapsed=%.1fms",
                    p_attempt, (t_auth_fail - t_auth_write) * 1000,
                    auth_err, type(auth_err).__name__,
                    self._is_connected, (t_auth_fail - t_pipeline_start) * 1000,
                )
                await asyncio.sleep(2.0)
                continue

            self._status = "waiting_for_machine_button"
            self._last_error = (
                "Auth-frame verstuurd! Druk NU op 'Verbinden' op het display van het koffieapparaat."
            )
            self._notify_callbacks()

            got_response = await self._pipeline_wait_for_auth(p_attempt)

            if self._authenticated:
                t_success = time.monotonic()
                _LOGGER.warning(
                    "=== FAST PIPELINE %d: AUTH SUCCEEDED! ===\n"
                    "  method=%s, total_pipeline_time=%.1fms\n"
                    "  session_key=%s",
                    p_attempt, method,
                    (t_success - t_pipeline_start) * 1000,
                    self._session_key.hex() if self._session_key else "None",
                )
                return True

            if self._auth_got_frame and not self._authenticated:
                _LOGGER.warning(
                    "FAST PIPELINE %d: Got frame but encrypted auth failed. Trying plaintext...\n"
                    "  pipeline_elapsed=%.1fms",
                    p_attempt, (time.monotonic() - t_pipeline_start) * 1000,
                )
                if self._is_connected and self._client is not None:
                    self._auth_challenge = os.urandom(4)
                    challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
                    auth_payload2 = self._auth_challenge + challenge_hash
                    auth_plaintext2 = build_frame(CMD_AUTH, None, auth_payload2, encrypt=False)
                    self._auth_event.clear()
                    self._auth_got_frame = False
                    try:
                        await asyncio.wait_for(
                            self._client.write_gatt_char(BLE_WRITE_UUID, auth_plaintext2, response=False),
                            timeout=3.0,
                        )
                        got_pt = await self._pipeline_wait_for_auth(p_attempt)
                        if self._authenticated:
                            _LOGGER.warning(
                                "=== FAST PIPELINE %d: AUTH SUCCEEDED (plaintext)! ===\n"
                                "  total_pipeline_time=%.1fms, session_key=%s",
                                p_attempt, (time.monotonic() - t_pipeline_start) * 1000,
                                self._session_key.hex() if self._session_key else "None",
                            )
                            return True
                    except Exception as pt_err:
                        _LOGGER.warning("FAST PIPELINE %d: plaintext auth error: %s", p_attempt, pt_err)

            if not self._is_connected:
                _LOGGER.warning(
                    "FAST PIPELINE %d: disconnected during auth wait (method=%s).\n"
                    "  disconnect_reason=%s",
                    p_attempt, method, self._auth_disconnect_reason,
                )
            else:
                _LOGGER.warning(
                    "FAST PIPELINE %d: no auth response (method=%s). Will try next method.",
                    p_attempt, method,
                )

            await asyncio.sleep(1.0)

        _LOGGER.warning("=== FAST PIPELINE: all %d attempts exhausted ===", len(pipeline_methods))
        return False

    def _build_auth_payload(self) -> bytes:
        self._auth_challenge = os.urandom(4)
        challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
        return self._auth_challenge + challenge_hash

    async def _pipeline_wait_for_auth(self, attempt: int) -> bool:
        t_wait_start = time.monotonic()
        _LOGGER.warning(
            "FAST PIPELINE %d: Waiting for auth response (%.0fs timeout)\n"
            "  notify_mode=%s, notifications_active=%s\n"
            "  auth_write_time=%s\n"
            "  Druk op 'Verbinden' op het koffieapparaat!",
            attempt, AUTH_TIMEOUT, self._notify_mode, self._notifications_active,
            "set" if getattr(self, '_pipeline_auth_write_time', None) else "not_set",
        )

        client = self._client
        if client is None:
            return False

        poll_interval = 0.15
        max_polls = int(AUTH_TIMEOUT / poll_interval)
        last_data = None

        for i in range(max_polls):
            t_poll = time.monotonic()
            wait_elapsed_ms = (t_poll - t_wait_start) * 1000

            if self._authenticated or self._auth_got_frame:
                _LOGGER.warning(
                    "FAST PIPELINE %d WAIT [#%d]: AUTH RESULT! authenticated=%s, got_frame=%s (waited %.1fms)",
                    attempt, i + 1, self._authenticated, self._auth_got_frame, wait_elapsed_ms,
                )
                return True

            if self._auth_event.is_set():
                _LOGGER.warning(
                    "FAST PIPELINE %d WAIT [#%d]: auth_event SET! (waited %.1fms)",
                    attempt, i + 1, wait_elapsed_ms,
                )
                return True

            if not self._is_connected or self._client is None:
                _LOGGER.warning(
                    "FAST PIPELINE %d WAIT [#%d]: CONNECTION LOST after %.1fms of waiting\n"
                    "  disconnect_reason=%s",
                    attempt, i + 1, wait_elapsed_ms,
                    self._auth_disconnect_reason,
                )
                return False

            try:
                data = await asyncio.wait_for(
                    client.read_gatt_char(BLE_READ_UUID),
                    timeout=2.0,
                )
                if data and len(data) > 0 and data != last_data:
                    _LOGGER.warning(
                        "FAST PIPELINE %d POLL [#%d]: NEW data %d bytes (waited %.1fms)\n"
                        "  hex=%s\n"
                        "  raw_bytes=[%s]\n"
                        "  first_byte=0x%02x, last_byte=0x%02x",
                        attempt, i + 1, len(data), wait_elapsed_ms,
                        data.hex(),
                        " ".join(f"0x{b:02x}" for b in data),
                        data[0], data[-1],
                    )
                    last_data = data
                    self._process_incoming_data(data)
                    if self._authenticated or self._auth_event.is_set():
                        _LOGGER.warning(
                            "FAST PIPELINE %d POLL [#%d]: Auth succeeded after processing! (total wait %.1fms)",
                            attempt, i + 1, (time.monotonic() - t_wait_start) * 1000,
                        )
                        return True
                elif i < 3 or i % 20 == 0:
                    _LOGGER.warning(
                        "FAST PIPELINE %d WAIT [#%d/%.0f]: still waiting... (%.1fms elapsed, connected=%s, same_data=%s)",
                        attempt, i + 1, max_polls, wait_elapsed_ms, self._is_connected,
                        "yes" if data == last_data else "no/empty",
                    )
            except asyncio.TimeoutError:
                if i < 3 or i % 20 == 0:
                    _LOGGER.warning(
                        "FAST PIPELINE %d WAIT [#%d]: read timeout (%.1fms elapsed, connected=%s)",
                        attempt, i + 1, wait_elapsed_ms, self._is_connected,
                    )
            except (BleakError, EOFError) as err:
                _LOGGER.warning(
                    "FAST PIPELINE %d WAIT [#%d]: BLE read error after %.1fms: %s (%s)",
                    attempt, i + 1, wait_elapsed_ms, err, type(err).__name__,
                )
                return False
            except Exception as err:
                _LOGGER.warning(
                    "FAST PIPELINE %d WAIT [#%d]: unexpected error after %.1fms: %s: %s",
                    attempt, i + 1, wait_elapsed_ms, type(err).__name__, err,
                )

            await asyncio.sleep(poll_interval)

        _LOGGER.warning(
            "FAST PIPELINE %d: auth wait TIMEOUT after %.1fms (%.0fs configured)\n"
            "  connected=%s, authenticated=%s, got_frame=%s, disconnect_reason=%s",
            attempt, (time.monotonic() - t_wait_start) * 1000, AUTH_TIMEOUT,
            self._is_connected, self._authenticated, self._auth_got_frame,
            self._auth_disconnect_reason,
        )
        return False

    async def _enable_notifications(self):
        if not self._client or not self._is_connected:
            _LOGGER.warning("NOTIFICATIONS: Cannot enable - no client/connection")
            return False

        _LOGGER.warning(
            "=== ENABLING NOTIFICATIONS on %s ===\n"
            "  Strategy: start_notify (CCCD write) with disconnect recovery.\n"
            "  CCCD write is REQUIRED for machine to enter pairing mode (blue display).\n"
            "  If machine disconnects after CCCD, we reconnect and retry.\n"
            "  hass=%s, connected=%s, client=%s",
            BLE_READ_UUID, self._hass is not None, self._is_connected, type(self._client).__name__,
        )

        notify_result = await self._start_notify_with_recovery()

        if notify_result == "bleak_notify":
            self._notifications_active = True
            self._notify_mode = "bleak_notify"
            _LOGGER.warning(
                "=== NOTIFICATIONS ACTIVE on %s (mode=bleak_notify) ===",
                BLE_READ_UUID,
            )

            if self._hass is not None:
                read_char_path = await self._get_char_dbus_path_async(BLE_READ_UUID)
                if read_char_path:
                    await self._register_dbus_notification_handler(read_char_path)
                    _LOGGER.warning("D-Bus handler also registered as backup")

            return True

        if notify_result == "direct_cccd":
            _LOGGER.warning(
                "=== CCCD written directly (bleak callback NOT registered) ===\n"
                "  D-Bus handler will be PRIMARY for notifications."
            )
            if self._hass is not None:
                read_char_path = await self._get_char_dbus_path_async(BLE_READ_UUID)
                if read_char_path:
                    dbus_ok = await self._register_dbus_notification_handler(read_char_path)
                    if dbus_ok:
                        self._notifications_active = True
                        self._notify_mode = "dbus_direct_cccd"
                        _LOGGER.warning(
                            "=== NOTIFICATIONS ACTIVE on %s (mode=dbus_direct_cccd) ===",
                            BLE_READ_UUID,
                        )
                        return True
            _LOGGER.warning("CCCD written but D-Bus handler registration failed. Using polling.")
            self._notifications_active = False
            self._notify_mode = "polling_only"
            return False

        _LOGGER.warning(
            "NOTIFICATIONS: start_notify failed after recovery attempts.\n"
            "  Falling back to polling only."
        )

        if self._hass is not None:
            read_char_path = await self._get_char_dbus_path_async(BLE_READ_UUID)
            if read_char_path:
                dbus_ok = await self._register_dbus_notification_handler(read_char_path)
                if dbus_ok:
                    self._notifications_active = True
                    self._notify_mode = "dbus_handler_only"
                    _LOGGER.warning("Fallback: D-Bus handler registered (polling is primary)")
                    return True

        self._notifications_active = False
        self._notify_mode = "polling_only"
        return False

    async def _dbus_stop_notify_on_char(self, char_path: str) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType

            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                stop_msg = Message(
                    destination="org.bluez",
                    path=char_path,
                    interface="org.bluez.GattCharacteristic1",
                    member="StopNotify",
                )
                reply = await bus.call(stop_msg)
                if reply.message_type == MessageType.ERROR:
                    _LOGGER.warning(
                        "D-Bus StopNotify on %s: %s %s",
                        char_path, reply.error_name, reply.body,
                    )
                    return False
                _LOGGER.warning("D-Bus StopNotify on %s: OK", char_path)
                return True
            finally:
                bus.disconnect()
        except ImportError:
            _LOGGER.warning("dbus_fast not available for D-Bus StopNotify")
            return False
        except Exception as err:
            _LOGGER.warning("D-Bus StopNotify error: %s (%s)", err, type(err).__name__)
            return False

    async def _dbus_check_notifying(self, char_path: str) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType, Variant

            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                get_msg = Message(
                    destination="org.bluez",
                    path=char_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Get",
                    signature="ss",
                    body=["org.bluez.GattCharacteristic1", "Notifying"],
                )
                reply = await asyncio.wait_for(bus.call(get_msg), timeout=1.0)
                if reply.message_type == MessageType.ERROR:
                    _LOGGER.warning("D-Bus Notifying check error: %s %s", reply.error_name, reply.body)
                    return False
                val = reply.body[0] if reply.body else None
                if isinstance(val, Variant):
                    val = val.value
                result = bool(val)
                _LOGGER.warning("D-Bus Notifying property on %s: %s", char_path, result)
                return result
            finally:
                try:
                    bus.disconnect()
                except Exception:
                    pass
        except Exception as err:
            _LOGGER.warning("D-Bus Notifying check failed: %s (%s)", err, type(err).__name__)
            return False

    async def _dbus_start_notify_on_char(self, char_path: str) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType

            t_start = time.monotonic()
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                start_msg = Message(
                    destination="org.bluez",
                    path=char_path,
                    interface="org.bluez.GattCharacteristic1",
                    member="StartNotify",
                )
                try:
                    reply = await asyncio.wait_for(bus.call(start_msg), timeout=1.0)
                except asyncio.TimeoutError:
                    elapsed = (time.monotonic() - t_start) * 1000
                    _LOGGER.warning(
                        "D-Bus StartNotify on %s: TIMEOUT after %.1fms (machine likely disconnected during CCCD write).\n"
                        "  This is expected - machine enters pairing mode after CCCD.\n"
                        "  connected=%s",
                        char_path, elapsed, self._is_connected,
                    )
                    return False
                if reply.message_type == MessageType.ERROR:
                    elapsed = (time.monotonic() - t_start) * 1000
                    _LOGGER.warning(
                        "D-Bus StartNotify on %s: ERROR after %.1fms: %s %s",
                        char_path, elapsed, reply.error_name, reply.body,
                    )
                    return False
                elapsed = (time.monotonic() - t_start) * 1000
                _LOGGER.warning(
                    "D-Bus StartNotify on %s: OK after %.1fms - CCCD written to machine via D-Bus!\n"
                    "  Notifications will arrive via PropertiesChanged signals.",
                    char_path, elapsed,
                )
                return True
            finally:
                try:
                    bus.disconnect()
                except Exception:
                    pass
        except ImportError:
            _LOGGER.warning("dbus_fast not available for D-Bus StartNotify")
            return False
        except Exception as err:
            elapsed = (time.monotonic() - t_start) * 1000
            _LOGGER.warning("D-Bus StartNotify error after %.1fms: %s (%s)", elapsed, err, type(err).__name__)
            return False

    async def _dbus_remove_device(self) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType
            import re

            mac_path = self._address.replace(":", "_").upper()
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspect_root = Message(
                    destination="org.bluez", path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_root)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"
                    remove_msg = Message(
                        destination="org.bluez",
                        path=f"/org/bluez/{adapter}",
                        interface="org.bluez.Adapter1",
                        member="RemoveDevice",
                        signature="o",
                        body=[device_path],
                    )
                    rm_reply = await bus.call(remove_msg)
                    if rm_reply.message_type == MessageType.ERROR:
                        _LOGGER.warning(
                            "D-Bus RemoveDevice %s on %s: %s %s",
                            device_path, adapter, rm_reply.error_name, rm_reply.body,
                        )
                    else:
                        _LOGGER.warning(
                            "D-Bus RemoveDevice %s on %s: OK - device fully removed from BlueZ!",
                            device_path, adapter,
                        )
                        return True
            finally:
                bus.disconnect()
        except ImportError:
            _LOGGER.warning("dbus_fast not available for D-Bus RemoveDevice")
        except Exception as err:
            _LOGGER.warning("D-Bus RemoveDevice error: %s (%s)", err, type(err).__name__)
        return False

    async def _start_notify_with_recovery(self) -> str:
        max_cccd_attempts = 5
        self._cccd_recovery_in_progress = True

        try:
            for attempt in range(1, max_cccd_attempts + 1):
                if not self._client or not self._is_connected:
                    _LOGGER.warning("CCCD attempt %d: no connection", attempt)
                    return "failed"

                if self._shutting_down:
                    _LOGGER.warning("CCCD attempt %d: shutting down", attempt)
                    return "failed"

                _LOGGER.warning(
                    "=== CCCD ATTEMPT %d/%d: calling start_notify on %s ===",
                    attempt, max_cccd_attempts, BLE_READ_UUID,
                )

                char_path = await self._get_char_dbus_path_async(BLE_READ_UUID)
                if char_path:
                    _LOGGER.warning(
                        "CCCD ATTEMPT %d: Pre-clearing BlueZ notify state via D-Bus StopNotify on %s",
                        attempt, char_path,
                    )
                    await self._dbus_stop_notify_on_char(char_path)
                    await asyncio.sleep(0.3)

                cccd_disconnect_detected = False
                cccd_written_ok = False
                cccd_via_direct_write = False
                notify_acquired_handled = False

                self._suppress_disconnect_callback = True
                try:
                    try:
                        await asyncio.wait_for(
                            self._client.start_notify(BLE_READ_UUID, self._notification_callback),
                            timeout=3.0,
                        )
                        cccd_written_ok = True
                    except asyncio.TimeoutError:
                        _LOGGER.warning("CCCD ATTEMPT %d: start_notify timed out (3s)", attempt)
                    except BleakError as err:
                        err_str = str(err).lower()
                        if "notify acquired" in err_str or "notpermitted" in err_str:
                            notify_acquired_handled = True
                            _LOGGER.warning(
                                "CCCD ATTEMPT %d: 'Notify acquired' - BlueZ cached old state.\n"
                                "  No CCCD written to machine! Trying stop_notify + retry, then direct write.",
                                attempt,
                            )
                            try:
                                await self._client.stop_notify(BLE_READ_UUID)
                                _LOGGER.warning("CCCD ATTEMPT %d: stop_notify cleared cached state", attempt)
                            except Exception as sn_err:
                                _LOGGER.warning("CCCD ATTEMPT %d: stop_notify: %s", attempt, sn_err)
                            await asyncio.sleep(0.3)
                            try:
                                await asyncio.wait_for(
                                    self._client.start_notify(BLE_READ_UUID, self._notification_callback),
                                    timeout=3.0,
                                )
                                cccd_written_ok = True
                                _LOGGER.warning("CCCD ATTEMPT %d: start_notify retry after stop OK!", attempt)
                            except (EOFError, OSError) as retry_err:
                                cccd_disconnect_detected = True
                                _LOGGER.warning("CCCD ATTEMPT %d: retry caused disconnect (good - CCCD was written): %s", attempt, retry_err)
                            except BleakError as retry_err:
                                retry_str = str(retry_err).lower()
                                if any(w in retry_str for w in ("not connected", "disconnected", "disconnect")):
                                    cccd_disconnect_detected = True
                                    _LOGGER.warning("CCCD ATTEMPT %d: retry disconnect: %s", attempt, retry_err)
                                else:
                                    _LOGGER.warning("CCCD ATTEMPT %d: retry still blocked: %s", attempt, retry_err)
                            except asyncio.TimeoutError:
                                _LOGGER.warning("CCCD ATTEMPT %d: retry timed out", attempt)
                            except Exception as retry_err:
                                _LOGGER.warning("CCCD ATTEMPT %d: retry error: %s", attempt, retry_err)

                            if not cccd_written_ok and not cccd_disconnect_detected:
                                if char_path:
                                    _LOGGER.warning(
                                        "CCCD ATTEMPT %d: Trying D-Bus StartNotify (bypasses AcquireNotify entirely).",
                                        attempt,
                                    )
                                    dbus_start_ok = await self._dbus_start_notify_on_char(char_path)
                                    if dbus_start_ok:
                                        cccd_written_ok = True
                                        cccd_via_direct_write = True
                                        _LOGGER.warning(
                                            "CCCD ATTEMPT %d: D-Bus StartNotify succeeded!\n"
                                            "  CCCD written to machine. Notifications via PropertiesChanged.",
                                            attempt,
                                        )

                                if not cccd_written_ok and not cccd_disconnect_detected:
                                    _LOGGER.warning(
                                        "CCCD ATTEMPT %d: D-Bus StartNotify also failed. Trying direct CCCD descriptor write.",
                                        attempt,
                                    )
                                    try:
                                        cccd_uuid = "00002902-0000-1000-8000-00805f9b34fb"
                                        read_char = self._client.services.get_characteristic(BLE_READ_UUID)
                                        if read_char:
                                            cccd_desc = None
                                            for desc in read_char.descriptors:
                                                if cccd_uuid in str(desc.uuid).lower():
                                                    cccd_desc = desc
                                                    break
                                            if cccd_desc:
                                                await self._client.write_gatt_descriptor(
                                                    cccd_desc.handle, b"\x01\x00",
                                                )
                                                cccd_written_ok = True
                                                cccd_via_direct_write = True
                                                _LOGGER.warning(
                                                    "CCCD ATTEMPT %d: DIRECT CCCD descriptor write OK (handle=%d).\n"
                                                    "  Machine should now receive CCCD and may enter pairing mode.\n"
                                                    "  Note: bleak callback NOT registered - D-Bus handler needed.",
                                                    attempt, cccd_desc.handle,
                                                )
                                            else:
                                                _LOGGER.warning("CCCD ATTEMPT %d: CCCD descriptor (0x2902) not found", attempt)
                                        else:
                                            _LOGGER.warning("CCCD ATTEMPT %d: read char not found in services", attempt)
                                    except (EOFError, OSError) as desc_err:
                                        cccd_disconnect_detected = True
                                        _LOGGER.warning(
                                            "CCCD ATTEMPT %d: direct CCCD write caused disconnect (good - was written): %s",
                                            attempt, desc_err,
                                        )
                                    except Exception as desc_err:
                                        _LOGGER.warning("CCCD ATTEMPT %d: direct CCCD write error: %s", attempt, desc_err)
                        elif any(w in err_str for w in ("not connected", "disconnected", "disconnect")):
                            cccd_disconnect_detected = True
                            _LOGGER.warning("CCCD ATTEMPT %d: disconnect error: %s", attempt, err)
                        else:
                            _LOGGER.warning("CCCD ATTEMPT %d: BleakError: %s", attempt, err)
                    except (EOFError, OSError) as err:
                        cccd_disconnect_detected = True
                        _LOGGER.warning("CCCD ATTEMPT %d: %s: %s", attempt, type(err).__name__, err)
                    except Exception as err:
                        _LOGGER.warning("CCCD ATTEMPT %d: error: %s (%s)", attempt, err, type(err).__name__)
                finally:
                    self._suppress_disconnect_callback = False

                if cccd_written_ok and not cccd_disconnect_detected:
                    for check_ms in (100, 200, 300, 500, 750):
                        await asyncio.sleep(0.1 if check_ms <= 200 else 0.2)
                        try:
                            still_connected = self._client and self._client.is_connected
                        except Exception:
                            still_connected = False
                        if not still_connected:
                            cccd_disconnect_detected = True
                            _LOGGER.warning(
                                "CCCD ATTEMPT %d: connection dropped %dms after CCCD write",
                                attempt, check_ms,
                            )
                            break

                    if not cccd_disconnect_detected:
                        result_mode = "direct_cccd" if cccd_via_direct_write else "bleak_notify"
                        _LOGGER.warning(
                            "CCCD ATTEMPT %d: CCCD write + connection stable after 750ms. SUCCESS! (mode=%s)",
                            attempt, result_mode,
                        )
                        return result_mode

                if not cccd_written_ok and not cccd_disconnect_detected:
                    if notify_acquired_handled:
                        use_remove = attempt >= 3
                        if use_remove:
                            _LOGGER.warning(
                                "CCCD ATTEMPT %d: 'Notify acquired' persists after %d attempts.\n"
                                "  Using NUCLEAR option: RemoveDevice from BlueZ to fully clear all state.\n"
                                "  This forces BlueZ to forget the device completely.\n"
                                "  The device will be re-discovered on next connection attempt.",
                                attempt, attempt,
                            )
                        else:
                            _LOGGER.warning(
                                "CCCD ATTEMPT %d: 'Notify acquired' could not be resolved on this connection.\n"
                                "  Neither D-Bus StopNotify + start_notify retry nor direct CCCD write worked.\n"
                                "  Doing full disconnect+reconnect to clear BlueZ state...",
                                attempt,
                            )
                        await self._internal_disconnect()
                        await asyncio.sleep(1.0)
                        if self._shutting_down:
                            return "failed"
                        if use_remove:
                            await self._dbus_remove_device()
                            await asyncio.sleep(3.0)
                        else:
                            if self._hass is not None:
                                await self._force_bluez_disconnect()
                            await asyncio.sleep(2.0)
                        reconnect_ok = await self._internal_reconnect_ble()
                        if not reconnect_ok:
                            _LOGGER.warning("CCCD ATTEMPT %d: reconnect failed, retrying...", attempt)
                            await asyncio.sleep(3.0)
                            reconnect_ok = await self._internal_reconnect_ble()
                        if reconnect_ok:
                            _LOGGER.warning("CCCD ATTEMPT %d: reconnected. Will retry CCCD on fresh connection.", attempt)
                        else:
                            _LOGGER.warning("CCCD ATTEMPT %d: reconnect failed. Giving up this attempt.", attempt)
                        continue
                    else:
                        _LOGGER.warning(
                            "CCCD ATTEMPT %d: start_notify failed but no disconnect. Retrying...",
                            attempt,
                        )
                        await asyncio.sleep(1.0)
                        continue

                _LOGGER.warning(
                    "CCCD ATTEMPT %d: machine disconnected after CCCD write (expected).\n"
                    "  CCCD written to machine - it may now enter pairing mode.\n"
                    "  Cleaning up fully and reconnecting...",
                    attempt,
                )

                if self._keepalive_task and not self._keepalive_task.done():
                    self._keepalive_task.cancel()
                    self._keepalive_task = None
                self._cancel_reconnect()

                await self._internal_disconnect()

                self._auth_event.clear()
                self._auth_got_frame = False
                self._auth_disconnect_reason = None
                self._authenticated = False
                self._session_key = None

                if attempt >= max_cccd_attempts:
                    _LOGGER.warning(
                        "CCCD: all %d attempts caused disconnect.\n"
                        "  Reconnecting for polling-only mode...",
                        max_cccd_attempts,
                    )
                    await asyncio.sleep(2.0)
                    if self._hass is not None:
                        await self._force_bluez_disconnect()
                    reconnect_ok = await self._internal_reconnect_ble()
                    if reconnect_ok:
                        _LOGGER.warning("CCCD: final reconnect OK - will use polling only")
                    return "failed"

                await asyncio.sleep(2.0)

                if self._shutting_down:
                    return "failed"

                if self._hass is not None:
                    await self._force_bluez_disconnect()

                reconnect_ok = await self._internal_reconnect_ble()
                if not reconnect_ok:
                    _LOGGER.warning("CCCD ATTEMPT %d: first reconnect failed, retrying...", attempt)
                    await asyncio.sleep(2.0)
                    if self._hass is not None:
                        await self._force_bluez_disconnect()
                    reconnect_ok = await self._internal_reconnect_ble()
                    if not reconnect_ok:
                        _LOGGER.warning("CCCD ATTEMPT %d: reconnect failed twice", attempt)
                        return "failed"

                _LOGGER.warning(
                    "CCCD ATTEMPT %d: reconnected. Clearing BlueZ notify state before retry...",
                    attempt,
                )

                try:
                    await self._client.stop_notify(BLE_READ_UUID)
                    _LOGGER.warning("CCCD ATTEMPT %d: stop_notify OK (cleared old state)", attempt)
                except Exception as sn_err:
                    _LOGGER.warning(
                        "CCCD ATTEMPT %d: stop_notify returned: %s (may be OK)", attempt, sn_err,
                    )

                await asyncio.sleep(0.5)

            return "failed"

        finally:
            self._cccd_recovery_in_progress = False

    def _notification_callback(self, sender, data: bytearray):
        _LOGGER.warning(
            ">>> BLE NOTIFICATION RX: sender=%s, %d bytes, hex=%s",
            sender, len(data), bytes(data).hex(),
        )
        self._process_incoming_data(bytes(data))

    async def _register_dbus_notification_handler(self, char_path: str) -> bool:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, BusType

            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            self._dbus_notify_bus = bus

            _LOGGER.info(
                "Registering D-Bus PropertiesChanged handler on %s", char_path,
            )

            match_rule = (
                f"type='signal',"
                f"sender='org.bluez',"
                f"interface='org.freedesktop.DBus.Properties',"
                f"member='PropertiesChanged',"
                f"path='{char_path}'"
            )
            self._dbus_match_rule = match_rule
            add_match_msg = Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[match_rule],
            )
            await bus.call(add_match_msg)

            t_handler_registered = time.monotonic()
            self._pipeline_auth_write_time = None

            def on_dbus_message(msg):
                t_rx = time.monotonic()
                if msg.member != "PropertiesChanged":
                    return
                msg_path = msg.path if hasattr(msg, 'path') else ""
                if msg_path != char_path:
                    return
                if not msg.body or len(msg.body) < 2:
                    _LOGGER.warning(
                        "D-Bus PropertiesChanged: empty body, path=%s, t=%.1fms since handler registered",
                        msg_path, (t_rx - t_handler_registered) * 1000,
                    )
                    return
                iface = msg.body[0]
                changed = msg.body[1]
                if iface != "org.bluez.GattCharacteristic1":
                    _LOGGER.warning(
                        "D-Bus PropertiesChanged: wrong interface=%s (expected GattCharacteristic1), path=%s",
                        iface, msg_path,
                    )
                    return
                if "Value" not in changed:
                    _LOGGER.warning(
                        "D-Bus PropertiesChanged: no Value key, keys=%s, path=%s, t=%.1fms",
                        list(changed.keys()), msg_path, (t_rx - t_handler_registered) * 1000,
                    )
                    return

                value = changed["Value"]
                if hasattr(value, 'value'):
                    value = value.value
                data = bytes(value)
                if len(data) == 0:
                    _LOGGER.warning("D-Bus PropertiesChanged: empty Value data, path=%s", msg_path)
                    return

                latency_from_auth = ""
                if self._pipeline_auth_write_time is not None:
                    latency_from_auth = ", latency_since_auth_write=%.1fms" % ((t_rx - self._pipeline_auth_write_time) * 1000)

                _LOGGER.warning(
                    ">>> D-Bus NOTIFICATION RX: %d bytes, hex=%s, path=%s\n"
                    "  t=%.1fms since handler registered%s\n"
                    "  first_byte=0x%02x, authenticated=%s, status=%s\n"
                    "  raw_bytes=[%s]",
                    len(data), data.hex(), msg_path,
                    (t_rx - t_handler_registered) * 1000, latency_from_auth,
                    data[0] if len(data) > 0 else 0,
                    self._authenticated, self._status,
                    " ".join(f"0x{b:02x}" for b in data),
                )
                self._process_incoming_data(data)

            bus.add_message_handler(on_dbus_message)
            self._dbus_notify_handler = on_dbus_message
            _LOGGER.info("D-Bus PropertiesChanged handler registered successfully for %s", char_path)
            return True

        except ImportError:
            _LOGGER.warning("dbus_fast not available for D-Bus notification handler")
            return False
        except Exception as err:
            _LOGGER.warning(
                "D-Bus notification handler failed: %s (%s)", err, type(err).__name__,
            )
            if self._dbus_notify_bus:
                try:
                    self._dbus_notify_bus.disconnect()
                except Exception:
                    pass
                self._dbus_notify_bus = None
            return False

    async def _stop_notifications(self):
        _LOGGER.warning(
            "=== STOPPING NOTIFICATIONS ===\n"
            "  notifications_active=%s, notify_mode=%s, status=%s, shutting_down=%s",
            self._notifications_active, self._notify_mode, self._status, self._shutting_down,
        )

        if self._dbus_notify_bus is not None:
            try:
                if self._dbus_notify_handler:
                    self._dbus_notify_bus.remove_message_handler(self._dbus_notify_handler)
                if self._dbus_match_rule:
                    try:
                        from dbus_fast import Message
                        remove_match = Message(
                            destination="org.freedesktop.DBus",
                            path="/org/freedesktop/DBus",
                            interface="org.freedesktop.DBus",
                            member="RemoveMatch",
                            signature="s",
                            body=[self._dbus_match_rule],
                        )
                        await self._dbus_notify_bus.call(remove_match)
                    except Exception:
                        pass
                self._dbus_notify_bus.disconnect()
                _LOGGER.warning("D-Bus notification bus disconnected")
            except Exception as err:
                _LOGGER.warning("D-Bus cleanup error (non-fatal): %s", err)
            self._dbus_notify_bus = None
            self._dbus_notify_handler = None
            self._dbus_match_rule = None

        self._notifications_active = False

    async def _authenticate(self):
        if self._auth_lock.locked():
            _LOGGER.warning("Auth already in progress for %s, skipping duplicate attempt", self._address)
            return

        async with self._auth_lock:
            await self._do_authenticate()

        if not self._authenticated and not self._is_connected and not self._shutting_down:
            _LOGGER.info("Auth completed without success and disconnected - scheduling reconnect")
            self.schedule_reconnect()

    async def _send_auth_frame(self, frame: bytes, desc: str) -> bool:
        if not self._is_connected or self._client is None:
            _LOGGER.warning("Connection lost before sending %s auth frame", desc)
            return False

        _LOGGER.warning(
            "AUTH SEND (%s): writing %d bytes to %s (response=False)",
            desc, len(frame), BLE_WRITE_UUID,
        )
        try:
            await asyncio.wait_for(
                self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False),
                timeout=5.0,
            )
            _LOGGER.warning("AUTH WRITE OK (%s)", desc)
            return True
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "AUTH WRITE HUNG (%s): write_gatt_char did not return within 5s! "
                "BLE connection may be stale.",
                desc,
            )
            return False
        except Exception as err:
            _LOGGER.warning("AUTH WRITE FAILED (%s): %s", desc, err)
            return False

    async def _do_authenticate(self):
        self._auth_challenge = os.urandom(4)
        self._auth_got_frame = False
        self._auth_disconnect_reason = None
        challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
        auth_payload = self._auth_challenge + challenge_hash

        _LOGGER.warning(
            "=== AUTH START (APK order: encrypted first, plaintext fallback) ===\n"
            "  challenge=%s, sbox_hash=%s, full_payload=%s (6 bytes)\n"
            "  connected=%s, notifications=%s, notify_mode=%s, shutting_down=%s",
            self._auth_challenge.hex(), challenge_hash.hex(), auth_payload.hex(),
            self._is_connected, self._notifications_active, self._notify_mode, self._shutting_down,
        )

        auth_encrypted = build_frame(CMD_AUTH, None, auth_payload, encrypt=True)
        auth_plaintext = build_frame(CMD_AUTH, None, auth_payload, encrypt=False)

        _LOGGER.warning(
            "AUTH FRAMES built:\n"
            "  encrypted=%s (%d bytes)\n"
            "  plaintext=%s (%d bytes)",
            auth_encrypted.hex(), len(auth_encrypted),
            auth_plaintext.hex(), len(auth_plaintext),
        )

        self._status = "waiting_for_machine_button"
        self._last_error = (
            "Druk op 'Verbinden' op het display van het koffieapparaat. "
            "Wacht tot het Bluetooth-lampje knippert..."
        )
        self._notify_callbacks()

        if not self._is_connected or self._client is None:
            _LOGGER.warning("Connection lost before auth")
            return

        self._auth_event.clear()
        self._authenticated = False

        encrypted_sent = await self._send_auth_frame(auth_encrypted, "ENCRYPTED (primary, matching APK)")
        if not encrypted_sent:
            _LOGGER.warning("AUTH: encrypted frame failed to send, trying plaintext directly")
            plaintext_sent = await self._send_auth_frame(auth_plaintext, "PLAINTEXT (fallback)")
            if not plaintext_sent:
                _LOGGER.error("AUTH: both frame sends failed, aborting auth")
                return

        self._status = "authenticating"
        self._last_error = (
            "Encrypted auth-frame verstuurd (zoals APK). Druk NU op 'Verbinden' op het display! "
            "Wachten op antwoord... (max %d seconden)" % int(AUTH_TIMEOUT)
        )
        self._notify_callbacks()

        _LOGGER.warning(
            "AUTH: encrypted frame sent (matching APK). Waiting up to %.0fs for response.\n"
            "  User should press 'Verbinden' on the machine display.",
            AUTH_TIMEOUT,
        )

        got_response = await self._poll_for_auth_response("encrypted")

        if self._authenticated:
            _LOGGER.warning("=== AUTH SUCCEEDED (encrypted frame, matching APK) ===")
            return

        should_try_plaintext = False
        if self._auth_got_frame:
            _LOGGER.warning(
                "AUTH: machine responded to encrypted frame but validation FAILED.\n"
                "  Trying PLAINTEXT fallback in case machine uses unencrypted auth...",
            )
            should_try_plaintext = True
        elif not self._auth_disconnect_reason and self._is_connected and encrypted_sent:
            _LOGGER.warning(
                "AUTH: no response to encrypted frame within %.0fs.\n"
                "  Trying PLAINTEXT fallback (in case machine expects unencrypted auth)...",
                AUTH_TIMEOUT,
            )
            should_try_plaintext = True

        if should_try_plaintext and self._is_connected and not self._shutting_down:

            self._auth_challenge = os.urandom(4)
            self._auth_got_frame = False
            self._auth_disconnect_reason = None
            challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
            auth_payload = self._auth_challenge + challenge_hash
            auth_plaintext = build_frame(CMD_AUTH, None, auth_payload, encrypt=False)

            _LOGGER.warning(
                "AUTH PLAINTEXT FALLBACK: new challenge=%s, frame=%s (%d bytes)",
                self._auth_challenge.hex(), auth_plaintext.hex(), len(auth_plaintext),
            )

            self._auth_event.clear()
            plaintext_sent = await self._send_auth_frame(auth_plaintext, "PLAINTEXT (fallback)")

            if plaintext_sent:
                self._last_error = (
                    "Plaintext auth-frame verstuurd (fallback). "
                    "Wachten op antwoord... (max %d seconden)" % int(AUTH_TIMEOUT)
                )
                self._notify_callbacks()

                got_response = await self._poll_for_auth_response("plaintext-fallback")

                if self._authenticated:
                    _LOGGER.warning("=== AUTH SUCCEEDED (plaintext fallback) ===")
                    return

        _LOGGER.warning(
            "=== AUTH RESULT (both attempts) ===\n"
            "  authenticated=%s, auth_got_frame=%s\n"
            "  auth_disconnect_reason=%s\n"
            "  connected=%s, shutting_down=%s, status=%s",
            self._authenticated, self._auth_got_frame,
            self._auth_disconnect_reason,
            self._is_connected, self._shutting_down, self._status,
        )

        if self._auth_disconnect_reason:
            _LOGGER.warning(
                "AUTH: connection dropped during auth wait.\n"
                "  disconnect_reason: %s\n"
                "  The machine did NOT respond. Notifications may not be working.",
                self._auth_disconnect_reason,
            )
        elif not self._auth_got_frame:
            _LOGGER.warning(
                "AUTH: no response to either encrypted or plaintext frame.\n"
                "  Possible causes:\n"
                "  1. User didn't press 'Verbinden' on machine display\n"
                "  2. Notifications not working (check notification logs above)\n"
                "  3. Wrong RC4 key (check RC4 KEY DERIVATION logs)\n"
                "  4. Machine requires different auth frame format",
            )

        self._last_error = (
            "Authenticatie mislukt. Heb je op 'Verbinden' gedrukt op het display "
            "van het koffieapparaat? Probeer opnieuw: herstart de integratie en "
            "druk op 'Verbinden' zodra de status verandert."
        )
        _LOGGER.error(
            "=== AUTH FAILED for %s ===\n"
            "  auth_got_frame=%s, disconnect_reason=%s, notifications_active=%s",
            self._address, self._auth_got_frame, self._auth_disconnect_reason,
            self._notifications_active,
        )

    async def _poll_for_auth_response(self, desc: str) -> bool:
        client = self._client
        if client is None:
            return False

        if self._notify_mode in ("bleak_notify", "dbus_direct_cccd", "dbus_handler_only") and self._notifications_active:
            _LOGGER.warning(
                "AUTH WAIT: %s - notifications ACTIVE (mode=%s).\n"
                "  Waiting for notification callback + polling as backup.",
                desc, self._notify_mode,
            )
            result = await self._wait_for_auth_combined(desc)
            if result:
                return True
            if self._authenticated or self._auth_got_frame:
                return True

        if not self._authenticated and not self._auth_got_frame:
            _LOGGER.warning(
                "AUTH POLL: %s - using read polling (notify_mode=%s, notifications_active=%s)",
                desc, self._notify_mode, self._notifications_active,
            )
            return await self._wait_for_auth_via_polling(desc)

        return False

    async def _wait_for_auth_combined(self, desc: str) -> bool:
        _LOGGER.warning(
            "AUTH COMBINED WAIT: notifications + polling for up to %.1fs\n"
            "  Checking auth_event (from notification callback) every 150ms\n"
            "  Also polling read characteristic as backup",
            AUTH_TIMEOUT,
        )
        client = self._client
        if client is None:
            return False

        poll_interval = 0.15
        max_polls = int(AUTH_TIMEOUT / poll_interval)
        last_data = None

        for i in range(max_polls):
            if self._authenticated or self._auth_got_frame:
                _LOGGER.warning("AUTH COMBINED [#%d]: auth result detected!", i + 1)
                return True

            if self._auth_event.is_set():
                _LOGGER.warning("AUTH COMBINED [#%d]: auth_event set!", i + 1)
                return True

            if not self._is_connected or self._client is None:
                _LOGGER.warning("AUTH COMBINED [#%d]: connection lost", i + 1)
                return False

            try:
                data = await asyncio.wait_for(
                    client.read_gatt_char(BLE_READ_UUID),
                    timeout=2.0,
                )
                if data and len(data) > 0 and data != last_data:
                    _LOGGER.warning(
                        "AUTH COMBINED POLL [#%d]: NEW data via read, %d bytes, hex=%s",
                        i + 1, len(data), data.hex(),
                    )
                    last_data = data
                    self._process_incoming_data(data)
                    if self._authenticated or self._auth_event.is_set():
                        return True
                elif i < 5 or i % 20 == 0:
                    _LOGGER.warning(
                        "AUTH COMBINED [#%d]: waiting... (notify_mode=%s)",
                        i + 1, self._notify_mode,
                    )
            except asyncio.TimeoutError:
                if i < 5 or i % 20 == 0:
                    _LOGGER.warning("AUTH COMBINED [#%d]: read timed out (notification may still arrive)", i + 1)
            except (BleakError, EOFError) as err:
                _LOGGER.warning("AUTH COMBINED [#%d]: read error: %s", i + 1, err)
            except Exception as err:
                _LOGGER.warning("AUTH COMBINED [#%d]: %s: %s", i + 1, type(err).__name__, err)

            await asyncio.sleep(poll_interval)

        _LOGGER.warning("AUTH COMBINED: timeout after %.1fs", AUTH_TIMEOUT)
        return False

    async def _wait_for_auth_via_notifications(self, desc: str) -> bool:
        _LOGGER.warning(
            "AUTH WAIT (notifications): waiting up to %.1fs for auth response on %s\n"
            "  notifications_active=%s, auth_event_cleared=%s, auth_got_frame=%s",
            AUTH_TIMEOUT, BLE_READ_UUID,
            self._notifications_active, not self._auth_event.is_set(), self._auth_got_frame,
        )

        try:
            await asyncio.wait_for(self._auth_event.wait(), timeout=AUTH_TIMEOUT)
        except asyncio.TimeoutError:
            pass

        _LOGGER.warning(
            "AUTH WAIT: event check:\n"
            "  auth_event.is_set=%s, authenticated=%s, auth_got_frame=%s\n"
            "  auth_disconnect_reason=%s, connected=%s, shutting_down=%s",
            self._auth_event.is_set(), self._authenticated, self._auth_got_frame,
            self._auth_disconnect_reason, self._is_connected, self._shutting_down,
        )

        if self._authenticated:
            _LOGGER.warning("AUTH WAIT: AUTHENTICATED via notification callback!")
            return True

        if self._auth_got_frame:
            _LOGGER.warning(
                "AUTH WAIT: got auth frame via notification but validation failed. "
                "Returning True so caller can inspect the failure reason.",
            )
            return True

        if self._auth_disconnect_reason:
            _LOGGER.warning(
                "AUTH WAIT: auth_event was set by DISCONNECT handler, NOT by a real response.\n"
                "  Reason: %s\n"
                "  No actual data was received from the machine.",
                self._auth_disconnect_reason,
            )
            return False

        if self._auth_event.is_set():
            _LOGGER.warning(
                "AUTH WAIT: auth_event is set but no frame and no disconnect reason. "
                "This should not happen. Treating as no response.",
            )
            return False

        _LOGGER.warning(
            "AUTH WAIT: TIMEOUT - no auth response within %.1fs via D-Bus notifications.\n"
            "  Returning False - caller will try read polling as fallback.",
            AUTH_TIMEOUT,
        )
        return False

    async def _wait_for_auth_via_polling(self, desc: str, short: bool = False) -> bool:
        client = self._client
        if client is None:
            return False

        poll_interval = 0.15
        timeout = 3.0 if short else AUTH_TIMEOUT
        max_polls = int(timeout / poll_interval)
        last_data = None

        _LOGGER.warning(
            "AUTH POLL: reading %s every %.0fms for up to %.1fs (%d reads max)",
            BLE_READ_UUID, poll_interval * 1000, timeout, max_polls,
        )

        for i in range(max_polls):
            if self._authenticated or self._auth_got_frame:
                _LOGGER.warning("AUTH POLL: auth result detected (via D-Bus handler) before read #%d", i + 1)
                return True

            if not self._is_connected or self._client is None:
                _LOGGER.warning("AUTH POLL: connection lost at read #%d", i + 1)
                return False

            try:
                data = await asyncio.wait_for(
                    client.read_gatt_char(BLE_READ_UUID),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                _LOGGER.warning("AUTH POLL [#%d]: read_gatt_char timed out (2s)", i + 1)
                continue
            except BleakError as err:
                _LOGGER.warning("AUTH POLL [#%d]: BleakError: %s", i + 1, err)
                await asyncio.sleep(poll_interval)
                continue
            except Exception as err:
                _LOGGER.warning("AUTH POLL [#%d]: %s: %s", i + 1, type(err).__name__, err)
                await asyncio.sleep(poll_interval)
                continue

            if data and len(data) > 0 and data != last_data:
                _LOGGER.warning(
                    "AUTH POLL [#%d]: NEW data received, %d bytes, hex=%s",
                    i + 1, len(data), data.hex(),
                )
                last_data = data
                self._process_incoming_data(data)

                if self._authenticated or self._auth_event.is_set():
                    _LOGGER.warning("AUTH POLL: auth event set after %d reads", i + 1)
                    return True
            elif i < 5 or i % 10 == 0:
                _LOGGER.warning(
                    "AUTH POLL [#%d]: %s",
                    i + 1,
                    "same/empty data" if data == last_data else f"data={repr(data)}",
                )

            await asyncio.sleep(poll_interval)

        _LOGGER.warning("AUTH POLL: no auth response after %d reads (%.1fs)", max_polls, timeout)
        return False

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
            self.schedule_reconnect()
            return

        if self._connect_pending or self._connect_lock.locked():
            _LOGGER.debug("Skipping async_update: connect in progress for %s", self._address)
            return

        if self._is_connected and not self._authenticated:
            if not self._auth_lock.locked():
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
        import traceback
        caller = "".join(traceback.format_stack(limit=5))
        _LOGGER.warning(
            "=== PUBLIC DISCONNECT() CALLED for %s ===\n"
            "  current_status=%s, connected=%s, authenticated=%s, auth_lock=%s\n"
            "  Setting shutting_down=True\n"
            "  caller:\n%s",
            self._address, self._status, self._is_connected, self._authenticated,
            self._auth_lock.locked(), caller,
        )
        if self._auth_lock.locked():
            _LOGGER.warning(
                "!!! DISCONNECT() CALLED WHILE AUTH IS IN PROGRESS !!!\n"
                "  This will kill the current auth attempt. Setting shutting_down=True\n"
                "  and signaling auth_event so auth wait exits cleanly.",
            )
            self._auth_disconnect_reason = "disconnect() called externally during auth (likely HA unload/reload)"

        self._shutting_down = True
        self._auth_event.set()
        self._cancel_reconnect()
        self._stop_polling()

        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except (asyncio.CancelledError, Exception):
                pass
            self._keepalive_task = None

        await self._stop_notifications()

        if self._client:
            if self._is_connected:
                try:
                    _LOGGER.warning("Disconnecting BLE client for %s...", self._address)
                    await asyncio.wait_for(self._client.disconnect(), timeout=DISCONNECT_TIMEOUT)
                    _LOGGER.warning("BLE disconnected cleanly from %s", self._address)
                except (BleakError, asyncio.TimeoutError, OSError) as err:
                    _LOGGER.warning("Disconnect error: %s", err)

            self._client = None

        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        self._status = "offline"
        self._shutting_down = False
        self._notify_callbacks()
        _LOGGER.warning("=== DISCONNECT COMPLETE for %s ===", self._address)
