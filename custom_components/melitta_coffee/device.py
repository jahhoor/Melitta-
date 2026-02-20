import asyncio
import logging
import os
import struct
import time
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
from .crypto import sbox_hash, rotate_rc4_key
from .protocol import build_frame, EfComParser, EfComFrame

_LOGGER = logging.getLogger(__name__)

AUTH_TIMEOUT = 10.0
CONNECT_TIMEOUT = 15.0
DISCONNECT_TIMEOUT = 10.0
RECONNECT_BASE_DELAY = 10.0
RECONNECT_MAX_DELAY = 300.0
RECONNECT_MAX_ATTEMPTS = 3


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
        self._authenticated = False
        self._is_connected = False
        self._shutting_down = False
        self._keepalive_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._connect_lock = asyncio.Lock()
        self._connect_pending = False
        self._last_reconnect_time: float = 0.0
        self._callbacks: list[Callable] = []
        self._status = "offline"
        self._machine_state: int | None = None
        self._machine_state_name: str = "Unknown"
        self._last_error: str | None = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = RECONNECT_MAX_ATTEMPTS
        self._auth_failure_count = 0
        self._gave_up = False
        self._suppress_disconnect_callback = False
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
        if self._suppress_disconnect_callback:
            self._is_connected = False
            _LOGGER.debug("Disconnect callback suppressed for %s", self._address)
            return
        if client is not self._client:
            return

        was_auth = self._status == "authenticating"
        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        self._stop_polling()
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            self._keepalive_task = None

        if was_auth:
            self._status = "auth_dropped"
            self._last_error = "Machine heeft verbinding verbroken tijdens authenticatie."
            self._auth_event.set()
        elif not self._shutting_down:
            self._status = "offline"
            self._last_error = "Verbinding verbroken"

        _LOGGER.info("Disconnected from %s (was_auth=%s)", self._address, was_auth)
        self._notify_callbacks()

        if self._gave_up:
            _LOGGER.info("Not reconnecting: gave up after %d failures", self._auth_failure_count)
        elif not self._shutting_down:
            self.schedule_reconnect()

    def _cancel_reconnect(self):
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            self._reconnect_task = None

    def schedule_reconnect(self):
        if self._shutting_down or self._gave_up:
            return
        if self._is_connected and self._authenticated:
            return
        if self._max_reconnect_attempts > 0 and self._auth_failure_count >= self._max_reconnect_attempts:
            self._gave_up = True
            self._status = "offline"
            self._last_error = (
                f"Verbinding gestopt na {self._auth_failure_count} mislukte pogingen. "
                "Druk opnieuw op 'Verbinden' op de machine en herlaad de integratie."
            )
            _LOGGER.warning("Reconnect stopped for %s after %d failures", self._address, self._auth_failure_count)
            self._cancel_reconnect()
            self._stop_polling()
            self._notify_callbacks()
            return
        if self._connect_pending or self._connect_lock.locked():
            return
        if self._reconnect_task and not self._reconnect_task.done():
            return

        now = time.monotonic()
        since_last = now - self._last_reconnect_time
        capped = min(self._reconnect_attempts, 5)
        delay = min(RECONNECT_BASE_DELAY * (2 ** capped), RECONNECT_MAX_DELAY)
        if since_last < 8.0:
            delay = max(delay, 8.0 - since_last)

        self._reconnect_attempts += 1
        _LOGGER.info("Reconnect to %s in %.0fs (attempt %d)", self._address, delay, self._reconnect_attempts)
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
            if self._shutting_down or self._gave_up or (self._is_connected and self._authenticated):
                return
            self._last_reconnect_time = time.monotonic()
            self._reconnect_task = None
            success = await self.connect()
            if not success and not self._shutting_down and not self._gave_up:
                self.schedule_reconnect()
        except asyncio.CancelledError:
            pass
        except Exception as err:
            _LOGGER.error("Reconnect error for %s: %s", self._address, err)
            self._reconnect_task = None
            if not self._shutting_down and not self._gave_up:
                self.schedule_reconnect()

    def _process_incoming_data(self, data: bytes):
        _LOGGER.debug("Incoming data: %d bytes, hex=%s", len(data), data.hex())
        frames = self._parser.feed(data)
        for frame in frames:
            _LOGGER.debug("Parsed frame: cmd=%r, payload=%s, encrypted=%s", frame.command, frame.payload.hex(), frame.encrypted)
            self._handle_frame(frame)

    def _on_notification(self, sender, data: bytes):
        _LOGGER.debug("BLE notification: %d bytes from %s", len(data), sender)
        self._process_incoming_data(bytes(data))

    def _handle_frame(self, frame: EfComFrame):
        if frame.command == CMD_AUTH:
            self._handle_auth_response(frame)
        elif frame.command == CMD_STATUS:
            self._handle_status_response(frame)
        elif frame.command == CMD_KEEPALIVE:
            _LOGGER.debug("Keepalive response received")
        elif frame.command in ("A", "N"):
            _LOGGER.debug("%s received", "ACK" if frame.command == "A" else "NACK")
        else:
            _LOGGER.debug("Unhandled frame: cmd=%r, payload=%s", frame.command, frame.payload.hex())

    def _handle_auth_response(self, frame: EfComFrame):
        payload = frame.payload
        self._auth_got_frame = True

        if len(payload) != 8:
            _LOGGER.warning("Auth response: unexpected payload length %d (expected 8)", len(payload))
            self._auth_event.set()
            return

        echo = payload[0:4]
        session = payload[4:6]
        hash_received = payload[6:8]

        if self._auth_challenge is None:
            _LOGGER.warning("Auth response: no pending challenge")
            self._auth_event.set()
            return

        if echo != self._auth_challenge:
            _LOGGER.warning("Auth response: echo mismatch (sent=%s, got=%s)", self._auth_challenge.hex(), echo.hex())
            self._auth_event.set()
            return

        verify_data = payload[0:6]
        expected_hash = sbox_hash(verify_data, len(verify_data))
        if hash_received != expected_hash:
            _LOGGER.info("Auth: hash mismatch but echo matched, accepting session anyway")

        self._session_key = session
        self._authenticated = True
        self._auth_failure_count = 0
        self._gave_up = False
        self._reconnect_attempts = 0
        _LOGGER.info("Auth succeeded: session_key=%s, encrypted=%s", session.hex(), frame.encrypted)
        self._auth_event.set()

    def _handle_status_response(self, frame: EfComFrame):
        self._last_status_data = frame.payload
        payload = frame.payload
        if len(payload) >= 2:
            state_value = struct.unpack(">H", payload[0:2])[0]
            self._machine_state = state_value
            self._machine_state_name = MACHINE_STATE_NAMES.get(state_value, f"Unknown ({state_value})")
        if len(payload) >= 3:
            self._water_level = payload[2] & 0xFF
        if len(payload) >= 4:
            self._bean_level = payload[3] & 0xFF
        if len(payload) >= 5:
            self._drip_tray_full = (payload[4] & 0x01) != 0
        if len(payload) >= 6:
            self._brew_progress = payload[5] & 0xFF
        if len(payload) >= 8:
            self._error_code = struct.unpack(">H", payload[6:8])[0]
            if self._error_code == 0:
                self._error_code = None
        _LOGGER.debug(
            "Status: state=%s, water=%s%%, beans=%s%%, tray=%s, progress=%s%%, error=%s",
            self._machine_state_name, self._water_level, self._bean_level,
            self._drip_tray_full, self._brew_progress, self._error_code,
        )
        self._notify_callbacks()

    async def connect(self) -> bool:
        if self._is_connected and self._authenticated:
            return True
        if self._gave_up:
            _LOGGER.info("Connect blocked: gave up after %d failures", self._auth_failure_count)
            return False

        self._connect_pending = True
        try:
            async with self._connect_lock:
                if self._is_connected and self._authenticated:
                    return True
                self._cancel_reconnect()
                return await self._do_connect()
        finally:
            self._connect_pending = False

    async def _do_connect(self) -> bool:
        self._cancel_reconnect()

        if self._client is not None:
            await self._internal_disconnect()
            await asyncio.sleep(0.5)

        if self._hass is not None:
            await self._force_bluez_disconnect()

        _LOGGER.info("Connecting to %s (attempt %d)", self._address, self._reconnect_attempts + 1)

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
                return False

            if self._hass is not None:
                freshly_paired = await self._handle_pairing()
                if freshly_paired:
                    self._suppress_disconnect_callback = True
                    try:
                        await self._internal_disconnect()
                    except Exception:
                        pass
                    self._suppress_disconnect_callback = False
                    await asyncio.sleep(0.5)

                    reconnected = await self._internal_reconnect_ble()
                    if not reconnected:
                        await asyncio.sleep(1.0)
                        reconnected = await self._internal_reconnect_ble()
                    if not reconnected:
                        _LOGGER.warning("Reconnect after pairing failed")
                        self._status = "offline"
                        self._last_error = "Herverbinding na koppeling mislukt"
                        self._notify_callbacks()
                        return False

                    _LOGGER.info("Reconnected after fresh pairing, activating encryption...")
                    from .dbus_utils import dbus_force_encryption
                    await dbus_force_encryption(self._address)

                    if not self._is_connected:
                        await asyncio.sleep(0.5)
                        reconnected = await self._internal_reconnect_ble()
                        if not reconnected:
                            await asyncio.sleep(1.0)
                            reconnected = await self._internal_reconnect_ble()
                        if reconnected:
                            await dbus_force_encryption(self._address)
                        else:
                            self._status = "offline"
                            self._last_error = "Herverbinding mislukt na koppeling"
                            self._notify_callbacks()
                            return False

            self._status = "authenticating"
            self._notify_callbacks()

            auth_ok = await self._setup_notifications_and_auth()

            if not self._is_connected:
                _LOGGER.info("Connection lost during auth for %s", self._address)
                return False

            if self._authenticated:
                self._status = "ready"
                self._start_keepalive()
                _LOGGER.info("Connected and authenticated with %s", self._address)
                await self._request_status()
                self._notify_callbacks()
                return True
            else:
                self._auth_failure_count += 1
                self._status = "connected_not_auth"
                self._last_error = (
                    f"Authenticatie mislukt (poging {self._auth_failure_count}/{self._max_reconnect_attempts}). "
                    "Zorg dat de machine in 'Verbinden' modus staat."
                )
                _LOGGER.warning(
                    "Auth failed for %s (failure %d/%d)",
                    self._address, self._auth_failure_count, self._max_reconnect_attempts,
                )
                self._notify_callbacks()
                return False

        except (BleakError, asyncio.TimeoutError, OSError, EOFError) as err:
            self._status = "offline"
            self._last_error = f"Verbinding mislukt: {err}"
            _LOGGER.error("Connect failed to %s: %s", self._address, err)
            self._notify_callbacks()
            return False

    async def _handle_pairing(self) -> bool:
        from .dbus_utils import dbus_check_paired, dbus_pair_device, dbus_force_encryption

        is_paired = await dbus_check_paired(self._address)
        if is_paired:
            _LOGGER.info("Device already paired, activating encryption")
            await dbus_force_encryption(self._address)
            return False

        _LOGGER.info("Device not paired, initiating pairing (machine must be in Verbinden mode)")

        def status_cb(status, msg):
            self._status = status
            self._last_error = msg
            self._notify_callbacks()

        pair_ok = await dbus_pair_device(self._address, status_callback=status_cb)
        if pair_ok:
            _LOGGER.info("Pairing succeeded")
            return True
        else:
            _LOGGER.warning("Pairing failed - continuing without pairing")
            return False

    async def _setup_notifications_and_auth(self) -> bool:
        if not self._client or not self._is_connected:
            return False

        char_path = await self._get_char_path()
        dbus_handler_active = False
        notifications_confirmed = False

        if char_path and self._hass is not None:
            from .dbus_utils import (
                dbus_write_cccd, dbus_start_notify, dbus_check_notifying,
                dbus_register_notification_handler,
            )

            cccd_ok = await dbus_write_cccd(char_path)
            if cccd_ok:
                _LOGGER.debug("CCCD descriptor written via D-Bus")
            else:
                _LOGGER.debug("CCCD descriptor write skipped (not found or failed)")

            start_ok = await dbus_start_notify(char_path)
            if start_ok:
                _LOGGER.debug("D-Bus StartNotify succeeded")

            await asyncio.sleep(0.3)

            notifying = await dbus_check_notifying(char_path)
            if notifying:
                _LOGGER.debug("Notifying confirmed active via D-Bus")
                notifications_confirmed = True
            else:
                _LOGGER.debug("Notifying not yet active, proceeding anyway")

            try:
                bus, handler, match_rule = await dbus_register_notification_handler(
                    char_path, self._process_incoming_data,
                )
                self._dbus_notify_bus = bus
                self._dbus_notify_handler = handler
                self._dbus_match_rule = match_rule
                self._notifications_active = True
                dbus_handler_active = True
                _LOGGER.debug("D-Bus notification handler registered")
            except Exception as err:
                _LOGGER.debug("D-Bus notification handler failed: %s", err)

        try:
            await asyncio.wait_for(
                self._client.start_notify(BLE_READ_UUID, self._on_notification),
                timeout=3.0,
            )
            self._notifications_active = True
            notifications_confirmed = True
            _LOGGER.debug("Bleak start_notify succeeded")
        except Exception as err:
            _LOGGER.debug("Bleak start_notify failed: %s - using D-Bus/polling", err)
            if not dbus_handler_active:
                _LOGGER.info("No notification channel available, will use polling")

        if notifications_confirmed:
            await asyncio.sleep(0.2)

        auth_ok = await self._do_authenticate()
        return auth_ok

    async def _do_authenticate(self) -> bool:
        if not self._is_connected or self._client is None:
            return False

        self._auth_challenge = os.urandom(4)
        self._auth_got_frame = False
        self._auth_event.clear()
        self._authenticated = False
        challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
        auth_payload = self._auth_challenge + challenge_hash

        auth_encrypted = build_frame(CMD_AUTH, None, auth_payload, encrypt=True)
        _LOGGER.info("Sending encrypted auth frame (%d bytes)", len(auth_encrypted))

        self._status = "authenticating"
        self._last_error = "Bezig met authenticeren..."
        self._notify_callbacks()

        try:
            await asyncio.wait_for(
                self._client.write_gatt_char(BLE_WRITE_UUID, auth_encrypted, response=False),
                timeout=3.0,
            )
        except Exception as err:
            _LOGGER.warning("Auth write failed: %s", err)
            return False

        auth_ok = await self._wait_for_auth()
        if self._authenticated:
            return True

        if self._auth_got_frame:
            _LOGGER.info("Encrypted auth got response but failed validation, trying plaintext")
        elif self._is_connected:
            _LOGGER.info("No response to encrypted auth, trying plaintext fallback")
        else:
            return False

        if not self._is_connected or self._client is None:
            return False

        self._auth_challenge = os.urandom(4)
        self._auth_got_frame = False
        self._auth_event.clear()
        self._authenticated = False
        challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
        auth_payload = self._auth_challenge + challenge_hash
        auth_plaintext = build_frame(CMD_AUTH, None, auth_payload, encrypt=False)

        _LOGGER.info("Sending plaintext auth frame (%d bytes)", len(auth_plaintext))
        try:
            await asyncio.wait_for(
                self._client.write_gatt_char(BLE_WRITE_UUID, auth_plaintext, response=False),
                timeout=3.0,
            )
        except Exception as err:
            _LOGGER.warning("Plaintext auth write failed: %s", err)
            return False

        await self._wait_for_auth()
        if self._authenticated:
            _LOGGER.info("Auth succeeded with plaintext frame")
            return True

        if self._auth_got_frame and not self._authenticated:
            new_key = rotate_rc4_key()
            _LOGGER.info("Auth got frame but failed - rotated RC4 key to: %s", new_key or "(no more)")

        return False

    async def _wait_for_auth(self) -> bool:
        client = self._client
        if client is None:
            return False

        poll_interval = 0.15
        max_polls = int(AUTH_TIMEOUT / poll_interval)
        last_data = None

        for i in range(max_polls):
            if self._authenticated or self._auth_got_frame:
                return True
            if self._auth_event.is_set():
                return True
            if not self._is_connected or self._client is None:
                return False

            try:
                data = await asyncio.wait_for(
                    client.read_gatt_char(BLE_READ_UUID),
                    timeout=2.0,
                )
                if data and len(data) > 0 and data != last_data:
                    _LOGGER.debug("Auth poll: new data %d bytes", len(data))
                    last_data = data
                    self._process_incoming_data(data)
                    if self._authenticated or self._auth_event.is_set():
                        return True
            except asyncio.TimeoutError:
                pass
            except (BleakError, EOFError) as err:
                _LOGGER.debug("Auth poll read error: %s", err)
            except Exception as err:
                _LOGGER.debug("Auth poll error: %s", err)

            await asyncio.sleep(poll_interval)

        _LOGGER.info("Auth wait timeout after %.1fs", AUTH_TIMEOUT)
        return False

    async def _get_ble_device(self):
        if self._hass is not None:
            try:
                from homeassistant.components.bluetooth import async_ble_device_from_address
                ble_device = async_ble_device_from_address(self._hass, self._address, connectable=True)
                if ble_device:
                    return ble_device
                _LOGGER.info("Device %s not found via HA Bluetooth", self._address)
                self._status = "offline"
                self._last_error = "Machine niet gevonden via Bluetooth. Staat de machine aan?"
                self._notify_callbacks()
                return None
            except ImportError:
                self._status = "offline"
                self._last_error = "Bluetooth-integratie niet beschikbaar"
                self._notify_callbacks()
                return None
            except Exception as err:
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

    async def _internal_disconnect(self):
        await self._stop_dbus_notifications()

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
        ble_device = await self._get_ble_device()
        if ble_device is None:
            return False

        try:
            await self._establish_ble_connection(ble_device)
            self._is_connected = True
            _LOGGER.debug("BLE reconnect succeeded for %s", self._address)
            await asyncio.sleep(0.3)
            return True
        except Exception as err:
            _LOGGER.debug("BLE reconnect failed for %s: %s", self._address, err)
            self._client = None
            self._is_connected = False
            return False

    async def _get_char_path(self) -> str | None:
        from .dbus_utils import get_char_path_from_services, get_char_path_via_dbus
        path = get_char_path_from_services(self._client, BLE_READ_UUID)
        if path:
            return path
        return await get_char_path_via_dbus(self._address, BLE_READ_UUID)

    async def _force_bluez_disconnect(self):
        from .dbus_utils import dbus_force_disconnect
        await dbus_force_disconnect(self._address)

    async def _stop_dbus_notifications(self):
        from .dbus_utils import dbus_cleanup_notification_handler
        await dbus_cleanup_notification_handler(
            self._dbus_notify_bus, self._dbus_notify_handler, self._dbus_match_rule,
        )
        self._dbus_notify_bus = None
        self._dbus_notify_handler = None
        self._dbus_match_rule = None
        self._notifications_active = False

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
            _LOGGER.debug("Status request failed: %s", err)

    async def _start_polling(self):
        last_data = None
        try:
            while self._is_connected and not self._shutting_down:
                client = self._client
                if client is None:
                    break
                try:
                    data = await client.read_gatt_char(BLE_READ_UUID)
                    if data and len(data) > 0 and data != last_data:
                        last_data = data
                        self._process_incoming_data(data)
                except (BleakError, EOFError, OSError):
                    if not self._is_connected or self._shutting_down:
                        break
                except Exception:
                    if not self._is_connected or self._shutting_down:
                        break
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            pass

    def _stop_polling(self):
        if self._polling_task and not self._polling_task.done():
            self._polling_task.cancel()
            self._polling_task = None

    async def async_update(self):
        if not self._is_connected:
            self.schedule_reconnect()
            return

        if self._connect_pending or self._connect_lock.locked():
            return

        if self._is_connected and not self._authenticated:
            auth_ok = await self._do_authenticate()
            if self._authenticated:
                self._status = "ready"
                self._start_keepalive()
                self._notify_callbacks()

        if self._authenticated:
            await self._request_status()

    async def brew(self, beverage_type: int, strength: int | None = None, cups: int | None = None) -> bool:
        if not self._authenticated or not self._session_key:
            _LOGGER.warning("Cannot brew: not authenticated")
            return False

        s = strength if strength is not None else self._strength
        c = cups if cups is not None else self._cups
        payload = bytes([beverage_type & 0xFF, s & 0xFF, c & 0xFF])

        bev_name = BEVERAGE_NAMES.get(beverage_type, f"type_{beverage_type}")
        _LOGGER.info("Brewing: %s (type=%d), strength=%d, cups=%d", bev_name, beverage_type, s, c)

        try:
            frame = build_frame(CMD_BREW, self._session_key, payload, encrypt=True)
            await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=False)
            _LOGGER.info("Brew command sent for %s", bev_name)
            return True
        except Exception as err:
            _LOGGER.error("Brew command failed: %s", err)
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
        _LOGGER.info("Disconnect requested for %s", self._address)
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

        await self._stop_dbus_notifications()

        if self._client:
            if self._is_connected:
                try:
                    await asyncio.wait_for(self._client.disconnect(), timeout=DISCONNECT_TIMEOUT)
                except (BleakError, asyncio.TimeoutError, OSError):
                    pass
            self._client = None

        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        self._status = "offline"
        self._shutting_down = False
        self._notify_callbacks()
        _LOGGER.info("Disconnect complete for %s", self._address)
