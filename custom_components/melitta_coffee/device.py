import asyncio
import logging
import os
import struct
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

AUTH_TIMEOUT = 6.0
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
        self._authenticated = False
        self._is_connected = False
        self._shutting_down = False
        self._keepalive_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._connect_lock = asyncio.Lock()
        self._connect_pending = False
        self._callbacks: list[Callable] = []
        self._status = "offline"
        self._machine_state: int | None = None
        self._machine_state_name: str = "Unknown"
        self._last_error: str | None = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = RECONNECT_MAX_ATTEMPTS
        self._disconnect_in_progress = False
        self._suppress_disconnect_callback = False
        self._notify_mode = "notifications"
        self._polling_task: asyncio.Task | None = None
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
        if self._suppress_disconnect_callback:
            _LOGGER.debug("Ignoring disconnect callback (suppressed during internal disconnect)")
            return
        if client is not self._client:
            _LOGGER.debug("Ignoring disconnect callback from stale client")
            return
        if self._disconnect_in_progress:
            _LOGGER.debug("Ignoring duplicate disconnect callback (already processing)")
            return

        self._disconnect_in_progress = True
        try:
            was_auth = self._status == "authenticating"
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
                self._last_error = "Machine dropped connection during authentication. Press 'Verbinden' on the machine display."
                self._auth_event.set()
            elif prev_status == "connecting":
                self._status = "offline"
                self._last_error = "Verbinding verbroken tijdens opzetten"
                use_fast_reconnect = True
            elif not self._shutting_down:
                self._status = "offline"
                self._last_error = "Connection lost"

            _LOGGER.warning(
                "DISCONNECTED from %s: prev_status=%s, was_auth=%s, shutting_down=%s, new_status=%s",
                self._address, prev_status, was_auth, self._shutting_down, self._status,
            )
            self._notify_callbacks()

            if not self._shutting_down:
                self.schedule_reconnect(fast=use_fast_reconnect)
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
        if self._connect_pending:
            _LOGGER.debug("Connect already in progress for %s, skipping schedule", self._address)
            return
        if self._reconnect_task and not self._reconnect_task.done():
            _LOGGER.debug("Reconnect already scheduled for %s", self._address)
            return

        if fast and self._reconnect_attempts < 2:
            delay = 3.0
        else:
            capped_attempts = min(self._reconnect_attempts, 5)
            delay = min(RECONNECT_BASE_DELAY * (2 ** capped_attempts), RECONNECT_MAX_DELAY)
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
        _LOGGER.info("BLE RX notification: %d bytes, raw_hex=%s, sender=%s", len(data), data.hex(), sender)
        self._process_incoming_data(data)

    def _process_incoming_data(self, data: bytes):
        frames = self._parser.feed(data)
        if not frames:
            _LOGGER.debug("No complete frames parsed (buffering)")
        for frame in frames:
            _LOGGER.info("Parsed frame: %s", frame)
            self._handle_frame(frame)

    async def _start_polling(self):
        _LOGGER.info("Starting BLE characteristic polling on %s (fallback mode)", BLE_READ_UUID)
        self._notify_mode = "polling"
        last_data = None
        try:
            while self._is_connected and not self._shutting_down:
                client = self._client
                if client is None:
                    _LOGGER.debug("Polling: client is None, stopping")
                    break
                try:
                    data = await client.read_gatt_char(BLE_READ_UUID)
                    if data and len(data) > 0 and data != last_data:
                        _LOGGER.warning("BLE POLL RX: %d bytes, raw_hex=%s", len(data), data.hex())
                        last_data = data
                        self._process_incoming_data(data)
                except BleakError as err:
                    if not self._is_connected or self._shutting_down or self._client is None:
                        break
                    _LOGGER.debug("Polling read error (non-fatal): %s", err)
                except Exception as err:
                    if not self._is_connected or self._shutting_down or self._client is None:
                        break
                    _LOGGER.debug("Polling error (non-fatal): %s", err)
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            _LOGGER.debug("Polling task cancelled")
        _LOGGER.debug("Polling loop ended")

    def _stop_polling(self):
        if self._polling_task and not self._polling_task.done():
            self._polling_task.cancel()
            self._polling_task = None

    def _handle_frame(self, frame: EfComFrame):
        _LOGGER.debug("Received frame: %s", frame)

        if frame.command == CMD_AUTH:
            self._handle_auth_response(frame)
        elif frame.command == CMD_STATUS:
            self._handle_status_response(frame)
        elif frame.command == CMD_KEEPALIVE:
            if len(frame.payload) >= 11:
                _LOGGER.debug(
                    "Version/keepalive response: payload=%s (%d bytes)",
                    frame.payload.hex(), len(frame.payload),
                )
            else:
                _LOGGER.debug("Keepalive acknowledged")
        elif frame.command == "A":
            _LOGGER.debug("ACK received")
        elif frame.command == "N":
            _LOGGER.warning("NACK received")
        else:
            _LOGGER.debug("Unhandled frame: %s", frame)

    def _handle_auth_response(self, frame: EfComFrame):
        payload = frame.payload
        _LOGGER.warning(
            "AUTH RESPONSE: %d bytes, hex=%s, encrypted=%s",
            len(payload), payload.hex(), frame.encrypted,
        )
        if len(payload) != 8:
            _LOGGER.warning(
                "AUTH FAIL: unexpected payload length %d (expected 8). "
                "Raw payload hex: %s",
                len(payload), payload.hex(),
            )
            self._auth_event.set()
            return

        echo = payload[0:4]
        session = payload[4:6]
        hash_received = payload[6:8]

        _LOGGER.warning(
            "AUTH FIELDS: echo=%s, session_key=%s, hash=%s",
            echo.hex(), session.hex(), hash_received.hex(),
        )

        if self._auth_challenge is None:
            _LOGGER.warning("AUTH FAIL: no pending challenge")
            self._auth_event.set()
            return

        _LOGGER.warning(
            "AUTH ECHO CHECK: sent=%s, received=%s, match=%s",
            self._auth_challenge.hex(), echo.hex(), echo == self._auth_challenge,
        )

        if echo != self._auth_challenge:
            _LOGGER.warning(
                "AUTH FAIL: echo mismatch. We sent challenge=%s but machine echoed=%s. "
                "This means the machine is responding to a different auth request, "
                "or decryption produced wrong bytes.",
                self._auth_challenge.hex(), echo.hex(),
            )
            self._auth_event.set()
            return

        verify_data = payload[0:6]
        expected_hash = sbox_hash(verify_data, len(verify_data))
        hash_match = hash_received == expected_hash
        _LOGGER.warning(
            "AUTH HASH CHECK: expected=%s, received=%s, match=%s, verify_data=%s",
            expected_hash.hex(), hash_received.hex(), hash_match, verify_data.hex(),
        )

        if not hash_match:
            _LOGGER.warning(
                "AUTH: SBOX hash mismatch but echo matched! "
                "Accepting session anyway (SBOX table may differ per model). "
                "expected_hash=%s, received_hash=%s",
                expected_hash.hex(), hash_received.hex(),
            )

        self._session_key = session
        self._authenticated = True
        _LOGGER.warning(
            "AUTH SUCCESS: session_key=%s, echo_match=%s, hash_match=%s, encrypted=%s",
            session.hex(), True, hash_match, frame.encrypted,
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
        if self._client is None:
            return
        old_client = self._client
        self._client = None
        self._is_connected = False
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
        ble_device = None
        if self._hass is not None:
            try:
                from homeassistant.components.bluetooth import async_ble_device_from_address
                ble_device = async_ble_device_from_address(self._hass, self._address, connectable=True)
                if not ble_device:
                    _LOGGER.warning("Device not found during internal reconnect")
                    return False
            except Exception as e:
                _LOGGER.error("Failed to get BLEDevice during internal reconnect: %s", e)
                return False
        else:
            ble_device = self._address

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
            _LOGGER.info("Internal BLE reconnect succeeded for %s", self._address)
            await asyncio.sleep(0.3)
            return True
        except Exception as err:
            _LOGGER.error("Internal BLE reconnect failed: %s", err)
            self._client = None
            self._is_connected = False
            return False

    async def _start_notifications_with_retry(self) -> str:
        self._cancel_reconnect()

        if not self._client or not self._is_connected:
            _LOGGER.warning("No client/connection for notify setup")
            return "failed"

        try:
            await self._client.stop_notify(BLE_READ_UUID)
            _LOGGER.debug("stop_notify succeeded")
        except Exception as e:
            _LOGGER.debug("stop_notify skipped (non-fatal): %s", e)

        try:
            await self._client.start_notify(
                BLE_READ_UUID, self._on_notification,
                **{"use_start_notify": True}
            )
            _LOGGER.info("BLE notifications active via StartNotify (bleak >= 2.1.0)")
            self._notify_mode = "notifications"
            return "ok"
        except TypeError:
            _LOGGER.info("use_start_notify not available (bleak < 2.1.0), trying AcquireNotify")
            try:
                await self._client.start_notify(BLE_READ_UUID, self._on_notification)
                _LOGGER.info("BLE notifications active via AcquireNotify")
                self._notify_mode = "notifications"
                return "ok"
            except BleakError as err:
                err_msg = str(err)
                if "Notify acquired" in err_msg or "NotPermitted" in err_msg:
                    _LOGGER.warning("AcquireNotify blocked by stale BlueZ state: %s", err_msg)
                    return "notify_acquired"
                _LOGGER.error("Notification error (AcquireNotify): %s", err)
                return "failed"
            except EOFError:
                _LOGGER.error("D-Bus connection crashed (EOFError) during AcquireNotify - BlueZ connection lost")
                return "dbus_crash"
        except BleakError as err:
            err_msg = str(err)
            if "Notify acquired" in err_msg or "NotPermitted" in err_msg:
                _LOGGER.warning("StartNotify blocked by stale BlueZ state: %s", err_msg)
                return "notify_acquired"
            _LOGGER.error("Notification error (StartNotify): %s", err)
            return "failed"
        except EOFError:
            _LOGGER.error("D-Bus connection crashed (EOFError) during StartNotify - BlueZ connection lost")
            return "dbus_crash"

    async def _clear_stale_bluez_notifications(self) -> bool:
        mac_path = self._address.replace(":", "_").upper()
        read_uuid_short = BLE_READ_UUID.replace("-", "")

        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType
            import re

            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspect_root = Message(
                    destination="org.bluez",
                    path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_root)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"

                    introspect_dev = Message(
                        destination="org.bluez",
                        path=device_path,
                        interface="org.freedesktop.DBus.Introspectable",
                        member="Introspect",
                    )
                    dev_reply = await bus.call(introspect_dev)
                    if dev_reply.message_type == MessageType.ERROR:
                        _LOGGER.debug("Device %s not found on %s", device_path, adapter)
                        continue

                    services = re.findall(r'<node name="(service\w+)"', dev_reply.body[0]) if dev_reply.body else []
                    for service in services:
                        service_path = f"{device_path}/{service}"
                        intro_svc = Message(
                            destination="org.bluez",
                            path=service_path,
                            interface="org.freedesktop.DBus.Introspectable",
                            member="Introspect",
                        )
                        svc_reply = await bus.call(intro_svc)
                        if svc_reply.message_type == MessageType.ERROR:
                            continue
                        chars = re.findall(r'<node name="(char\w+)"', svc_reply.body[0]) if svc_reply.body else []
                        for char in chars:
                            char_path = f"{service_path}/{char}"
                            uuid_msg = Message(
                                destination="org.bluez",
                                path=char_path,
                                interface="org.freedesktop.DBus.Properties",
                                member="Get",
                                signature="ss",
                                body=["org.bluez.GattCharacteristic1", "UUID"],
                            )
                            uuid_reply = await bus.call(uuid_msg)
                            if uuid_reply.message_type == MessageType.ERROR:
                                continue
                            char_uuid = str(uuid_reply.body[0].value if uuid_reply.body else "")
                            if char_uuid.replace("-", "").lower() == read_uuid_short.lower():
                                _LOGGER.info(
                                    "Found stale notification characteristic at %s, sending StopNotify",
                                    char_path,
                                )
                                stop_msg = Message(
                                    destination="org.bluez",
                                    path=char_path,
                                    interface="org.bluez.GattCharacteristic1",
                                    member="StopNotify",
                                )
                                stop_reply = await bus.call(stop_msg)
                                if stop_reply.message_type == MessageType.ERROR:
                                    _LOGGER.debug(
                                        "StopNotify on %s: %s %s",
                                        char_path, stop_reply.error_name, stop_reply.body,
                                    )
                                else:
                                    _LOGGER.info(
                                        "StopNotify succeeded on %s - stale notification state cleared",
                                        char_path,
                                    )
                                    return True
            finally:
                bus.disconnect()
        except ImportError:
            _LOGGER.debug("dbus_fast not available for StopNotify")
        except Exception as err:
            _LOGGER.debug("D-Bus StopNotify failed: %s (%s)", err, type(err).__name__)

        return False

    async def _remove_device_from_bluez(self) -> bool:
        mac_path = self._address.replace(":", "_").upper()

        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import Message, MessageType, BusType
            import re

            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspect_msg = Message(
                    destination="org.bluez",
                    path="/org/bluez",
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                )
                reply = await bus.call(introspect_msg)
                adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else ["hci0"]
                if not adapters:
                    adapters = ["hci0"]

                for adapter in adapters:
                    device_path = f"/org/bluez/{adapter}/dev_{mac_path}"
                    adapter_path = f"/org/bluez/{adapter}"
                    _LOGGER.info(
                        "Removing %s from BlueZ via D-Bus (adapter=%s, path=%s)",
                        self._address, adapter, device_path,
                    )
                    remove_msg = Message(
                        destination="org.bluez",
                        path=adapter_path,
                        interface="org.bluez.Adapter1",
                        member="RemoveDevice",
                        signature="o",
                        body=[device_path],
                    )
                    rm_reply = await bus.call(remove_msg)
                    if rm_reply.message_type == MessageType.ERROR:
                        _LOGGER.debug(
                            "RemoveDevice on %s: %s %s",
                            adapter, rm_reply.error_name, rm_reply.body,
                        )
                        continue
                    _LOGGER.info(
                        "Successfully removed %s from BlueZ cache (adapter=%s). "
                        "Stale notification state cleared.",
                        self._address, adapter,
                    )
                    return True
            finally:
                bus.disconnect()
        except ImportError:
            _LOGGER.debug("dbus_fast not available for RemoveDevice")
        except Exception as err:
            _LOGGER.debug("D-Bus RemoveDevice failed: %s (%s)", err, type(err).__name__)

        try:
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "remove", self._address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = (stdout or b"").decode() + (stderr or b"").decode()
            if proc.returncode == 0 or "removed" in output.lower():
                _LOGGER.info("Removed %s from BlueZ via bluetoothctl", self._address)
                return True
            _LOGGER.debug("bluetoothctl remove output: %s", output.strip())
        except FileNotFoundError:
            _LOGGER.debug("bluetoothctl not found")
        except Exception as err:
            _LOGGER.debug("bluetoothctl remove failed: %s", err)

        _LOGGER.warning(
            "Could not remove %s from BlueZ automatically. "
            "To fix manually, run: bluetoothctl remove %s",
            self._address, self._address,
        )
        return False

    async def _do_connect(self) -> bool:
        self._cancel_reconnect()

        if self._client is not None:
            _LOGGER.debug("Cleaning up previous BLE client before reconnect")
            await self._internal_disconnect()
            await asyncio.sleep(1.0)

        _LOGGER.info(
            "Connecting to %s (attempt %d, polling-first mode)",
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

            await asyncio.sleep(0.3)

            if not self._is_connected or self._shutting_down:
                _LOGGER.warning("Connection lost during settle for %s", self._address)
                return False

            _LOGGER.info(
                "Starting polling-first mode on %s (bypasses D-Bus StartNotify issues)",
                BLE_READ_UUID,
            )
            self._notify_mode = "polling"
            self._polling_task = asyncio.ensure_future(self._start_polling())

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
                _LOGGER.info("CONNECTED and AUTHENTICATED with %s (polling mode)", self._address)
                await self._request_status()
            else:
                self._status = "connected_not_auth"
                _LOGGER.warning(
                    "Connected but NOT authenticated to %s - "
                    "machine may need pairing button press",
                    self._address,
                )

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

    async def _wait_for_device_rediscovery(self, timeout: float = 15.0) -> bool:
        if self._hass is None:
            await asyncio.sleep(2.0)
            return True

        end_time = asyncio.get_event_loop().time() + timeout
        attempt = 0
        while asyncio.get_event_loop().time() < end_time:
            attempt += 1
            try:
                from homeassistant.components.bluetooth import async_ble_device_from_address
                device = async_ble_device_from_address(self._hass, self._address, connectable=True)
                if device:
                    _LOGGER.info(
                        "Device %s rediscovered after BlueZ reset (attempt %d)",
                        self._address, attempt,
                    )
                    return True
            except Exception:
                pass
            await asyncio.sleep(2.0)

        _LOGGER.warning("Device %s not rediscovered within %.0fs", self._address, timeout)
        return False

    async def _authenticate(self):
        self._auth_challenge = os.urandom(4)
        challenge_hash = sbox_hash(self._auth_challenge, len(self._auth_challenge))
        auth_payload = self._auth_challenge + challenge_hash

        _LOGGER.warning(
            "AUTH START: challenge=%s, sbox_hash=%s, full_payload=%s (6 bytes)",
            self._auth_challenge.hex(), challenge_hash.hex(), auth_payload.hex(),
        )

        auth_encrypted = build_frame(CMD_AUTH, None, auth_payload, encrypt=True)
        auth_plaintext = build_frame(CMD_AUTH, None, auth_payload, encrypt=False)

        _LOGGER.warning(
            "AUTH FRAMES: encrypted=%s (%d bytes), plaintext=%s (%d bytes)",
            auth_encrypted.hex(), len(auth_encrypted),
            auth_plaintext.hex(), len(auth_plaintext),
        )

        auth_attempts = [
            (auth_encrypted, "encrypted", False, 0.3),
            (auth_plaintext, "plaintext", False, 0.5),
            (auth_encrypted, "encrypted-with-response", True, 0.5),
            (auth_plaintext, "plaintext-with-response", True, 0.5),
        ]

        for attempt, (frame, desc, with_response, retry_delay) in enumerate(auth_attempts):
            if not self._is_connected or self._client is None:
                _LOGGER.warning("Connection lost before auth attempt %d", attempt + 1)
                return

            self._auth_event.clear()
            self._authenticated = False

            _LOGGER.warning(
                "AUTH ATTEMPT %d/%d (%s): writing %d bytes to %s (response=%s)",
                attempt + 1, len(auth_attempts), desc, len(frame), BLE_WRITE_UUID, with_response,
            )

            try:
                await self._client.write_gatt_char(BLE_WRITE_UUID, frame, response=with_response)
                _LOGGER.warning("AUTH WRITE OK (%s)", desc)
            except Exception as err:
                _LOGGER.warning("AUTH WRITE FAILED (%s): %s", desc, err)
                if not self._is_connected or self._client is None:
                    _LOGGER.warning("Connection lost after auth write failure")
                    return
                await asyncio.sleep(retry_delay)
                continue

            try:
                await asyncio.wait_for(self._auth_event.wait(), timeout=AUTH_TIMEOUT)
            except asyncio.TimeoutError:
                _LOGGER.warning(
                    "AUTH TIMEOUT after %.1fs with %s frame (no response via polling). "
                    "Machine may not be in pairing mode.",
                    AUTH_TIMEOUT, desc,
                )
                await asyncio.sleep(retry_delay)
                continue

            if self._authenticated:
                _LOGGER.warning("AUTH SUCCEEDED with %s frame on attempt %d", desc, attempt + 1)
                return

            _LOGGER.warning("AUTH attempt %d (%s) got a response but validation FAILED", attempt + 1, desc)
            await asyncio.sleep(retry_delay)

        self._last_error = (
            "Authenticatie mislukt. Controleer of de machine in koppelmodus staat. "
            "Druk op de Bluetooth-knop op het display van de machine."
        )
        _LOGGER.error(
            "ALL %d auth attempts FAILED for %s - machine may need pairing confirmation. "
            "Tried encrypted+plaintext with response=False and response=True.",
            len(auth_attempts), self._address,
        )

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
        _LOGGER.info("Disconnecting from %s...", self._address)
        self._shutting_down = True
        self._cancel_reconnect()
        self._stop_polling()

        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except (asyncio.CancelledError, Exception):
                pass
            self._keepalive_task = None

        if self._client:
            if self._is_connected:
                try:
                    _LOGGER.debug("Stopping BLE notifications on %s", BLE_READ_UUID)
                    await asyncio.wait_for(
                        self._client.stop_notify(BLE_READ_UUID),
                        timeout=5.0,
                    )
                except (BleakError, asyncio.TimeoutError, OSError, Exception) as err:
                    _LOGGER.debug("Stop notify error (non-critical): %s", err)

                try:
                    _LOGGER.debug("Disconnecting BLE client...")
                    await asyncio.wait_for(self._client.disconnect(), timeout=DISCONNECT_TIMEOUT)
                    _LOGGER.info("BLE disconnected cleanly from %s", self._address)
                except (BleakError, asyncio.TimeoutError, OSError) as err:
                    _LOGGER.warning("Disconnect error: %s", err)

            self._client = None

        self._is_connected = False
        self._authenticated = False
        self._session_key = None
        self._status = "offline"
        self._shutting_down = False
        self._notify_callbacks()
        _LOGGER.info("Disconnect complete for %s", self._address)
