import asyncio
import logging
from datetime import datetime
from typing import Any, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError

from .const import (
    MELITTA_SERVICE_UUID,
    MELITTA_CONTROL_CHAR_UUID,
    MELITTA_STATUS_CHAR_UUID,
    MELITTA_NOTIFY_CHAR_UUID,
    MACHINE_STATUS_MAP,
    STRENGTH_MAP,
    BEVERAGE_MAP,
    WATER_LEVEL_MAP,
    BEAN_LEVEL_MAP,
    ERROR_MAP,
    CONNECT_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)

MELITTA_KEYWORDS = ["melitta", "caffeo", "barista"]
RECONNECT_INTERVALS = [5, 10, 30, 60, 120]


class MelittaDevice:

    def __init__(self, address: str, name: str = "Melitta", hass=None) -> None:
        self._address = address
        self._name = name
        self._hass = hass
        self._client: BleakClient | None = None
        self._is_connected = False
        self._has_ever_connected = False
        self._status = "offline"
        self._water_level = "unknown"
        self._bean_level = "unknown"
        self._error: str | None = None
        self._is_brewing = False
        self._current_beverage: str | None = None
        self._strength = "medium"
        self._cups = 1
        self._temperature: int | None = None
        self._total_brews = 0
        self._callbacks: list[Callable] = []
        self._lock = asyncio.Lock()
        self._control_char: str | None = None
        self._status_char: str | None = None
        self._notify_char: str | None = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 5
        self._reconnect_task: asyncio.Task | None = None
        self._shutting_down = False
        self._last_connect_time: str | None = None
        self._last_error_message: str | None = None
        self._services_discovered = False
        self._discovered_services_info: str = "Nog niet verbonden"

    @property
    def address(self) -> str:
        return self._address

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def status(self) -> str:
        return self._status

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
                        return True
                except Exception:
                    pass
                self._is_connected = False
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
                self._status = "idle"
                self._reconnect_attempts = 0
                self._last_connect_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._last_error_message = None

                await self._discover_services()
                await self._subscribe_notifications()
                await self._request_status()

                _LOGGER.info("Connected to Melitta at %s", self._address)
                self._notify_callbacks()
                return True

            except (BleakError, asyncio.TimeoutError, OSError) as err:
                error_msg = str(err)
                _LOGGER.warning("Failed to connect to Melitta at %s: %s", self._address, error_msg)
                self._is_connected = False
                self._client = None
                self._last_error_message = error_msg
                if not self._has_ever_connected:
                    self._status = "offline"
                self._notify_callbacks()
                return False

    async def disconnect(self) -> None:
        self._shutting_down = True

        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

        async with self._lock:
            if self._client:
                try:
                    await self._client.disconnect()
                except (BleakError, OSError):
                    pass
                self._client = None
            self._is_connected = False
            self._status = "offline"
            self._notify_callbacks()

    def _on_disconnect(self, client: BleakClient) -> None:
        _LOGGER.info("Disconnected from Melitta at %s", self._address)
        self._is_connected = False
        self._client = None
        self._notify_callbacks()

        if not self._shutting_down:
            self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        if self._reconnect_task and not self._reconnect_task.done():
            return

        if self._reconnect_attempts >= self._max_reconnect_attempts:
            _LOGGER.info(
                "Max reconnect attempts (%d) reached for %s, will retry on next update cycle",
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
                _LOGGER.debug("Attempting reconnect to %s", self._address)
                connected = await self.connect()
                if not connected and not self._shutting_down:
                    self._schedule_reconnect()
        except asyncio.CancelledError:
            pass
        except Exception as err:
            _LOGGER.debug("Reconnect failed for %s: %s", self._address, err)
            if not self._shutting_down:
                self._schedule_reconnect()

    async def _ensure_connected(self) -> bool:
        if self._is_connected and self._client:
            try:
                if self._client.is_connected:
                    return True
            except Exception:
                pass
            self._is_connected = False
            self._client = None

        return await self.connect()

    async def _discover_services(self) -> None:
        if not self._client or not self._is_connected:
            return

        try:
            services = self._client.services
            info_lines = []
            all_write_chars = []
            all_read_chars = []
            all_notify_chars = []

            for service in services:
                svc_desc = service.description or "Onbekend"
                info_lines.append(f"Service: {service.uuid} ({svc_desc})")
                _LOGGER.info("=== BLE Service: %s (%s) ===", service.uuid, svc_desc)

                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    char_desc = char.description or ""
                    info_lines.append(f"  Kenmerk: {char.uuid} [{props}] {char_desc}")
                    _LOGGER.info(
                        "  Characteristic: %s props=[%s] desc=%s handle=%s",
                        char.uuid, props, char_desc, char.handle,
                    )

                    for desc in char.descriptors:
                        info_lines.append(f"    Descriptor: {desc.uuid}")
                        _LOGGER.info("    Descriptor: %s handle=%s", desc.uuid, desc.handle)

                    uuid_lower = char.uuid.lower()
                    if uuid_lower == MELITTA_CONTROL_CHAR_UUID.lower():
                        self._control_char = char.uuid
                    elif uuid_lower == MELITTA_STATUS_CHAR_UUID.lower():
                        self._status_char = char.uuid
                    elif uuid_lower == MELITTA_NOTIFY_CHAR_UUID.lower():
                        self._notify_char = char.uuid

                    if "write" in char.properties or "write-without-response" in char.properties:
                        all_write_chars.append(char.uuid)
                    if "read" in char.properties:
                        all_read_chars.append(char.uuid)
                    if "notify" in char.properties or "indicate" in char.properties:
                        all_notify_chars.append(char.uuid)

            info_lines.append("")
            info_lines.append(f"Schrijfbare kenmerken: {', '.join(all_write_chars) or 'Geen'}")
            info_lines.append(f"Leesbare kenmerken: {', '.join(all_read_chars) or 'Geen'}")
            info_lines.append(f"Notificatie kenmerken: {', '.join(all_notify_chars) or 'Geen'}")

            if not self._control_char and all_write_chars:
                self._control_char = all_write_chars[0]
                _LOGGER.info("Fallback control char: %s", self._control_char)

            if not self._status_char and all_read_chars:
                for rc in all_read_chars:
                    if rc != self._control_char:
                        self._status_char = rc
                        _LOGGER.info("Fallback status char: %s", self._status_char)
                        break

            if not self._notify_char and all_notify_chars:
                self._notify_char = all_notify_chars[0]
                _LOGGER.info("Fallback notify char: %s", self._notify_char)

            info_lines.append("")
            info_lines.append(f"Geselecteerd - Schrijven: {self._control_char or 'Geen'}")
            info_lines.append(f"Geselecteerd - Lezen: {self._status_char or 'Geen'}")
            info_lines.append(f"Geselecteerd - Notificaties: {self._notify_char or 'Geen'}")

            self._discovered_services_info = "\n".join(info_lines)

            self._services_discovered = bool(self._control_char or self._status_char or self._notify_char)

            if not self._services_discovered:
                _LOGGER.warning(
                    "No usable GATT characteristics found on %s. "
                    "The device may use a different BLE protocol than expected.",
                    self._address,
                )
                self._last_error_message = "Geen bruikbare Bluetooth-kenmerken gevonden"
                self._discovered_services_info = "Geen bruikbare kenmerken gevonden op dit apparaat"

            _LOGGER.info(
                "Discovery complete - control: %s, status: %s, notify: %s (discovered=%s)",
                self._control_char, self._status_char, self._notify_char,
                self._services_discovered,
            )

        except (BleakError, OSError) as err:
            _LOGGER.error("Failed to discover services: %s", err)
            self._last_error_message = f"Service discovery mislukt: {err}"
            self._discovered_services_info = f"Discovery mislukt: {err}"

    async def _subscribe_notifications(self) -> None:
        if not self._client or not self._notify_char:
            _LOGGER.debug("Cannot subscribe: client=%s, notify_char=%s", bool(self._client), self._notify_char)
            return

        try:
            await self._client.start_notify(
                self._notify_char, self._handle_notification
            )
            _LOGGER.debug("Subscribed to notifications on %s", self._notify_char)
        except (BleakError, OSError) as err:
            _LOGGER.warning("Failed to subscribe to notifications: %s", err)

    def _handle_notification(self, sender: Any, data: bytearray) -> None:
        _LOGGER.debug("Notification from %s: %s", sender, data.hex())
        self._parse_status_data(data)
        self._notify_callbacks()

    def _parse_status_data(self, data: bytearray) -> None:
        if len(data) < 1:
            return

        try:
            status_byte = data[0]
            self._status = MACHINE_STATUS_MAP.get(status_byte, f"unknown_{status_byte:#x}")

            if self._status == "brewing":
                self._is_brewing = True
            elif self._is_brewing and self._status in ("idle", "standby"):
                self._is_brewing = False
                self._total_brews += 1

            if len(data) >= 2:
                self._water_level = WATER_LEVEL_MAP.get(data[1], "unknown")

            if len(data) >= 3:
                self._bean_level = BEAN_LEVEL_MAP.get(data[2], "unknown")

            if len(data) >= 4:
                error_byte = data[3]
                self._error = ERROR_MAP.get(error_byte) if error_byte != 0 else None

            if len(data) >= 5:
                self._temperature = data[4]

        except (IndexError, ValueError) as err:
            _LOGGER.debug("Error parsing status data: %s", err)

    async def _request_status(self) -> None:
        if not self._client or not self._status_char:
            return

        try:
            data = await self._client.read_gatt_char(self._status_char)
            _LOGGER.debug("Status data: %s", data.hex())
            self._parse_status_data(bytearray(data))
        except (BleakError, OSError) as err:
            _LOGGER.warning("Failed to read status: %s", err)

    async def _write_command(self, command: bytes) -> bool:
        if not await self._ensure_connected():
            _LOGGER.warning("Cannot send command: not connected")
            return False

        if not self._control_char:
            _LOGGER.warning("No control characteristic discovered")
            return False

        try:
            await self._client.write_gatt_char(self._control_char, command)
            _LOGGER.debug("Sent command: %s", command.hex())
            return True
        except (BleakError, OSError) as err:
            _LOGGER.error("Failed to send command: %s", err)
            self._last_error_message = f"Commando mislukt: {err}"
            self._is_connected = False
            self._client = None
            self._notify_callbacks()
            self._schedule_reconnect()
            return False

    async def brew(
        self,
        beverage: str = "coffee",
        strength: str = "medium",
        cups: int = 1,
    ) -> bool:
        bev_code = BEVERAGE_MAP.get(beverage, 0x02)
        str_code = STRENGTH_MAP.get(strength, 0x02)
        cups_code = min(max(cups, 1), 12)

        command = bytes([0x0D, bev_code, str_code, cups_code, 0x01])
        self._current_beverage = beverage
        self._strength = strength
        self._cups = cups

        success = await self._write_command(command)
        if success:
            self._status = "brewing"
            self._is_brewing = True
            self._notify_callbacks()
        return success

    async def stop(self) -> bool:
        command = bytes([0x0D, 0x00, 0x00, 0x00, 0x00])
        success = await self._write_command(command)
        if success:
            self._status = "idle"
            self._is_brewing = False
            self._current_beverage = None
            self._notify_callbacks()
        return success

    async def clean(self) -> bool:
        command = bytes([0x0E, 0x01, 0x00, 0x00, 0x00])
        success = await self._write_command(command)
        if success:
            self._status = "cleaning"
            self._notify_callbacks()
        return success

    async def rinse(self) -> bool:
        command = bytes([0x0E, 0x02, 0x00, 0x00, 0x00])
        success = await self._write_command(command)
        if success:
            self._status = "rinsing"
            self._notify_callbacks()
        return success

    async def standby(self) -> bool:
        command = bytes([0x0F, 0x00, 0x00, 0x00, 0x00])
        success = await self._write_command(command)
        if success:
            self._status = "standby"
            self._notify_callbacks()
        return success

    async def wake_up(self) -> bool:
        command = bytes([0x0F, 0x01, 0x00, 0x00, 0x00])
        success = await self._write_command(command)
        if success:
            self._status = "idle"
            self._notify_callbacks()
        return success

    async def update(self) -> None:
        if not self._is_connected:
            connected = await self.connect()
            if not connected:
                return

        try:
            if self._client and self._client.is_connected:
                await self._request_status()
                self._notify_callbacks()
            else:
                self._is_connected = False
                self._client = None
                self._schedule_reconnect()
        except (BleakError, OSError) as err:
            _LOGGER.debug("Update failed for %s: %s", self._address, err)
            self._is_connected = False
            self._client = None
            self._schedule_reconnect()


async def discover_melitta_devices(timeout: float = 10.0) -> list[BLEDevice]:
    _LOGGER.debug("Scanning for Melitta devices...")
    devices = await BleakScanner.discover(timeout=timeout)

    melitta_devices = []
    for device in devices:
        name = device.name or ""
        if any(kw in name.lower() for kw in MELITTA_KEYWORDS):
            _LOGGER.info("Found Melitta device: %s (%s)", device.name, device.address)
            melitta_devices.append(device)

    return melitta_devices


async def discover_all_ble_devices(timeout: float = 10.0) -> list[BLEDevice]:
    _LOGGER.debug("Scanning for all BLE devices...")
    devices = await BleakScanner.discover(timeout=timeout)

    named_devices = []
    for device in devices:
        if device.name:
            _LOGGER.debug("Found BLE device: %s (%s)", device.name, device.address)
            named_devices.append(device)

    _LOGGER.info("Found %d named BLE devices", len(named_devices))
    return named_devices
