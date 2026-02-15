import asyncio
import logging
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


class MelittaDevice:

    def __init__(self, address: str, name: str = "Melitta") -> None:
        self._address = address
        self._name = name
        self._client: BleakClient | None = None
        self._is_connected = False
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
        self._max_reconnect_attempts = 3

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
                return True

            try:
                _LOGGER.debug("Connecting to Melitta at %s", self._address)
                self._client = BleakClient(
                    self._address,
                    timeout=CONNECT_TIMEOUT,
                    disconnected_callback=self._on_disconnect,
                )
                await self._client.connect()
                self._is_connected = True
                self._status = "idle"
                self._reconnect_attempts = 0

                await self._discover_services()
                await self._subscribe_notifications()
                await self._request_status()

                _LOGGER.info("Connected to Melitta at %s", self._address)
                self._notify_callbacks()
                return True

            except (BleakError, asyncio.TimeoutError, OSError) as err:
                _LOGGER.warning("Failed to connect to Melitta at %s: %s", self._address, err)
                self._is_connected = False
                self._status = "offline"
                self._client = None
                self._notify_callbacks()
                return False

    async def disconnect(self) -> None:
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
        self._status = "offline"
        self._client = None
        self._notify_callbacks()

    async def _ensure_connected(self) -> bool:
        if self._is_connected and self._client:
            return True

        if self._reconnect_attempts >= self._max_reconnect_attempts:
            _LOGGER.debug("Max reconnect attempts reached for %s", self._address)
            self._reconnect_attempts = 0
            return False

        self._reconnect_attempts += 1
        return await self.connect()

    async def _discover_services(self) -> None:
        if not self._client or not self._is_connected:
            return

        try:
            services = self._client.services

            for service in services:
                _LOGGER.debug("Service: %s", service.uuid)
                for char in service.characteristics:
                    _LOGGER.debug("  Char: %s props=%s", char.uuid, char.properties)

                    uuid_lower = char.uuid.lower()
                    if uuid_lower == MELITTA_CONTROL_CHAR_UUID.lower():
                        self._control_char = char.uuid
                    elif uuid_lower == MELITTA_STATUS_CHAR_UUID.lower():
                        self._status_char = char.uuid
                    elif uuid_lower == MELITTA_NOTIFY_CHAR_UUID.lower():
                        self._notify_char = char.uuid

            if not self._control_char:
                for service in services:
                    for char in service.characteristics:
                        if "write" in char.properties:
                            self._control_char = char.uuid
                            break
                    if self._control_char:
                        break

            if not self._status_char:
                for service in services:
                    for char in service.characteristics:
                        if "read" in char.properties and char.uuid != self._control_char:
                            self._status_char = char.uuid
                            break
                    if self._status_char:
                        break

            if not self._notify_char:
                for service in services:
                    for char in service.characteristics:
                        if "notify" in char.properties:
                            self._notify_char = char.uuid
                            break
                    if self._notify_char:
                        break

            _LOGGER.debug(
                "Discovered chars - control: %s, status: %s, notify: %s",
                self._control_char, self._status_char, self._notify_char,
            )

        except (BleakError, OSError) as err:
            _LOGGER.error("Failed to discover services: %s", err)

    async def _subscribe_notifications(self) -> None:
        if not self._client or not self._notify_char:
            return

        try:
            await self._client.start_notify(
                self._notify_char, self._handle_notification
            )
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

        await self._request_status()
        self._notify_callbacks()


async def discover_melitta_devices(timeout: float = 10.0) -> list[BLEDevice]:
    _LOGGER.debug("Scanning for Melitta devices...")
    devices = await BleakScanner.discover(timeout=timeout)

    melitta_devices = []
    for device in devices:
        name = device.name or ""
        if any(kw in name.lower() for kw in ["melitta", "caffeo", "barista"]):
            _LOGGER.info("Found Melitta device: %s (%s)", device.name, device.address)
            melitta_devices.append(device)

    return melitta_devices
