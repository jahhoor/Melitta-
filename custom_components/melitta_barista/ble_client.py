"""BLE client for Melitta Barista Smart coffee machine.

Connection flow (matching dzerik/melitta-barista-ha proven architecture):
1. BLE connect via establish_connection(pair=False)
2. D-Bus: check if already paired
3. If not paired: D-Bus pair_device() with Agent1
4. Disconnect → stabilization delay → reconnect
5. D-Bus: force_encryption (Pair with AlreadyExists expected)
6. Dual-channel notifications: Bleak start_notify + D-Bus CCCD write
7. Verify Notifying=True (with retry)
8. HU handshake (EfCom protocol auth)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak.exc import BleakDBusError, BleakError

from .const import (
    CHAR_NOTIFY,
    CHAR_WRITE,
    DEFAULT_BLE_CONNECT_TIMEOUT,
    DEFAULT_FRAME_TIMEOUT,
    DEFAULT_MAX_CONSECUTIVE_ERRORS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_RECIPE_RETRIES,
    DEFAULT_RECONNECT_DELAY,
    DEFAULT_RECONNECT_MAX_DELAY,
    MACHINE_MODEL_NAMES,
    MACHINE_TYPE_SETTING_ID,
    MachineProcess,
    MachineType,
    RecipeId,
    RECIPE_NAMES,
    TEMP_RECIPE_ID,
    FREESTYLE_NAME_ID,
    get_recipe_key,
    detect_machine_type_from_name,
)
from .protocol import MachineRecipe, MachineStatus, MelittaProtocol

_LOGGER = logging.getLogger("melitta_barista")

MELITTA_SERVICE_UUID = "0000ad00-b35c-11e4-9813-0002a5d5c51b"

_STABILIZATION_DELAY = 0.8
_NOTIFY_RETRY_DELAY = 0.5
_NOTIFY_MAX_RETRIES = 3
_RECONNECT_AFTER_PAIR_RETRIES = 2


class MelittaBleClient:
    """BLE client managing connection and communication with the machine."""

    def __init__(
        self,
        address: str,
        device_name: str | None = None,
        ble_device: BLEDevice | None = None,
        *,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        ble_connect_timeout: float = DEFAULT_BLE_CONNECT_TIMEOUT,
        frame_timeout: int = DEFAULT_FRAME_TIMEOUT,
        max_consecutive_errors: int = DEFAULT_MAX_CONSECUTIVE_ERRORS,
        reconnect_delay: float = DEFAULT_RECONNECT_DELAY,
        reconnect_max_delay: float = DEFAULT_RECONNECT_MAX_DELAY,
        recipe_retries: int = DEFAULT_RECIPE_RETRIES,
    ) -> None:
        self._address = address
        self._device_name = device_name
        self._ble_device: BLEDevice | None = ble_device
        self._client: BleakClient | None = None
        self._protocol = MelittaProtocol(frame_timeout=frame_timeout)

        self._poll_interval = poll_interval
        self._ble_connect_timeout = ble_connect_timeout
        self._frame_timeout = frame_timeout
        self._max_consecutive_errors = max_consecutive_errors
        self._reconnect_delay = reconnect_delay
        self._reconnect_max_delay = reconnect_max_delay
        self._recipe_retries = recipe_retries

        self._connected = False
        self._connect_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._brew_lock = asyncio.Lock()

        self._status: MachineStatus | None = None
        self._firmware: str | None = None
        self._machine_type: MachineType | None = None

        self._status_callbacks: list[Callable[[MachineStatus], None]] = []
        self._connection_callbacks: list[Callable[[bool], None]] = []

        self._poll_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._reconnect_event = asyncio.Event()
        self._auto_reconnect = True
        self._disconnecting = False

        self._paired = False
        self._has_bluez = True

        self._selected_intensity: int = 2
        self._selected_two_cups: bool = False

        if device_name:
            self._machine_type = detect_machine_type_from_name(device_name)

    @property
    def address(self) -> str:
        return self._address

    @property
    def connected(self) -> bool:
        client = self._client
        return self._connected and client is not None and client.is_connected

    @property
    def status(self) -> MachineStatus | None:
        return self._status

    @property
    def firmware_version(self) -> str | None:
        return self._firmware

    @property
    def machine_type(self) -> MachineType | None:
        return self._machine_type

    @property
    def model_name(self) -> str:
        if self._machine_type:
            return MACHINE_MODEL_NAMES.get(self._machine_type, "Melitta Barista")
        return "Melitta Barista"

    @property
    def selected_intensity(self) -> int:
        return self._selected_intensity

    @selected_intensity.setter
    def selected_intensity(self, value: int) -> None:
        self._selected_intensity = max(0, min(4, value))

    @property
    def selected_two_cups(self) -> bool:
        return self._selected_two_cups

    @selected_two_cups.setter
    def selected_two_cups(self, value: bool) -> None:
        self._selected_two_cups = bool(value)

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Update BLEDevice reference from HA bluetooth advertisements."""
        self._ble_device = ble_device
        if not self._connected and self._auto_reconnect:
            _LOGGER.debug(
                "BLE advertisement from %s while disconnected, triggering reconnect",
                self._address,
            )
            self._reconnect_event.set()
            if not self._reconnect_task or self._reconnect_task.done():
                self._schedule_reconnect()

    def add_status_callback(self, callback: Callable[[MachineStatus], None]) -> None:
        self._status_callbacks.append(callback)

    def remove_status_callback(self, callback: Callable[[MachineStatus], None]) -> None:
        try:
            self._status_callbacks.remove(callback)
        except ValueError:
            pass

    def add_connection_callback(self, callback: Callable[[bool], None]) -> None:
        self._connection_callbacks.append(callback)

    def remove_connection_callback(self, callback: Callable[[bool], None]) -> None:
        try:
            self._connection_callbacks.remove(callback)
        except ValueError:
            pass

    def _on_status(self, status: MachineStatus) -> None:
        self._status = status
        for cb in self._status_callbacks:
            try:
                cb(status)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Error in status callback")

    def _on_disconnect(self, client: BleakClient) -> None:
        if self._disconnecting:
            return
        if client is not self._client:
            _LOGGER.debug("Ignoring disconnect callback from stale client")
            return
        _LOGGER.info("Disconnected from %s", self._address)
        self._connected = False
        self._client = None
        self._stop_polling()
        for cb in self._connection_callbacks:
            try:
                cb(False)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Error in connection callback")
        if self._auto_reconnect:
            self._schedule_reconnect()

    def _on_notification(self, _sender: int, data: bytearray) -> None:
        self._protocol.on_ble_data(bytes(data))

    async def _write_ble(self, data: bytes) -> None:
        async with self._write_lock:
            client = self._client
            if not client or not client.is_connected:
                raise BleakError("Not connected")
            try:
                await client.write_gatt_char(CHAR_WRITE, data, response=False)
            except AssertionError:
                _LOGGER.debug("D-Bus connection lost during write (assert self._bus)")
                raise BleakError("D-Bus connection lost")

    # ------------------------------------------------------------------
    # BLE connection helpers
    # ------------------------------------------------------------------

    async def _establish_connection(self) -> BleakClient:
        """Establish BLE connection using bleak_retry_connector when available."""
        if self._ble_device is not None:
            try:
                from bleak_retry_connector import (
                    BleakClientWithServiceCache,
                    establish_connection,
                )

                _LOGGER.debug(
                    "Using establish_connection for %s", self._address,
                )
                client = await establish_connection(
                    BleakClientWithServiceCache,
                    self._ble_device,
                    self._device_name or self._address,
                    disconnected_callback=self._on_disconnect,
                    use_services_cache=True,
                    ble_device_callback=lambda: self._ble_device,
                    max_attempts=3,
                )
                return client
            except ImportError:
                _LOGGER.debug(
                    "bleak_retry_connector not available, using raw BleakClient"
                )
            except (BleakError, OSError, asyncio.TimeoutError):
                _LOGGER.debug(
                    "establish_connection failed, falling back to raw BleakClient",
                    exc_info=True,
                )

        _LOGGER.debug("Using raw BleakClient for %s", self._address)
        client = BleakClient(
            self._ble_device or self._address,
            disconnected_callback=self._on_disconnect,
            timeout=self._ble_connect_timeout,
        )
        await client.connect()
        return client

    async def _start_notify(self, client: BleakClient) -> None:
        """Subscribe to BLE notifications via Bleak.

        Handles "Notify acquired" (stale BlueZ D-Bus state) as success.
        Uses BlueZStartNotifyArgs when available (bleak 2.0+).
        """
        try:
            try:
                from bleak.args.bluez import BlueZStartNotifyArgs
                await client.start_notify(
                    CHAR_NOTIFY,
                    self._on_notification,
                    bluez=BlueZStartNotifyArgs(use_start_notify=True),
                )
                return
            except (ImportError, TypeError):
                pass

            await client.start_notify(CHAR_NOTIFY, self._on_notification)

        except BleakDBusError as err:
            if "Notify acquired" in str(err):
                _LOGGER.debug(
                    "BlueZ notifications already acquired for %s — treating as success",
                    CHAR_NOTIFY,
                )
            else:
                raise

    async def _setup_notifications(self, client: BleakClient) -> bool:
        """Set up dual-channel notifications: Bleak + D-Bus CCCD write.

        Returns True if notifications are confirmed active.
        """
        try:
            await self._start_notify(client)
        except (BleakError, OSError, asyncio.TimeoutError) as err:
            _LOGGER.debug("Bleak start_notify failed: %s", err)
            return False

        if not self._has_bluez:
            return True

        from . import dbus_utils

        char_uuid = str(CHAR_NOTIFY)
        await dbus_utils.write_cccd(self._address, char_uuid, enable=True)

        for attempt in range(_NOTIFY_MAX_RETRIES):
            notifying = await dbus_utils.check_notifying(self._address, char_uuid)
            if notifying:
                _LOGGER.debug("Notifications confirmed active (attempt %d)", attempt + 1)
                return True
            _LOGGER.debug(
                "Notifying=False (attempt %d/%d), retrying...",
                attempt + 1, _NOTIFY_MAX_RETRIES,
            )
            await asyncio.sleep(_NOTIFY_RETRY_DELAY)
            await dbus_utils.write_cccd(self._address, char_uuid, enable=True)

        _LOGGER.warning(
            "Could not confirm Notifying=True for %s after %d attempts",
            self._address, _NOTIFY_MAX_RETRIES,
        )
        return False

    async def _safe_disconnect(self) -> None:
        """Disconnect current client, suppressing errors."""
        client = self._client
        self._client = None
        if client:
            try:
                await client.disconnect()
            except (BleakError, OSError):
                pass

    async def _try_unpair(self) -> None:
        """Clear stale bond via D-Bus RemoveDevice or Bleak unpair."""
        if self._has_bluez:
            from . import dbus_utils
            await dbus_utils.unpair_device(self._address)
        else:
            try:
                _LOGGER.debug("Clearing stale bond for %s via Bleak unpair", self._address)
                client = await self._establish_connection()
                try:
                    await client.unpair()
                except (BleakError, OSError, NotImplementedError, AttributeError):
                    _LOGGER.debug("unpair() failed or not supported", exc_info=True)
                finally:
                    try:
                        await client.disconnect()
                    except (BleakError, OSError):
                        pass
            except (BleakError, OSError, asyncio.TimeoutError):
                _LOGGER.debug("Could not connect for unpair", exc_info=True)

    # ------------------------------------------------------------------
    # Main connection flow
    # ------------------------------------------------------------------

    async def _try_connect_and_handshake(self) -> bool:
        """Full connection flow with D-Bus pairing integration.

        Flow:
        1. BLE connect (establish_connection, no pair flag)
        2. D-Bus: check paired → pair if needed → disconnect/reconnect
        3. D-Bus: force encryption
        4. Dual-channel notifications (Bleak + D-Bus CCCD)
        5. Verify Notifying=True
        6. HU handshake

        Returns True on success, False on failure (cleans up client).
        """
        self._protocol = MelittaProtocol(frame_timeout=self._frame_timeout)
        self._protocol.set_status_callback(self._on_status)

        try:
            self._client = await self._establish_connection()
        except (BleakError, OSError, asyncio.TimeoutError):
            _LOGGER.debug("BLE connect failed", exc_info=True)
            self._client = None
            return False

        if not self._client or not self._client.is_connected:
            _LOGGER.debug("BLE client not connected after establish")
            self._client = None
            return False

        _LOGGER.debug("BLE connected to %s", self._address)

        if self._has_bluez:
            from . import dbus_utils

            paired = await dbus_utils.check_paired(self._address)

            if paired is None or paired is False:
                _LOGGER.info("Device %s not paired, initiating D-Bus pairing", self._address)
                pair_result = await dbus_utils.pair_device(self._address)
                if pair_result not in ("ok",):
                    _LOGGER.info(
                        "D-Bus pairing returned %s for %s", pair_result, self._address
                    )
                    if pair_result in ("pairing_failed", "pairing_timeout", "not_found"):
                        await self._safe_disconnect()
                        return False

                _LOGGER.debug("Disconnecting after fresh pair for reconnect cycle")
                self._disconnecting = True
                await self._safe_disconnect()
                self._disconnecting = False

                await asyncio.sleep(_STABILIZATION_DELAY)

                for reconnect_attempt in range(_RECONNECT_AFTER_PAIR_RETRIES):
                    try:
                        self._client = await self._establish_connection()
                        if self._client and self._client.is_connected:
                            _LOGGER.debug(
                                "Reconnected after pair (attempt %d)",
                                reconnect_attempt + 1,
                            )
                            break
                    except (BleakError, OSError, asyncio.TimeoutError):
                        _LOGGER.debug(
                            "Reconnect after pair attempt %d failed",
                            reconnect_attempt + 1,
                            exc_info=True,
                        )
                        self._client = None
                    await asyncio.sleep(_STABILIZATION_DELAY)
                else:
                    _LOGGER.debug("All reconnect attempts after pair failed")
                    return False

                if not self._client or not self._client.is_connected:
                    _LOGGER.debug("Not connected after pair reconnect cycle")
                    return False

                self._paired = True

            await asyncio.sleep(_STABILIZATION_DELAY)

            enc_ok = await dbus_utils.force_encryption(self._address)
            if not enc_ok:
                _LOGGER.debug("force_encryption failed (non-fatal, continuing)")

            if not self._client or not self._client.is_connected:
                _LOGGER.debug("Connection lost after force_encryption")
                await self._safe_disconnect()
                return False

            await asyncio.sleep(0.5)

        if not await self._setup_notifications(self._client):
            _LOGGER.debug("Notification setup failed")
            await self._safe_disconnect()
            return False

        if not self._client or not self._client.is_connected:
            _LOGGER.debug("Connection lost after notification setup")
            await self._safe_disconnect()
            return False

        if not await self._protocol.perform_handshake(self._write_ble):
            _LOGGER.debug("HU handshake failed")
            await self._safe_disconnect()
            return False

        return True

    async def connect(self) -> bool:
        """Connect to the coffee machine.

        Strategy:
        1. Try normal connect with D-Bus pairing integration
        2. If fail: unpair stale bond, retry
        """
        async with self._connect_lock:
            return await self._connect_impl()

    async def _connect_impl(self) -> bool:
        """Internal connect implementation (must be called under _connect_lock)."""
        if self._connected and self._client and self._client.is_connected:
            return True

        if self._reconnect_task and not self._reconnect_task.done():
            if asyncio.current_task() is not self._reconnect_task:
                self._reconnect_task.cancel()
                self._reconnect_task = None

        try:
            if self._has_bluez:
                from . import dbus_utils
                self._has_bluez = await dbus_utils.has_bluez_adapter()
                if not self._has_bluez:
                    _LOGGER.info(
                        "No BlueZ adapter found (ESPHome proxy?), skipping D-Bus operations"
                    )

            _LOGGER.info("Connecting to Melitta at %s", self._address)

            if await self._try_connect_and_handshake():
                self._paired = True
            else:
                _LOGGER.info("First attempt failed, clearing bond and retrying for %s", self._address)
                await self._try_unpair()
                await asyncio.sleep(_STABILIZATION_DELAY)

                if not await self._try_connect_and_handshake():
                    _LOGGER.info("Connection failed for %s after unpair+retry", self._address)
                    return False
                self._paired = True

            self._connected = True
            _LOGGER.info("Connected and handshake complete for %s", self._address)

            self._firmware = await self._protocol.read_version(self._write_ble)
            _LOGGER.debug("Firmware: %s", self._firmware)

            type_id = await self._protocol.read_numerical(
                self._write_ble, MACHINE_TYPE_SETTING_ID,
            )
            if type_id is not None:
                try:
                    self._machine_type = MachineType(type_id)
                except ValueError:
                    _LOGGER.debug("Unknown machine type ID: %d", type_id)
            _LOGGER.debug("Machine type: %s", self._machine_type)

            for cb in self._connection_callbacks:
                try:
                    cb(True)
                except Exception:  # noqa: BLE001
                    _LOGGER.exception("Error in connection callback")

            self._start_polling()
            return True

        except (BleakError, OSError, asyncio.TimeoutError):
            _LOGGER.exception("Connection failed for %s", self._address)
            self._connected = False
            await self._safe_disconnect()
            return False

    # ------------------------------------------------------------------
    # Disconnect
    # ------------------------------------------------------------------

    async def disconnect(self) -> None:
        """Disconnect from the machine and stop all background tasks."""
        self._auto_reconnect = False
        self._disconnecting = True
        self._stop_polling()

        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            self._reconnect_task = None

        client = self._client
        self._client = None
        self._connected = False
        if client:
            try:
                if client.is_connected:
                    try:
                        await client.stop_notify(CHAR_NOTIFY)
                    except (BleakError, OSError):
                        _LOGGER.debug("stop_notify during disconnect failed", exc_info=True)
                await client.disconnect()
            except (BleakError, OSError):
                _LOGGER.debug("Error during disconnect", exc_info=True)

        self._disconnecting = False

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def _start_polling(self) -> None:
        """Start the status polling loop."""
        self._stop_polling()
        self._poll_task = asyncio.create_task(self._poll_loop())

    def _stop_polling(self) -> None:
        """Stop the status polling loop."""
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            self._poll_task = None

    async def _poll_loop(self) -> None:
        """Continuously poll machine status."""
        consecutive_errors = 0
        while self.connected:
            try:
                status = await self._protocol.read_status(self._write_ble)
                if status:
                    self._status = status
                    for cb in self._status_callbacks:
                        try:
                            cb(status)
                        except Exception:
                            pass
                    consecutive_errors = 0
                else:
                    consecutive_errors += 1
            except (BleakError, OSError, asyncio.TimeoutError):
                consecutive_errors += 1
                _LOGGER.debug(
                    "Poll error (%d/%d)",
                    consecutive_errors, self._max_consecutive_errors,
                    exc_info=True,
                )
                if consecutive_errors >= self._max_consecutive_errors:
                    _LOGGER.warning(
                        "Poll failed %d times in a row for %s, forcing disconnect",
                        self._max_consecutive_errors, self._address,
                    )
                    self._connected = False
                    await self._safe_disconnect()
                    for cb in self._connection_callbacks:
                        try:
                            cb(False)
                        except Exception:
                            _LOGGER.exception("Error in connection callback")
                    if self._auto_reconnect:
                        self._schedule_reconnect()
                    return
            except asyncio.CancelledError:
                return
            except Exception:
                _LOGGER.exception("Unexpected poll error")
                consecutive_errors += 1

            await asyncio.sleep(self._poll_interval)

    # ------------------------------------------------------------------
    # Reconnect
    # ------------------------------------------------------------------

    def _schedule_reconnect(self) -> None:
        """Schedule a reconnect attempt."""
        if self._reconnect_task and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        """Try to reconnect with exponential backoff."""
        delay = self._reconnect_delay
        while self._auto_reconnect and not self.connected:
            _LOGGER.debug("Reconnecting to %s in %.0fs...", self._address, delay)
            self._reconnect_event.clear()
            try:
                await asyncio.wait_for(self._reconnect_event.wait(), timeout=delay)
                _LOGGER.debug("Reconnect woken up early (BLE advertisement received)")
                delay = self._reconnect_delay
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                return

            if not self._auto_reconnect:
                break

            try:
                if await self.connect():
                    _LOGGER.info("Reconnected to %s", self._address)
                    return
            except (BleakError, OSError, asyncio.TimeoutError):
                _LOGGER.debug("Reconnect attempt failed", exc_info=True)
            except Exception:
                _LOGGER.exception("Unexpected error during reconnect")

            delay = min(delay * 2, self._reconnect_max_delay)

    # ------------------------------------------------------------------
    # Brewing
    # ------------------------------------------------------------------

    async def brew_recipe(
        self,
        recipe_id: RecipeId,
        *,
        two_cups: bool | None = None,
        intensity: int | None = None,
    ) -> bool:
        """Brew a recipe by reading it, writing to temp slot, then starting process.

        ``two_cups`` and ``intensity`` default to the user's current selections
        when not explicitly provided.
        """
        if self._brew_lock.locked():
            _LOGGER.warning("Brew already in progress, ignoring")
            return False

        if not self.connected:
            _LOGGER.warning("Not connected, cannot brew")
            return False

        if self._status and not self._status.is_ready:
            _LOGGER.warning("Machine not ready: %s", self._status)
            return False

        use_two_cups = self._selected_two_cups if two_cups is None else two_cups
        use_intensity = self._selected_intensity if intensity is None else max(0, min(4, intensity))

        self._stop_polling()
        async with self._brew_lock:
            try:
                recipe = None
                for attempt in range(self._recipe_retries):
                    recipe = await self._protocol.read_recipe(
                        self._write_ble, int(recipe_id)
                    )
                    if recipe:
                        break
                    _LOGGER.debug("Read recipe %d attempt %d failed", recipe_id, attempt + 1)
                    await asyncio.sleep(0.3)

                if not recipe:
                    _LOGGER.warning("Failed to read recipe %d", recipe_id)
                    return False

                from dataclasses import replace
                comp1 = replace(recipe.component1, intensity=use_intensity)
                comp2 = replace(recipe.component2, intensity=use_intensity)

                if not await self._protocol.write_recipe(
                    self._write_ble,
                    TEMP_RECIPE_ID,
                    recipe.recipe_type,
                    comp1,
                    comp2,
                    recipe_key=get_recipe_key(recipe.recipe_type),
                ):
                    _LOGGER.warning("Failed to write recipe to temp slot")
                    return False

                await asyncio.sleep(0.2)

                name = RECIPE_NAMES.get(recipe_id, str(recipe_id))
                if not await self._protocol.write_alphanumeric(
                    self._write_ble, FREESTYLE_NAME_ID, name,
                ):
                    _LOGGER.warning("Failed to write recipe name")
                    return False

                await asyncio.sleep(0.2)

                result = await self._protocol.start_process(
                    self._write_ble,
                    int(MachineProcess.PRODUCT),
                    two_cups=use_two_cups,
                )
                if result:
                    _LOGGER.info(
                        "Started brewing %s (intensity=%d, two_cups=%s)",
                        name, use_intensity, use_two_cups,
                    )
                else:
                    _LOGGER.warning("start_process returned False for %s", name)
                return result

            finally:
                if self.connected:
                    self._start_polling()

    async def cancel_brewing(self) -> bool:
        """Cancel the current brewing process."""
        if not self.connected:
            return False
        return await self._protocol.cancel_process(
            self._write_ble, int(MachineProcess.PRODUCT)
        )
