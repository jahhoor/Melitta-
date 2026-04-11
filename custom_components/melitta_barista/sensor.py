"""Sensor platform for Melitta Barista Smart."""

from __future__ import annotations

import logging

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .ble_client import MelittaBleClient
from .const import DOMAIN, MachineProcess, Manipulation
from .protocol import MachineStatus

_LOGGER = logging.getLogger("melitta_barista")

MACHINE_STATE_NAMES: dict[int, str] = {
    MachineProcess.READY: "Ready",
    MachineProcess.PRODUCT: "Brewing",
    MachineProcess.CLEANING: "Cleaning",
    MachineProcess.DESCALING: "Descaling",
    MachineProcess.FILTER_INSERT: "Filter Insert",
    MachineProcess.FILTER_REPLACE: "Filter Replace",
    MachineProcess.FILTER_REMOVE: "Filter Remove",
    MachineProcess.SWITCH_OFF: "Switch Off",
    MachineProcess.EASY_CLEAN: "Easy Clean",
    MachineProcess.INTENSIVE_CLEAN: "Intensive Clean",
    MachineProcess.EVAPORATING: "Evaporating",
    MachineProcess.BUSY: "Busy",
}

MANIPULATION_NAMES: dict[int, str] = {
    Manipulation.NONE: "",
    Manipulation.BU_REMOVED: "Brew unit removed",
    Manipulation.TRAYS_MISSING: "Trays missing",
    Manipulation.EMPTY_TRAYS: "Empty trays",
    Manipulation.FILL_WATER: "Fill water",
    Manipulation.CLOSE_POWDER_LID: "Close powder lid",
    Manipulation.FILL_POWDER: "Fill powder",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensor entities."""
    client: MelittaBleClient = hass.data[DOMAIN][entry.entry_id]
    address: str = entry.data[CONF_ADDRESS]

    entities = [
        MelittaConnectionSensor(client, entry, address),
        MelittaStateSensor(client, entry, address),
        MelittaProgressSensor(client, entry, address),
        MelittaManipulationSensor(client, entry, address),
    ]
    async_add_entities(entities)


class MelittaBaseSensor(SensorEntity):
    """Base class for Melitta sensors."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        client: MelittaBleClient,
        entry: ConfigEntry,
        address: str,
    ) -> None:
        self._client = client
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            name=entry.title,
            manufacturer="Melitta",
            model=client.model_name,
        )

    async def async_added_to_hass(self) -> None:
        self._client.add_status_callback(self._handle_status)
        self._client.add_connection_callback(self._handle_connection)

    async def async_will_remove_from_hass(self) -> None:
        self._client.remove_status_callback(self._handle_status)
        self._client.remove_connection_callback(self._handle_connection)

    @callback
    def _handle_status(self, status: MachineStatus) -> None:
        self.async_write_ha_state()

    @callback
    def _handle_connection(self, connected: bool) -> None:
        self.async_write_ha_state()


class MelittaConnectionSensor(MelittaBaseSensor):
    """Shows whether the machine is connected."""

    def __init__(self, client: MelittaBleClient, entry: ConfigEntry, address: str) -> None:
        super().__init__(client, entry, address)
        self._attr_unique_id = f"{address}_connection"
        self._attr_name = "Connection"
        self._attr_icon = "mdi:bluetooth-connect"

    @property
    def native_value(self) -> str:
        if self._client.connected:
            return "Connected"
        return "Disconnected"


class MelittaStateSensor(MelittaBaseSensor):
    """Shows the current machine state."""

    def __init__(self, client: MelittaBleClient, entry: ConfigEntry, address: str) -> None:
        super().__init__(client, entry, address)
        self._attr_unique_id = f"{address}_state"
        self._attr_name = "State"
        self._attr_icon = "mdi:state-machine"

    @property
    def available(self) -> bool:
        return self._client.connected

    @property
    def native_value(self) -> str | None:
        status = self._client.status
        if status is None or status.process is None:
            return None
        return MACHINE_STATE_NAMES.get(status.process, f"State {status.process}")

    @property
    def extra_state_attributes(self) -> dict:
        status = self._client.status
        if status is None:
            return {}
        attrs: dict = {}
        if status.process is not None:
            attrs["process_code"] = int(status.process)
        if status.sub_process is not None:
            attrs["sub_process"] = int(status.sub_process)
        if status.info_messages:
            attrs["info_messages"] = int(status.info_messages)
        return attrs


class MelittaProgressSensor(MelittaBaseSensor):
    """Shows the brewing progress percentage."""

    def __init__(self, client: MelittaBleClient, entry: ConfigEntry, address: str) -> None:
        super().__init__(client, entry, address)
        self._attr_unique_id = f"{address}_progress"
        self._attr_name = "Brew Progress"
        self._attr_icon = "mdi:progress-clock"
        self._attr_native_unit_of_measurement = "%"

    @property
    def available(self) -> bool:
        status = self._client.status
        return self._client.connected and status is not None and status.is_brewing

    @property
    def native_value(self) -> int | None:
        status = self._client.status
        if status is None:
            return None
        return status.progress


class MelittaManipulationSensor(MelittaBaseSensor):
    """Shows when user action is required."""

    def __init__(self, client: MelittaBleClient, entry: ConfigEntry, address: str) -> None:
        super().__init__(client, entry, address)
        self._attr_unique_id = f"{address}_manipulation"
        self._attr_name = "Required Action"
        self._attr_icon = "mdi:alert-circle"

    @property
    def available(self) -> bool:
        return self._client.connected

    @property
    def native_value(self) -> str | None:
        status = self._client.status
        if status is None:
            return None
        name = MANIPULATION_NAMES.get(status.manipulation, f"Action {status.manipulation}")
        return name if name else "None"
