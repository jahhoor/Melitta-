import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, CONF_DEVICE_NAME, CONF_MODEL, CONF_MAC_ADDRESS
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]

    entities = [
        MelittaConnectedSensor(device, entry),
        MelittaBrewingSensor(device, entry),
    ]

    async_add_entities(entities)


class MelittaBaseBinarySensor(BinarySensorEntity):

    _attr_has_entity_name = True

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        self._device = device
        self._entry = entry

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.data[CONF_MAC_ADDRESS])},
            name=self._entry.data.get(CONF_DEVICE_NAME, "Melitta"),
            manufacturer="Melitta",
            model=self._entry.data.get(CONF_MODEL, "Barista Smart"),
        )

    async def async_added_to_hass(self) -> None:
        self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self) -> None:
        self._device.remove_callback(self._handle_update)

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()


class MelittaConnectedSensor(MelittaBaseBinarySensor):

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_connected"
        self._attr_name = "Verbonden"

    @property
    def is_on(self) -> bool:
        return self._device.is_connected

    @property
    def available(self) -> bool:
        return True


class MelittaBrewingSensor(MelittaBaseBinarySensor):

    _attr_device_class = BinarySensorDeviceClass.RUNNING

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_brewing"
        self._attr_name = "Bezig met zetten"
        self._attr_icon = "mdi:coffee"

    @property
    def is_on(self) -> bool:
        return self._device.is_brewing

    @property
    def available(self) -> bool:
        return self._device.is_connected
