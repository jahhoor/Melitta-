import logging
from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, CONF_MAC_ADDRESS, MACHINE_STATE_PRODUCT
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]
    entities = [
        MelittaConnectedSensor(device, entry),
        MelittaBrewingSensor(device, entry),
        MelittaDripTraySensor(device, entry),
    ]
    async_add_entities(entities)


class MelittaBaseBinarySensor(BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        self._device = device
        self._entry = entry
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.data[CONF_MAC_ADDRESS])},
            name=device.name,
            manufacturer="Melitta",
            model="Caffeo Barista",
            sw_version="2.0.0",
        )
        self._remove_callback = None

    async def async_added_to_hass(self):
        self._remove_callback = self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self):
        if self._remove_callback:
            self._remove_callback()

    @callback
    def _handle_update(self):
        self.async_write_ha_state()


class MelittaConnectedSensor(MelittaBaseBinarySensor):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_connected"
        self._attr_name = "Connected"

    @property
    def is_on(self) -> bool:
        return self._device.is_connected and self._device.is_authenticated


class MelittaBrewingSensor(MelittaBaseBinarySensor):
    _attr_device_class = BinarySensorDeviceClass.RUNNING

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_brewing"
        self._attr_name = "Brewing"
        self._attr_icon = "mdi:coffee"

    @property
    def is_on(self) -> bool:
        return self._device.machine_state == MACHINE_STATE_PRODUCT


class MelittaDripTraySensor(MelittaBaseBinarySensor):
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_drip_tray"
        self._attr_name = "Drip Tray Full"
        self._attr_icon = "mdi:tray-full"

    @property
    def is_on(self) -> bool:
        return self._device.drip_tray_full

    @property
    def available(self) -> bool:
        return self._device.is_authenticated
