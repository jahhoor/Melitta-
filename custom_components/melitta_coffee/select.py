import logging
from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, CONF_MAC_ADDRESS
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)

STRENGTH_OPTIONS = ["Very Mild", "Mild", "Normal", "Strong", "Very Strong"]
STRENGTH_MAP = {name: idx for idx, name in enumerate(STRENGTH_OPTIONS)}

CUPS_OPTIONS = ["1", "2"]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]
    entities = [
        MelittaStrengthSelect(device, entry),
        MelittaCupsSelect(device, entry),
    ]
    async_add_entities(entities)


class MelittaStrengthSelect(SelectEntity):
    _attr_has_entity_name = True

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        self._device = device
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_strength"
        self._attr_name = "Strength"
        self._attr_icon = "mdi:coffee"
        self._attr_options = STRENGTH_OPTIONS
        self._attr_current_option = STRENGTH_OPTIONS[device.strength]
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data[CONF_MAC_ADDRESS])},
            "name": device.name,
            "manufacturer": "Melitta",
            "model": "Caffeo Barista",
        }
        self._remove_callback = None

    async def async_added_to_hass(self):
        self._remove_callback = self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self):
        if self._remove_callback:
            self._remove_callback()

    @callback
    def _handle_update(self):
        self._attr_current_option = STRENGTH_OPTIONS[self._device.strength]
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        return self._device.is_authenticated

    async def async_select_option(self, option: str) -> None:
        value = STRENGTH_MAP.get(option, 2)
        self._device.strength = value
        self._attr_current_option = option
        self.async_write_ha_state()


class MelittaCupsSelect(SelectEntity):
    _attr_has_entity_name = True

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        self._device = device
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_cups"
        self._attr_name = "Cups"
        self._attr_icon = "mdi:cup"
        self._attr_options = CUPS_OPTIONS
        self._attr_current_option = str(device.cups)
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data[CONF_MAC_ADDRESS])},
            "name": device.name,
            "manufacturer": "Melitta",
            "model": "Caffeo Barista",
        }
        self._remove_callback = None

    async def async_added_to_hass(self):
        self._remove_callback = self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self):
        if self._remove_callback:
            self._remove_callback()

    @callback
    def _handle_update(self):
        self._attr_current_option = str(self._device.cups)
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        return self._device.is_authenticated

    async def async_select_option(self, option: str) -> None:
        value = int(option)
        self._device.cups = value
        self._attr_current_option = option
        self.async_write_ha_state()
