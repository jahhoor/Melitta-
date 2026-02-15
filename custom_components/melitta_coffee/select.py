import logging

from homeassistant.components.select import SelectEntity
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
        MelittaStrengthSelect(device, entry),
        MelittaCupsSelect(device, entry),
    ]

    async_add_entities(entities)


class MelittaBaseSelect(SelectEntity):

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

    @property
    def available(self) -> bool:
        return True

    async def async_added_to_hass(self) -> None:
        self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self) -> None:
        self._device.remove_callback(self._handle_update)

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()


class MelittaStrengthSelect(MelittaBaseSelect):

    STRENGTH_OPTIONS = {
        "mild": "Mild",
        "medium": "Normaal",
        "strong": "Sterk",
        "extra_strong": "Extra Sterk",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_strength"
        self._attr_name = "Koffiesterkte"
        self._attr_icon = "mdi:gauge"
        self._attr_options = list(self.STRENGTH_OPTIONS.values())

    @property
    def current_option(self) -> str:
        return self.STRENGTH_OPTIONS.get(self._device.strength, "Normaal")

    async def async_select_option(self, option: str) -> None:
        reverse_map = {v: k for k, v in self.STRENGTH_OPTIONS.items()}
        strength = reverse_map.get(option, "medium")
        self._device.set_strength(strength)


class MelittaCupsSelect(MelittaBaseSelect):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_cups"
        self._attr_name = "Aantal kopjes"
        self._attr_icon = "mdi:cup-outline"
        self._attr_options = ["1", "2", "3", "4"]

    @property
    def current_option(self) -> str:
        return str(self._device.cups)

    async def async_select_option(self, option: str) -> None:
        self._device.set_cups(int(option))
