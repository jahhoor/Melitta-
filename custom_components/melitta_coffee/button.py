import logging
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import (
    DOMAIN, CONF_MAC_ADDRESS,
    BEVERAGE_ESPRESSO, BEVERAGE_RISTRETTO, BEVERAGE_LUNGO,
    BEVERAGE_ESPRESSO_DOPIO, BEVERAGE_CAFE_CREME,
    BEVERAGE_AMERICANO, BEVERAGE_CAPPUCCINO,
    BEVERAGE_LATTE_MACCHIATO, BEVERAGE_CAFE_LATTE,
    BEVERAGE_FLAT_WHITE, BEVERAGE_MILK_FOAM,
    BEVERAGE_WARM_MILK, BEVERAGE_HOT_WATER,
    BEVERAGE_NAMES,
)
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)

BREW_BUTTONS = [
    BEVERAGE_ESPRESSO,
    BEVERAGE_RISTRETTO,
    BEVERAGE_LUNGO,
    BEVERAGE_ESPRESSO_DOPIO,
    BEVERAGE_CAFE_CREME,
    BEVERAGE_AMERICANO,
    BEVERAGE_CAPPUCCINO,
    BEVERAGE_LATTE_MACCHIATO,
    BEVERAGE_CAFE_LATTE,
    BEVERAGE_FLAT_WHITE,
    BEVERAGE_MILK_FOAM,
    BEVERAGE_WARM_MILK,
    BEVERAGE_HOT_WATER,
]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for bev_type in BREW_BUTTONS:
        entities.append(MelittaBrewButton(device, entry, bev_type))
    async_add_entities(entities)


class MelittaBrewButton(ButtonEntity):
    _attr_has_entity_name = True

    def __init__(self, device: MelittaDevice, entry: ConfigEntry, beverage_type: int):
        self._device = device
        self._beverage_type = beverage_type
        bev_name = BEVERAGE_NAMES.get(beverage_type, f"Beverage {beverage_type}")
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_brew_{beverage_type}"
        self._attr_name = f"Brew {bev_name}"
        self._attr_icon = "mdi:coffee"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data[CONF_MAC_ADDRESS])},
            "name": device.name,
            "manufacturer": "Melitta",
            "model": "Caffeo Barista",
        }

    @property
    def available(self) -> bool:
        return self._device.is_authenticated

    async def async_press(self) -> None:
        await self._device.brew(self._beverage_type)
