import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, CONF_DEVICE_NAME, CONF_MODEL, CONF_MAC_ADDRESS, BEVERAGE_MAP
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]

    entities = [
        MelittaBrewButton(device, entry, beverage)
        for beverage in BEVERAGE_MAP
    ]
    entities.extend([
        MelittaStopButton(device, entry),
        MelittaCleanButton(device, entry),
        MelittaRinseButton(device, entry),
        MelittaStandbyButton(device, entry),
        MelittaWakeUpButton(device, entry),
    ])

    async_add_entities(entities)


class MelittaBaseButton(ButtonEntity):

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


class MelittaBrewButton(MelittaBaseButton):

    BEVERAGE_NAMES = {
        "espresso": "Espresso",
        "coffee": "Koffie",
        "cappuccino": "Cappuccino",
        "latte_macchiato": "Latte Macchiato",
        "lungo": "Lungo",
        "hot_water": "Heet Water",
        "steam": "Stoom",
    }

    def __init__(
        self, device: MelittaDevice, entry: ConfigEntry, beverage: str
    ) -> None:
        super().__init__(device, entry)
        self._beverage = beverage
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_brew_{beverage}"
        self._attr_name = f"Zet {self.BEVERAGE_NAMES.get(beverage, beverage)}"
        self._attr_icon = "mdi:coffee"

    async def async_press(self) -> None:
        strength = self._device.strength
        cups = self._device.cups
        success = await self._device.brew(self._beverage, strength, cups)
        if not success:
            _LOGGER.warning("Failed to brew %s - machine may not be connected", self._beverage)


class MelittaStopButton(MelittaBaseButton):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_stop"
        self._attr_name = "Stop"
        self._attr_icon = "mdi:stop-circle"

    async def async_press(self) -> None:
        await self._device.stop()


class MelittaCleanButton(MelittaBaseButton):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_clean"
        self._attr_name = "Reinigen"
        self._attr_icon = "mdi:broom"

    async def async_press(self) -> None:
        await self._device.clean()


class MelittaRinseButton(MelittaBaseButton):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_rinse"
        self._attr_name = "Spoelen"
        self._attr_icon = "mdi:water"

    async def async_press(self) -> None:
        await self._device.rinse()


class MelittaStandbyButton(MelittaBaseButton):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_standby"
        self._attr_name = "Standby"
        self._attr_icon = "mdi:power-standby"

    async def async_press(self) -> None:
        await self._device.standby()


class MelittaWakeUpButton(MelittaBaseButton):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_wake_up"
        self._attr_name = "Inschakelen"
        self._attr_icon = "mdi:power"

    async def async_press(self) -> None:
        await self._device.wake_up()
