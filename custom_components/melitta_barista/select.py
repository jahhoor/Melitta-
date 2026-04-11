"""Select platform for Melitta Barista Smart."""

from __future__ import annotations

import logging

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .ble_client import MelittaBleClient
from .const import DOMAIN
from .entity import MelittaBaseEntity

_LOGGER = logging.getLogger("melitta_barista")

INTENSITY_OPTIONS: list[str] = [
    "very_mild",
    "mild",
    "medium",
    "strong",
    "very_strong",
]

INTENSITY_LABELS: dict[str, str] = {
    "very_mild": "Very Mild",
    "mild": "Mild",
    "medium": "Medium",
    "strong": "Strong",
    "very_strong": "Very Strong",
}

CUPS_OPTIONS: list[str] = ["1", "2"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up select entities."""
    client: MelittaBleClient = hass.data[DOMAIN][entry.entry_id]
    address: str = entry.data[CONF_ADDRESS]

    async_add_entities([
        MelittaIntensitySelect(client, entry, address),
        MelittaCupsSelect(client, entry, address),
    ])


class MelittaIntensitySelect(MelittaBaseEntity, SelectEntity):
    """Select the default brew intensity."""

    _attr_icon = "mdi:coffee-maker"
    _attr_options = INTENSITY_OPTIONS

    def __init__(
        self,
        client: MelittaBleClient,
        entry: ConfigEntry,
        address: str,
    ) -> None:
        super().__init__(client, entry, address)
        self._attr_unique_id = f"{address}_intensity"
        self._attr_name = "Brew Intensity"

    @property
    def current_option(self) -> str:
        idx = self._client.selected_intensity
        if 0 <= idx < len(INTENSITY_OPTIONS):
            return INTENSITY_OPTIONS[idx]
        return INTENSITY_OPTIONS[2]

    async def async_select_option(self, option: str) -> None:
        if option in INTENSITY_OPTIONS:
            self._client.selected_intensity = INTENSITY_OPTIONS.index(option)
            self.async_write_ha_state()


class MelittaCupsSelect(MelittaBaseEntity, SelectEntity):
    """Select the number of cups to brew."""

    _attr_icon = "mdi:coffee"
    _attr_options = CUPS_OPTIONS

    def __init__(
        self,
        client: MelittaBleClient,
        entry: ConfigEntry,
        address: str,
    ) -> None:
        super().__init__(client, entry, address)
        self._attr_unique_id = f"{address}_cups"
        self._attr_name = "Cups"

    @property
    def current_option(self) -> str:
        return "2" if self._client.selected_two_cups else "1"

    async def async_select_option(self, option: str) -> None:
        self._client.selected_two_cups = option == "2"
        self.async_write_ha_state()
