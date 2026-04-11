"""Button platform for Melitta Barista Smart."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .ble_client import MelittaBleClient
from .const import (
    DOMAIN,
    RecipeId,
    RECIPE_NAMES,
    TS_ONLY_RECIPES,
    MachineType,
)

_LOGGER = logging.getLogger("melitta_barista")

BREW_BUTTONS: list[int] = [
    RecipeId.ESPRESSO,
    RecipeId.RISTRETTO,
    RecipeId.LUNGO,
    RecipeId.ESPRESSO_DOPIO,
    RecipeId.CAFE_CREME,
    RecipeId.AMERICANO,
    RecipeId.CAPPUCCINO,
    RecipeId.LATTE_MACCHIATO,
    RecipeId.CAFFE_LATTE,
    RecipeId.FLAT_WHITE,
    RecipeId.MILK_FROTH,
    RecipeId.MILK,
    RecipeId.WATER,
    RecipeId.RED_EYE,
    RecipeId.BLACK_EYE,
    RecipeId.DEAD_EYE,
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up brew button entities."""
    client: MelittaBleClient = hass.data[DOMAIN][entry.entry_id]
    address: str = entry.data[CONF_ADDRESS]

    entities = [
        MelittaBrewButton(client, entry, address, recipe_id)
        for recipe_id in BREW_BUTTONS
    ]
    async_add_entities(entities)


class MelittaBrewButton(ButtonEntity):
    """Button to brew a specific recipe."""

    _attr_has_entity_name = True

    def __init__(
        self,
        client: MelittaBleClient,
        entry: ConfigEntry,
        address: str,
        recipe_id: int,
    ) -> None:
        self._client = client
        self._recipe_id = RecipeId(recipe_id)
        bev_name = RECIPE_NAMES.get(recipe_id, f"Recipe {recipe_id}")
        self._attr_unique_id = f"{address}_brew_{recipe_id}"
        self._attr_name = f"Brew {bev_name}"
        self._attr_icon = "mdi:coffee"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            name=entry.title,
            manufacturer="Melitta",
            model=client.model_name,
        )

    @property
    def available(self) -> bool:
        if not self._client.connected:
            return False
        if self._recipe_id in TS_ONLY_RECIPES:
            mt = self._client.machine_type
            if mt is not None and mt != MachineType.BARISTA_TS:
                return False
        return True

    async def async_press(self) -> None:
        """Brew the recipe."""
        _LOGGER.info("Brew button pressed: %s", RECIPE_NAMES.get(self._recipe_id, "?"))
        await self._client.brew_recipe(self._recipe_id)
