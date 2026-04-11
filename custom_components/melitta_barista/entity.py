"""Base entity for Melitta Barista Smart."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from .ble_client import MelittaBleClient
from .const import DOMAIN
from .protocol import MachineStatus

_LOGGER = logging.getLogger("melitta_barista")


class MelittaBaseEntity(Entity):
    """Base class for all Melitta Barista entities."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        client: MelittaBleClient,
        entry: ConfigEntry,
        address: str,
    ) -> None:
        self._client = client
        self._address = address
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
