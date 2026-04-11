"""Config flow for Melitta Barista Smart."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS, CONF_NAME

from .const import BLE_PREFIXES_ALL, DOMAIN

_LOGGER = logging.getLogger("melitta_barista")


class MelittaBaristaConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Melitta Barista Smart."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovered_devices: dict[str, str] = {}
        self._address: str | None = None
        self._name: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle user-initiated setup."""
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input[CONF_ADDRESS].upper().strip()
            name = self._discovered_devices.get(address, f"Melitta Barista ({address})")

            await self.async_set_unique_id(address)
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=name,
                data={CONF_ADDRESS: address, CONF_NAME: name},
            )

        # Scan for discovered Melitta devices
        self._discovered_devices = {}
        try:
            for info in async_discovered_service_info(self.hass):
                name = info.name or ""
                for prefix in BLE_PREFIXES_ALL:
                    if name.startswith(prefix):
                        addr = info.address.upper()
                        self._discovered_devices[addr] = f"{name} ({addr})"
                        break
        except Exception:  # noqa: BLE001
            pass

        if self._discovered_devices:
            schema = vol.Schema({
                vol.Required(CONF_ADDRESS): vol.In(self._discovered_devices),
            })
        else:
            schema = vol.Schema({
                vol.Required(CONF_ADDRESS): str,
            })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle bluetooth discovery."""
        address = discovery_info.address.upper()
        name = discovery_info.name or ""

        is_melitta = any(name.startswith(prefix) for prefix in BLE_PREFIXES_ALL)
        if not is_melitta:
            return self.async_abort(reason="not_supported")

        await self.async_set_unique_id(address)
        self._abort_if_unique_id_configured()

        self._address = address
        self._name = f"{name} ({address})"
        self.context["title_placeholders"] = {"name": self._name}

        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm bluetooth discovery."""
        if user_input is not None:
            return self.async_create_entry(
                title=self._name or self._address or "Melitta Barista",
                data={
                    CONF_ADDRESS: self._address,
                    CONF_NAME: self._name,
                },
            )

        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={"name": self._name or self._address or "Melitta Barista"},
        )
