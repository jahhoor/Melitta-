import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.const import CONF_ADDRESS, CONF_NAME
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_MAC_ADDRESS, CONF_DEVICE_NAME, CONF_MODEL, SUPPORTED_MODELS

_LOGGER = logging.getLogger(__name__)


class MelittaCoffeeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    VERSION = 1

    def __init__(self) -> None:
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovery_info = discovery_info
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        assert self._discovery_info is not None

        if user_input is not None:
            return self.async_create_entry(
                title=user_input.get(CONF_NAME, self._discovery_info.name),
                data={
                    CONF_MAC_ADDRESS: self._discovery_info.address,
                    CONF_DEVICE_NAME: user_input.get(CONF_NAME, self._discovery_info.name),
                    CONF_MODEL: user_input.get(CONF_MODEL, "Barista Smart"),
                },
            )

        self._set_confirm_only()
        placeholders = {
            "name": self._discovery_info.name,
            "address": self._discovery_info.address,
        }
        self.context["title_placeholders"] = placeholders

        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_NAME,
                        default=self._discovery_info.name or "Melitta Koffiezetapparaat",
                    ): str,
                    vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                        SUPPORTED_MODELS
                    ),
                }
            ),
            description_placeholders=placeholders,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input[CONF_MAC_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=user_input.get(CONF_DEVICE_NAME, "Melitta Koffiezetapparaat"),
                data={
                    CONF_MAC_ADDRESS: address,
                    CONF_DEVICE_NAME: user_input.get(
                        CONF_DEVICE_NAME, "Melitta Koffiezetapparaat"
                    ),
                    CONF_MODEL: user_input.get(CONF_MODEL, "Barista Smart"),
                },
            )

        current_addresses = self._async_current_ids()
        discovered_devices = {}

        for discovery_info in async_discovered_service_info(self.hass, connectable=True):
            name = discovery_info.name or ""
            if any(
                keyword in name.lower()
                for keyword in ["melitta", "caffeo", "barista"]
            ):
                if discovery_info.address not in current_addresses:
                    discovered_devices[discovery_info.address] = discovery_info

        if discovered_devices:
            device_options = {
                address: f"{info.name} ({address})"
                for address, info in discovered_devices.items()
            }

            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_MAC_ADDRESS): vol.In(device_options),
                        vol.Optional(
                            CONF_DEVICE_NAME, default="Melitta Koffiezetapparaat"
                        ): str,
                        vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                            SUPPORTED_MODELS
                        ),
                    }
                ),
                errors=errors,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC_ADDRESS): str,
                    vol.Optional(
                        CONF_DEVICE_NAME, default="Melitta Koffiezetapparaat"
                    ): str,
                    vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                        SUPPORTED_MODELS
                    ),
                }
            ),
            errors=errors,
            description_placeholders={
                "no_devices": "Geen Melitta apparaten gevonden. Voer het MAC-adres handmatig in."
            },
        )
